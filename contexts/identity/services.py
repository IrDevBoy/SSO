"""Identity lifecycle orchestration (P0.6.1 §11.4/§12.0/§34.5; P0.6.2-A adds
the §12.2 password contract per ADR-0003).

Every transition is a single transaction: **lock the row** (``select_for_update``
— the race-safety primitive; the second concurrent transition re-reads the
already-updated status and is refused), **validate** against the §11.4 map,
**bump row_version**, **append history** — commit.  Creation writes the
initial history row in the same transaction.  No silent coercion: forbidden
transitions raise :class:`TransitionForbidden` from the pure lifecycle map.

Outbox emission is deliberately absent in P0.6.1/2-A (D-8; P0.6.2-B adds the
emitter inside these same atomic blocks).  Audit tables do not exist yet —
the INV-08 same-tx append joins this exact boundary in P0.7 (OD-1 deferral
recorded in ADR-0003).
"""

from __future__ import annotations

from django.db import models, transaction
from django.utils import timezone

from contexts.identity import passwords
from contexts.identity.lifecycle import (
    CREDENTIAL_TRANSITIONS,
    IDENTITY_TRANSITIONS,
    validate_transition,
)
from contexts.identity.models import (
    Credential,
    Identity,
    IdentityStatusHistory,
    PasswordSecret,
)


class PasswordInvariantError(Exception):
    """OD-5: a second ACTIVE password credential was attempted under lock."""


@transaction.atomic
def create_identity(
    *,
    type: str,
    region_tag: str,
    status: str = Identity.Status.PROVISIONAL,
    verification_level: str = Identity.VerificationLevel.UNVERIFIED,
) -> Identity:
    """Create the root aggregate + its initial history row (same transaction)."""
    identity = Identity.objects.create(
        type=type,
        status=status,
        verification_level=verification_level,
        region_tag=region_tag,
        # "[*] --> ACTIVE: verified at creation" (§11.4) — activation timestamp
        # is set at birth for identities born ACTIVE.
        activated_at=timezone.now() if status == Identity.Status.ACTIVE else None,
    )
    IdentityStatusHistory.objects.create(identity=identity, status=identity.status)
    return identity


@transaction.atomic
def transition_identity(identity_id, *, to_status: str) -> Identity:
    """Validate + apply one lifecycle edge; append history in the same transaction."""
    identity = Identity.objects.select_for_update().get(pk=identity_id)
    validate_transition(IDENTITY_TRANSITIONS, identity.status, to_status, kind="identity")
    identity.status = to_status
    identity.row_version += 1
    if to_status == Identity.Status.ACTIVE and identity.activated_at is None:
        identity.activated_at = timezone.now()  # D-5: set by the owning transition
    if to_status in ("DELETED", "ABANDONED", "MERGED") and identity.closed_at is None:
        identity.closed_at = timezone.now()  # terminal closure (§11.2 closed_at)
    identity.save(update_fields=["status", "row_version", "activated_at", "closed_at"])
    IdentityStatusHistory.objects.create(identity=identity, status=to_status)
    return identity


@transaction.atomic
def transition_credential(credential_id, *, to_status: str) -> Credential:
    """Apply one §12.0 header lifecycle edge (header only — no typed tables)."""
    credential = Credential.objects.select_for_update().get(pk=credential_id)
    validate_transition(CREDENTIAL_TRANSITIONS, credential.status, to_status, kind="credential")
    credential.status = to_status
    credential.row_version += 1
    credential.updated_at = timezone.now()
    if to_status == Credential.Status.REVOKED and credential.revoked_at is None:
        credential.revoked_at = timezone.now()
    credential.save(update_fields=["status", "row_version", "updated_at", "revoked_at"])
    # P0.6.2-A: a terminal credential closes its password secrets too —
    # a DISABLED secret must never authenticate (§10.2 DISABLED state).
    if to_status in ("REVOKED", "EXPIRED"):
        credential.password_secrets.exclude(status="DISABLED").update(
            status="DISABLED", row_version=models.F("row_version") + 1
        )
    return credential


# ---------------------------------------------------------------------------
# P0.6.2-A — password set / verify / rehash (§12.2, §10.2, R-04; ADR-0003).
# Transaction shape (OD-1 deferral noted): identity lock → validate → active-
# password invariant (OD-5, service-enforced under the identity-row lock) →
# header credential → password_secrets append + wipe.  The audit append joins
# this exact boundary in P0.7 (INV-08 deferral recorded in ADR-0003) and the
# outbox emitter joins it in P0.6.2-B — both are single-call inserts inside
# the atomic block, no redesign required.
# ---------------------------------------------------------------------------


def _one_active_password_guard(identity, exclude_credential_pk=None) -> None:
    """OD-5: at most one ACTIVE password credential per identity — enforced
    in the service layer while holding the identity-row lock (the §34.4 spec
    defines no DB partial unique; the P0.6.1 pattern gives us the serializing
    lock).  Raises :class:`PasswordInvariantError` on violation."""
    active = Credential.objects.filter(
        identity=identity, kind="PASSWORD", status="ACTIVE"
    ).exclude(pk=exclude_credential_pk).exists()
    if active:
        raise PasswordInvariantError(
            "identity already has an ACTIVE password credential (OD-5 "
            "service-enforced invariant)"
        )


def set_password(
    identity_id,
    *,
    raw_password: str,
    breach: passwords.BreachDenier | None = None,
    legacy_import: bool = False,
) -> Credential:
    """Set (or rotate) the identity's password atomically.

    One transaction: lock the identity row (§9 race discipline), validate
    the §12.2 policy, enforce the OD-5 active-password invariant, create or
    reuse the PASSWORD credential (PENDING→ACTIVE), append the new secret
    row, then apply R-04: current→SUPERSEDED (keep one prior) and wipe
    anything older (hash destroyed — R-04 "wiped").

    Plaintext never persists: it lives only in this frame as a function
    argument and is hashed via :mod:`contexts.identity.passwords`.
    """
    normalized = passwords.validate(
        raw_password, legacy_import=legacy_import, breach=breach
    )
    with transaction.atomic():
        identity = Identity.objects.select_for_update().get(pk=identity_id)

        # Reuse-or-create is decided FIRST so the OD-5 guard can exclude the
        # credential this call is rotating (rotation is not a second ACTIVE
        # credential — the invariant guards against a *second* live one).
        existing = (
            Credential.objects.select_for_update()
            .filter(identity=identity, kind="PASSWORD")
            .order_by("created_at")
            .last()
        )
        reusable = existing is not None and existing.status in ("PENDING", "ACTIVE")
        _one_active_password_guard(
            identity, exclude_credential_pk=existing.pk if reusable else None
        )

        # R-04 history window = current + 1 prior (R-04 "current + 1 prior";
        # §12.2 "history block = previous 1 ... revoke = re-set same password
        # loops").  Reuse of either the ACTIVE or the kept previous/disabled
        # generation is refused — the kept rows span the identity's PASSWORD
        # credentials so the revoke→re-set loop stays blocked (ADR-0003).
        current_secret = (
            PasswordSecret.objects.filter(credential=existing, status="ACTIVE").first()
            if reusable
            else None
        )
        kept_prior = (
            PasswordSecret.objects.filter(
                credential__identity=identity, credential__kind="PASSWORD"
            )
            .filter(models.Q(status="SUPERSEDED") | models.Q(status="DISABLED"))
            .order_by("-superseded_at", "-created_at")
            .first()
        )
        for blocked in (current_secret, kept_prior):
            if blocked is not None and passwords.verify(blocked.phc, normalized):
                raise passwords.PasswordHistoryConflict(
                    "password matches the blocked history window "
                    "(current + 1 prior; R-04/§12.2)"
                )

        if reusable:
            credential = existing
            credential.status = Credential.Status.ACTIVE  # PENDING→ACTIVE on first set
            credential.row_version += 1
            credential.verified_at = credential.verified_at or timezone.now()
            credential.updated_at = timezone.now()
            credential.save(update_fields=["status", "row_version", "verified_at", "updated_at"])
            transitioned = existing.status == "PENDING"
        else:
            credential = Credential.objects.create(
                identity=identity, kind="PASSWORD", status="PENDING"
            )
            credential = transition_credential(credential.pk, to_status="ACTIVE")
            transitioned = True

        if transitioned:
            IdentityStatusHistory.objects.create(identity=identity, status=identity.status)

        # R-04 bookkeeping: the current ACTIVE secret becomes the single kept
        # "previous" (superseded now); rows superseded earlier than that are
        # wiped (deleted — R-04: "current + 1 prior → wiped"), leaving at most
        # one SUPERSEDED row behind the new ACTIVE one.
        PasswordSecret.objects.select_for_update().filter(
            credential=credential, status="ACTIVE"
        ).update(
            status="SUPERSEDED", superseded_at=timezone.now(),
            row_version=models.F("row_version") + 1,
        )
        keeper = (
            PasswordSecret.objects.filter(
                credential=credential, status="SUPERSEDED"
            )
            .order_by("-superseded_at")
            .values("pk")[:1]
        )
        PasswordSecret.objects.filter(
            credential=credential, status="SUPERSEDED"
        ).exclude(pk=models.Subquery(keeper)).delete()

        PasswordSecret.objects.create(
            credential=credential,
            phc=passwords.hash_password(normalized),
            argon_memory_kib=passwords.INITIAL_MEMORY_KIB,
            argon_time_cost=passwords.INITIAL_TIME_COST,
            argon_parallelism=passwords.INITIAL_PARALLELISM,
            status="ACTIVE",
            breach_checked_at=timezone.now() if breach is not None else None,
        )
        credential.refresh_from_db()
        return credential


def verify_password(identity_id, *, raw_password: str) -> tuple[bool, bool]:
    """Verify a candidate against the ACTIVE secret (login-path contract).

    Returns ``(ok, needs_rehash)`` — ``needs_rehash`` is meaningful only
    when ``ok`` is True (§12.2: rehash transparently **on next successful
    login**; the caller re-hashes in its own transaction after a successful
    verification, via :func:`rehash_password`).

    Enumerability is preserved for the future login flow (§24.7 timing
    equalization) by always running the KDF when a secret exists.
    """
    normalized = passwords.normalize(raw_password)
    secret = (
        PasswordSecret.objects
        .filter(credential__identity_id=identity_id, status="ACTIVE",
                credential__kind="PASSWORD")
        .order_by("-created_at")
        .first()
    )
    if secret is None:
        # No-password account (§10.2 allows zero-password): uniform refusal,
        # no KDF run (nothing to equalize against — no oracle to normalize).
        return False, False
    ok = passwords.verify(secret.phc, normalized)
    return ok, (ok and passwords.check_needs_rehash(secret.phc))


def rehash_password(identity_id, *, raw_password: str) -> bool:
    """§12.2 rehash-on-login: after a *successful* verify, upgrade the stored
    hash to current policy params (new row, previous becomes the kept one).
    Returns True when an upgrade was actually needed and applied."""
    normalized = passwords.normalize(raw_password)
    with transaction.atomic():
        identity = Identity.objects.select_for_update().get(pk=identity_id)
        secret = (
            PasswordSecret.objects.select_for_update()
            .filter(credential__identity=identity, status="ACTIVE",
                    credential__kind="PASSWORD")
            .order_by("-created_at")
            .first()
        )
        if secret is None or not passwords.verify(secret.phc, normalized):
            return False
        if not passwords.check_needs_rehash(secret.phc):
            return False
        # Same R-04 bookkeeping as set_password, scoped to this credential.
        PasswordSecret.objects.filter(
            credential=secret.credential, status="ACTIVE"
        ).exclude(pk=secret.pk).update(
            status="SUPERSEDED", superseded_at=timezone.now(),
            row_version=models.F("row_version") + 1,
        )
        secret.status = "SUPERSEDED"
        secret.superseded_at = timezone.now()
        secret.row_version += 1
        secret.save(update_fields=["status", "superseded_at", "row_version"])
        PasswordSecret.objects.create(
            credential=secret.credential,
            phc=passwords.hash_password(normalized),
            argon_memory_kib=passwords.INITIAL_MEMORY_KIB,
            argon_time_cost=passwords.INITIAL_TIME_COST,
            argon_parallelism=passwords.INITIAL_PARALLELISM,
            status="ACTIVE",
        )
        return True
