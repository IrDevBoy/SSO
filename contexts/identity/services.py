"""Identity lifecycle orchestration (P0.6.1 — §11.4, §12.0, §34.5).

Every transition is a single transaction: **lock the row** (``select_for_update``
— the race-safety primitive; the second concurrent transition re-reads the
already-updated status and is refused), **validate** against the §11.4 map,
**bump row_version**, **append history** — commit.  Creation writes the
initial history row in the same transaction.  No silent coercion: forbidden
transitions raise :class:`TransitionForbidden` from the pure lifecycle map.

Outbox emission is deliberately absent (D-8 — P0.6.2); audit tables do not
exist yet (§34.5's full same-tx set completes when the audit foundation lands).
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from contexts.identity.lifecycle import (
    CREDENTIAL_TRANSITIONS,
    IDENTITY_TRANSITIONS,
    validate_transition,
)
from contexts.identity.models import Credential, Identity, IdentityStatusHistory


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
    return credential
