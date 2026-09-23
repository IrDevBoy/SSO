"""UIAP Identity storage foundation (P0.6.1 — §11.2, §12.0, §34.4).

Three tables, exactly the architecture's fields — nothing invented:

* ``uiap_identity.identities`` — the root aggregate (ADR-0001 / §11.2);
  PK is an application-side RFC 9562 UUIDv7 (D-2), immutable, no DB default.
* ``uiap_identity.identity_status_history`` — point-in-time status answers
  (§34.4); append-only by service discipline + tests (D-6).
* ``uiap_identity.credentials`` — the §12.0 lifecycle hub header; NO typed
  secret tables in this phase.

Schema-qualified ``db_table`` follows the P0.4 pattern (ADR 0001 A-3);
``db_default=Now()`` keeps timestamps DB-authoritative (UTC semantics);
``row_version`` is bumped in the service layer — no triggers (§34.2 rule
for mutable rows; ADR 0002 D-6/D-7 constraints recorded).
"""

from __future__ import annotations

from django.contrib.postgres.indexes import BrinIndex
from django.db import models
from django.db.models import Q
from django.db.models.functions import Now

from contexts.identity.ids import uuid7
from contexts.identity.lifecycle import (
    CREDENTIAL_KINDS,
    CREDENTIAL_STATUSES,
    IDENTITY_LIVE_STATUSES,
    IDENTITY_STATUSES,
    IDENTITY_TYPES,
    VERIFICATION_LEVELS,
)


class IdentityHardDeleteForbidden(Exception):
    """INV-01 (§11.4): a tombstone is never hard-deleted."""


class IdentityQuerySet(models.QuerySet):
    """Bulk-delete path is sealed exactly like the instance path (INV-01)."""

    def delete(self):  # type: ignore[override]
        raise IdentityHardDeleteForbidden(
            "INV-01: identity tombstones are never hard-deleted (§11.4); "
            "lifecycle deletion is a status transition, not a DELETE."
        )


class Identity(models.Model):
    class Type(models.TextChoices):
        HUMAN = "HUMAN"
        ORGANIZATION = "ORGANIZATION"
        SERVICE = "SERVICE"

    class Status(models.TextChoices):
        PROVISIONAL = "PROVISIONAL"
        ACTIVE = "ACTIVE"
        SUSPENDED = "SUSPENDED"
        LOCKED = "LOCKED"
        PENDING_DELETION = "PENDING_DELETION"
        DELETED = "DELETED"
        # D-1 (ADR 0002): §11.4's state machine defines ABANDONED even though
        # the §11.2 enumeration omits it — the machine is authoritative and
        # the discrepancy is documented.
        ABANDONED = "ABANDONED"
        MERGED = "MERGED"

    class VerificationLevel(models.TextChoices):
        UNVERIFIED = "UNVERIFIED"
        IAL1 = "IAL1"
        IAL2 = "IAL2"

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    type = models.CharField(max_length=12, choices=Type.choices)
    status = models.CharField(max_length=16, choices=Status.choices)
    verification_level = models.CharField(max_length=10, choices=VerificationLevel.choices)
    created_at = models.DateTimeField(db_default=Now())
    # D-5: nullable until the lifecycle transition that owns them sets them
    # (ACTIVE entry / terminal closure).
    activated_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    region_tag = models.CharField(max_length=64)  # residency partition key (§11.2, C-05)
    row_version = models.BigIntegerField(default=1)  # bumped per MUT in the service layer

    objects = IdentityQuerySet.as_manager()

    class Meta:
        db_table = 'uiap_identity"."identities'
        constraints = [
            models.CheckConstraint(
                condition=Q(type__in=sorted(IDENTITY_TYPES)), name="identities_type_check"
            ),
            models.CheckConstraint(
                condition=Q(status__in=sorted(IDENTITY_STATUSES)), name="identities_status_check"
            ),
            models.CheckConstraint(
                condition=Q(verification_level__in=sorted(VERIFICATION_LEVELS)),
                name="identities_verification_level_check",
            ),
        ]
        indexes = [
            BrinIndex(fields=["created_at"], name="identities_created_at_brin"),
            # §34.4 "status partial (ops scans)": live (non-terminal) rows only.
            models.Index(
                fields=["status"],
                condition=~Q(status__in=sorted(IDENTITY_LIVE_STATUSES)),
                name="identities_status_live_idx",
            ),
        ]

    def delete(self, *args, **kwargs):  # type: ignore[override]
        raise IdentityHardDeleteForbidden(
            "INV-01: identity tombstones are never hard-deleted (§11.4); "
            "lifecycle deletion is a status transition, not a DELETE."
        )

    def __str__(self) -> str:  # pragma: no cover - repr convenience
        return f"Identity<{self.pk}:{self.type}:{self.status}>"


class IdentityHistoryImmutable(Exception):
    """§5.B / D-6: identity_status_history is append-only in the application
    layer — UPDATE and DELETE of history rows are refused by the model."""


class IdentityHistoryQuerySet(models.QuerySet):
    """Bulk-delete path is sealed exactly like the instance path (append-only)."""

    def delete(self):  # type: ignore[override]
        raise IdentityHistoryImmutable(
            "identity_status_history is append-only (D-6): history rows are "
            "never deleted; a status change appends a new row instead."
        )


class IdentityStatusHistory(models.Model):
    """Point-in-time status answers (§34.4). Append-only by discipline (D-6/D-7)."""

    id = models.BigAutoField(primary_key=True)
    identity = models.ForeignKey(
        Identity, on_delete=models.PROTECT, related_name="status_history"
    )
    status = models.CharField(max_length=16, choices=Identity.Status.choices)
    valid_from = models.DateTimeField(db_default=Now())

    objects = IdentityHistoryQuerySet.as_manager()

    class Meta:
        db_table = 'uiap_identity"."identity_status_history'
        constraints = [
            # §34.4: unique (id, valid_from) — the documented contract, kept
            # as a named constraint even though id alone is already unique.
            models.UniqueConstraint(
                fields=["id", "valid_from"], name="identity_status_history_id_valid_from_uc"
            ),
        ]

    def save(self, *args, **kwargs):  # type: ignore[override]
        if self.pk is not None:
            raise IdentityHistoryImmutable(
                "identity_status_history is append-only (D-6): existing "
                "history rows are never updated."
            )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):  # type: ignore[override]
        raise IdentityHistoryImmutable(
            "identity_status_history is append-only (D-6): history rows are "
            "never deleted; a status change appends a new row instead."
        )

    def __str__(self) -> str:  # pragma: no cover - repr convenience
        return f"IdentityStatusHistory<{self.identity_id}:{self.status}>"


class Credential(models.Model):
    """§12.0 lifecycle hub header — typed secret tables are NOT part of P0.6.1."""

    class Status(models.TextChoices):
        PENDING = "PENDING"
        ACTIVE = "ACTIVE"
        STALE = "STALE"
        REVOKED = "REVOKED"
        EXPIRED = "EXPIRED"

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    identity = models.ForeignKey(
        Identity, on_delete=models.PROTECT, related_name="credentials"
    )
    kind = models.CharField(max_length=14)  # longest §12.1 kind: RECOVERY_CODES
    label = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=7, choices=Status.choices)
    created_at = models.DateTimeField(db_default=Now())
    updated_at = models.DateTimeField(db_default=Now())
    last_used_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    risk_flags = models.JSONField(null=True, blank=True)
    # §12.0 lists created_by without a type; an opaque principal reference is
    # the minimal non-inventive storage (ADR 0002, recorded inference).
    created_by = models.CharField(max_length=128, null=True, blank=True)
    # §12.0 defines the *order* (passkey > security-key > TOTP > email ≈ SMS);
    # the numeric ranking is policy-owned, the column only stores it.
    mfa_strength_rank = models.IntegerField(null=True, blank=True)
    row_version = models.BigIntegerField(default=1)

    class Meta:
        db_table = 'uiap_identity"."credentials'
        constraints = [
            models.CheckConstraint(
                condition=Q(kind__in=sorted(CREDENTIAL_KINDS)), name="credentials_kind_check"
            ),
            models.CheckConstraint(
                condition=Q(status__in=sorted(CREDENTIAL_STATUSES)),
                name="credentials_status_check",
            ),
        ]
        indexes = [
            models.Index(fields=["identity", "status"], name="cred_identity_status_idx"),
            # §34.4 "kind partial": live credentials per kind are the hot slice.
            models.Index(
                fields=["kind"],
                condition=Q(status__in=["PENDING", "ACTIVE"]),
                name="credentials_kind_live_idx",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover - repr convenience
        return f"Credential<{self.pk}:{self.kind}:{self.status}>"
