"""§28.2 audit_event model — schema per the architecture, nothing invented.

Schema-qualified ``db_table`` follows the ADR-0001 A-3 pattern; the natural
home for audit rows is the audit context's own schema ``uiap_audit`` (§34.2
nine-schema list — the audit schema exists since P0.4).

Column provenance (all §28.2, no invention):

* ``audit_id`` — per-partition sequence (BigAutoField; "internal only, never
  exposed; external ref = ``audit_uuid``");
* ``audit_uuid`` — the public handle (P-08 opaque ids);
* ``at_ts`` — timestamptz, DB-authoritative (``db_default=Now()``);
* ``actor_kind`` — IDENTITY | SERVICE | SYSTEM_JOB | ANONYMOUS (§28.2);
  ``actor_id`` — identity/service id, **never a name** (§28.2 redaction);
* ``action`` — §28.3 closed taxonomy verb (validated by the service);
* ``subject_kind``/``subject_id`` — what was acted on;
* ``outcome`` — SUCCESS | DENIED (§28.2: "denied admin attempts are audited
  too");
* ``before_digest``/``after_digest`` — SHA-256 over canonical JSON of the
  *redacted* before/after states (§28.2 — digests stored, not values);
* ``payload_ref`` — object-storage ref (P0 has no object storage; nullable
  and unused in P0.7.2 — ADR-0006 §5);
* ``ip`` — network coordinate, nullable (truncated per retention);
* ``application_id``, ``device_id``, ``session_sid`` — §28.2 "nullable
  (system jobs)"; P0 has no session/producer → NULL (ADR-0006 §5);
* ``request_id``/``correlation_id``/``trace_id`` — §45.2 propagation,
  explicit optional arguments (BD-6 pattern, ADR-0004);
* ``reason_text`` — required for admin actions only (none in P0.7.2);
* ``context`` — action-specific structured JSONB;
* ``stream`` — §28.5 SEC|IDN|APP|ADM|POL;
* ``seq_in_stream``, ``prev_hash``, ``row_hash`` — the §28.4 tamper
  structure (per ``(stream, month-partition)`` chain).

Hash-chain fields (§28.4 V1 structure): rows form a chain within each
``(stream, month-partition)`` subpartition: ``row_hash =
H(row_hash_input || prev_hash)`` (§28.4 formula verbatim) — SHA-256,
canonical-JSON input, maintained under **partition-local advisory locks**
(§28.4 structure bullet: "maintained with partition-local advisory locks").
``H`` is SHA-256 — the repository's established hash convention
(ADR-0004 BD-4 payload_hash).

Immutability: append-only by application discipline + tests (the ADR-0002
D-6 pattern); §28.4 PG-level immutability (UPDATE/DELETE revoked via role
grants) is enforced by the privilege layer — the application roles receive
only INSERT/SELECT (ADR-0006 §12).
"""

from __future__ import annotations

import hashlib
import json

from django.db import models
from django.db.models import Q
from django.db.models.functions import Now

from contexts.audit.taxonomy import AUDIT_ACTIONS, AuditStream


class AuditImmutable(Exception):
    """§28.4 append-only: existing audit rows are never updated or deleted."""


class AuditQuerySet(models.QuerySet):
    """The only write the platform permits is INSERT (§28.4 layer 3)."""

    def update(self, **kwargs):  # type: ignore[override]
        raise AuditImmutable("audit rows are never updated (§28.4 append-only)")

    def delete(self):  # type: ignore[override]
        raise AuditImmutable("audit rows are never deleted (§28.4 append-only)")


class AuditEvent(models.Model):
    """§28.2 ``uiap_audit.audit_events`` — one tamper-evident audit row."""

    class ActorKind(models.TextChoices):
        IDENTITY = "IDENTITY"
        SERVICE = "SERVICE"
        SYSTEM_JOB = "SYSTEM_JOB"
        ANONYMOUS = "ANONYMOUS"

    class Outcome(models.TextChoices):
        SUCCESS = "SUCCESS"
        DENIED = "DENIED"

    audit_id = models.BigAutoField(primary_key=True)
    audit_uuid = models.UUIDField(unique=True, editable=False)
    at_ts = models.DateTimeField(db_default=Now())
    actor_kind = models.CharField(max_length=10, choices=ActorKind.choices)
    # §28.2: actor_id is an id, never a name. Nullable for SYSTEM_JOB /
    # ANONYMOUS actors that have no identity row (§28.2 actor_kind list).
    actor_id = models.UUIDField(null=True, blank=True)
    action = models.CharField(max_length=64)
    subject_kind = models.CharField(max_length=32)
    subject_id = models.CharField(max_length=64)
    outcome = models.CharField(max_length=7, choices=Outcome.choices)
    before_digest = models.CharField(max_length=64, null=True, blank=True)
    after_digest = models.CharField(max_length=64, null=True, blank=True)
    payload_ref = models.TextField(null=True, blank=True)  # §28.2; unused in P0.7.2
    ip = models.CharField(max_length=64, null=True, blank=True)
    application_id = models.CharField(max_length=64, null=True, blank=True)
    device_id = models.CharField(max_length=64, null=True, blank=True)
    session_sid = models.CharField(max_length=64, null=True, blank=True)
    request_id = models.CharField(max_length=64, null=True, blank=True)
    correlation_id = models.CharField(max_length=64, null=True, blank=True)
    trace_id = models.CharField(max_length=64, null=True, blank=True)
    reason_text = models.TextField(null=True, blank=True)
    context = models.JSONField(null=True, blank=True)
    stream = models.CharField(max_length=3)
    seq_in_stream = models.BigIntegerField()
    prev_hash = models.CharField(max_length=64)
    row_hash = models.CharField(max_length=64)

    objects = AuditQuerySet.as_manager()

    class Meta:
        db_table = 'uiap_audit"."audit_events'
        constraints = [
            # §28.4 threat table: "gaps impossible" — the seq is unique per
            # (stream, logical partition); DB-enforced backstop behind the
            # advisory lock (ADR-0006 §7).
            models.UniqueConstraint(
                fields=["stream", "seq_in_stream"],
                name="audit_events_stream_seq_uc",
            ),
            models.CheckConstraint(
                condition=Q(action__in=sorted(AUDIT_ACTIONS)),
                name="audit_events_action_taxonomy_check",
            ),
            models.CheckConstraint(
                condition=Q(stream__in=[AuditStream.SEC, AuditStream.IDN, AuditStream.APP,
                                         AuditStream.ADM, AuditStream.POL]),
                name="audit_events_stream_check",
            ),
            models.CheckConstraint(
                condition=Q(outcome__in=["SUCCESS", "DENIED"]),
                name="audit_events_outcome_check",
            ),
            # §28.6: no digests, no free-text values — digests are the only
            # value-carrier and they are hashes by construction.
            models.CheckConstraint(
                condition=~Q(context__isnull=False) | ~Q(
                    context__has_key="phc"
                ) & ~Q(context__has_key="password"),
                name="audit_events_no_secret_keys_check",
            ),
        ]
        indexes = [
            # §28.2: partition key + chain ordering (verification scans).
            models.Index(
                fields=["stream", "seq_in_stream"], name="audit_stream_seq_idx"
            ),
            # §34.4 pattern: hot lookups by subject.
            models.Index(
                fields=["subject_kind", "subject_id"], name="audit_subject_idx"
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover - repr convenience
        return f"AuditEvent<{self.audit_uuid}:{self.action}:{self.stream}>"

    # -- immutability discipline (§28.4 layer 3 + ADR-0002 D-6 pattern) ------

    def save(self, *args, **kwargs):  # type: ignore[override]
        if self.pk is not None:
            raise AuditImmutable(
                "audit rows are never updated (§28.4 append-only); a state "
                "change appends a new row."
            )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):  # type: ignore[override]
        raise AuditImmutable("audit rows are never deleted (§28.4 append-only)")


class AuditRoot(models.Model):
    """§28.4 layer 2 — ``uiap_audit.audit_roots`` checkpoint commitments.

    Every 5,000 rows or 15 min (whichever first) per (stream, partition):
    ``{root_hash, range (seq_from, seq_to), stream, partition, created_at,
    prev_root_hash}`` (§28.4 verbatim). Root-to-root chain = the "big
    chain"; row-to-row = detail (§28.4).
    """

    root_id = models.BigAutoField(primary_key=True)
    stream = models.CharField(max_length=3)
    partition = models.CharField(max_length=7)  # YYYY-MM
    seq_from = models.BigIntegerField()
    seq_to = models.BigIntegerField()
    root_hash = models.CharField(max_length=64)
    prev_root_hash = models.CharField(max_length=64, null=True, blank=True)
    created_at = models.DateTimeField(db_default=Now())

    class Meta:
        db_table = 'uiap_audit"."audit_roots'
        constraints = [
            models.UniqueConstraint(
                fields=["stream", "partition", "seq_to"],
                name="audit_roots_stream_partition_seq_to_uc",
            ),
        ]
        indexes = [
            models.Index(fields=["stream", "partition"], name="audit_roots_stream_idx"),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"AuditRoot<{self.stream}:{self.partition}:{self.seq_from}-{self.seq_to}>"
