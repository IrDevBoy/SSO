"""
Outbox event table contract (P0.4, decisions A-3/A-5; ARCHITECTURE.md §29.4,
§29.5, §34.3, §34.4).

The single P0 table is ``uiap_access.outbox_events`` — a schema-qualified
name reaching across the app's *label* into the access schema. This is the
one approved cross-context exception: the outbox is infrastructure shared by
all contexts (§29), written by the owning aggregate's transaction and read
by the relay (a separate process, later sub-phase). Django cannot map a
model to a different schema than its app otherwise implies, so the
infrastructural ownership is documented here and in ADR 0001.

Storage rules honored (§34.3):
  - timestamptz everywhere (USE_TZ=True; server defaults via now()),
  - JSONB for payload/metadata, hot facts as columns,
  - text + CHECK for enum-like state (publish_state),
  - C collation on id/hash-like textual identity fields,
  - no soft-delete boolean (§34.3: status machines, not is_deleted),
  - NO row_version: outbox rows are append-mostly and state transitions are
    relay-claimed updates guarded by the partial PENDING index + relay-side
    SKIP LOCKED claims (Relay phase); optimistic row_version adds no safety
    the claim pattern does not already provide (rationale recorded in the
    ADR per the P0.4 storage rule).

No FKs: the outbox is deliberately reference-free so retention (R-30) can
purge/move rows without cascades and so the relay never needs joins.
"""

from django.db import models
from django.db.models.functions import Now

# §34.4 lifecycle: PENDING → PUBLISHED → ACKED/FAILED (DLQ handling belongs
# to the relay phase, not this table).
PUBLISH_STATE_CHOICES = (
    ("PENDING", "Pending publish"),
    ("PUBLISHED", "Published to the stream"),
    ("ACKED", "Acknowledged by all consumer groups"),
    ("FAILED", "Parked in DLQ after retry budget"),
)

PUBLISH_STATE_CHECK = "publish_state IN ('PENDING', 'PUBLISHED', 'ACKED', 'FAILED')"


class OutboxEvent(models.Model):
    """One durable publish-intent row (the transactional outbox entry)."""

    # --- identity & ordering (§29.4/§29.5 envelope) -------------------------
    # bigint PK (§34.3: append-only logs use bigint); never reused, monotonic
    # by sequence default set in the migration.
    id = models.BigAutoField(primary_key=True)

    # Subject = aggregate coordinate ("identity:<uuid>" per §29.5); seq is the
    # per-subject monotonic counter consumers use for gap detection.
    subject = models.CharField(max_length=255, db_collation="C")
    seq = models.BigIntegerField()

    event_id = models.UUIDField(editable=False, unique=True)  # CloudEvents id (uuidv7 shape)

    # --- envelope (CloudEvents-compatible subset, §29.5) --------------------
    event_type = models.CharField(max_length=255, db_collation="C")
    dataversion = models.IntegerField(default=1)  # semver-per-type major lane

    # nudge-not-data (§29.7): payload is the invalidation signal; payload_ref
    # may point at a large blob instead of inlining it.
    payload = models.JSONField()
    payload_hash = models.CharField(max_length=64, db_collation="C")
    payload_ref = models.TextField(null=True, blank=True)
    partition_key = models.CharField(max_length=255, null=True, blank=True)

    # --- relay lifecycle (state machine, §34.4) -----------------------------
    publish_state = models.CharField(
        max_length=16,
        choices=PUBLISH_STATE_CHOICES,
        default="PENDING",
    )
    attempts = models.PositiveIntegerField(default=0)
    # DB-level now() defaults (§34.3): the database, not the app clock,
    # timestamps availability and creation.
    available_at = models.DateTimeField(db_default=Now())
    published_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(null=True, blank=True)

    # --- observability coordinates (§29.5 traceparent/request/correlation) --
    trace_id = models.CharField(max_length=64, null=True, blank=True, db_collation="C")
    request_id = models.CharField(max_length=64, null=True, blank=True, db_collation="C")
    correlation_id = models.CharField(max_length=64, null=True, blank=True, db_collation="C")

    metadata = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(db_default=Now())

    class Meta:
        # A-3: exact schema-qualified table. Django renders the escaped name
        # so the table can only ever be created inside uiap_access.
        db_table = 'uiap_access"."outbox_events'
        constraints = [
            models.UniqueConstraint(
                fields=("subject", "seq"),
                name="outbox_subject_seq_key",
            ),
            models.CheckConstraint(
                condition=models.Q(publish_state__in=[s for s, _ in PUBLISH_STATE_CHOICES]),
                name="outbox_publish_state_check",
            ),
            models.CheckConstraint(
                condition=models.Q(attempts__gte=0),
                name="outbox_attempts_nonnegative_check",
            ),
        ]
        indexes = [
            # §34.4: state PENDING partial — the relay claim index (SKIP LOCKED
            # scan target in the Relay phase). Deliberately the only
            # non-unique index (minimal by contract; rationale in ADR 0001).
            models.Index(
                fields=("available_at",),
                condition=models.Q(publish_state="PENDING"),
                name="outbox_pending_claim_idx",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.event_type}#{self.seq} → {self.subject} [{self.publish_state}]"
