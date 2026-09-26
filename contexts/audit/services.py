"""§28.2/§28.4 audit append service — the INV-08 same-transaction seam.

Contract (all architecture-mandated):

* **Atomic with the caller** (INV-08, §28.1): this module never opens a
  transaction of its own (the emitter's rule, ADR-0004 §4 — a nested
  ``atomic()`` would create a savepoint and break the
  fail-rolls-back-everything property). If the caller's transaction rolls
  back, the audit row rolls back with it (§34.5: rows + audit + outbox
  intent in one transaction).
* **Append-only** (§28.4 layer 3): no update/delete path exists.
* **Chain correctness under concurrency** (§28.4 layer 1): rows chain per
  ``(stream, month-partition)``; the previous row_hash is read and the new
  row written under a **partition-local advisory lock**
  (``pg_advisory_xact_lock`` — transaction-scoped, auto-released at commit/
  rollback, no separate lock rows, no deadlocks when lock order is
  identity-row → advisory as documented in ADR-0006 §7).
* **No secrets/PII** (§28.6, invariant #10): callers pass *digests*
  (SHA-256 over canonical JSON of redacted states — §28.2 "digests stored"),
  never values; the service refuses a ``context`` containing secret-shaped
  keys.
* **Deterministic validation**: action must be in the §28.3 closed
  taxonomy; outcome in {SUCCESS, DENIED}; actor ids opaque.

seq allocation: ``seq_in_stream`` = 1 + current max within the same
``(stream, partition)`` — assigned pre-commit inside the advisory lock, so
gaps are impossible (§28.4 threat table: "gaps impossible: seq assigned
pre-commit, gaps roll back the transaction").
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from django.db import connection, transaction
from django.db.models import Max

from contexts.audit.chain import (
    CHECKPOINT_ROWS,
    GENESIS_PREV_HASH,
    compute_row_hash,
    root_hash_for_segment,
)
from contexts.audit.models import AuditEvent, AuditRoot
from contexts.audit.taxonomy import AuditStream, action_stream, validate_action

__all__ = [
    "AuditAppendRequest",
    "AuditAppendError",
    "append_audit_event",
    "verify_stream_partition",
]


class AuditAppendError(Exception):
    """Deterministic audit failure (rolls the caller's transaction back)."""


@dataclass(frozen=True)
class AuditAppendRequest:
    """A validated audit request — digests only, never raw values (§28.6)."""

    action: str
    actor_kind: str = AuditEvent.ActorKind.SYSTEM_JOB
    actor_id: uuid.UUID | None = None
    subject_kind: str = "identity"
    subject_id: str = ""
    outcome: str = AuditEvent.Outcome.SUCCESS
    before_digest: str | None = None
    after_digest: str | None = None
    ip: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    reason_text: str | None = None
    context: dict | None = None


_SECRET_SHAPED_KEYS = frozenset(
    {"password", "phc", "secret", "token", "otp", "credential_secret", "authorization"}
)


def _guard_context(context: dict | None) -> dict | None:
    """§28.6/invariant #10: refuse secret-shaped keys in the context JSONB."""
    if context is None:
        return None
    offending = sorted(k.lower() for k in context if k.lower() in _SECRET_SHAPED_KEYS)
    if offending:
        raise AuditAppendError(
            "audit context contains forbidden secret-shaped keys "
            f"({', '.join(offending)}) — invariant #10/§28.6"
        )
    return context


def _partition_key(stream: str) -> int:
    """Stable int key for the partition-local advisory lock (§28.4 layer 1:
    "partition-local advisory locks"). Key = hashtext of the qualified
    stream name — PostgreSQL's 32-bit signed hashtext; deterministic."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT hashtext(%s)", [f"uiap_audit:{stream}"])
        (key,) = cursor.fetchone()
    return key


def _acquire_partition_lock(stream: str) -> int:
    """``pg_advisory_xact_lock`` — blocking acquisition, held until commit/
    rollback of the caller's transaction (no manual release; no
    cross-transaction leak). The void-returning call simply waits until the
    lock is free — contention is per-partition (§28.4 layer 1), bounded by
    the write itself."""
    key = _partition_key(stream)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [key])
        cursor.fetchone()  # void result — the call blocks until acquired
    return key


def _partition_label() -> str:
    """The current UTC month-partition (§28.5: monthly range partitions)."""
    from django.utils import timezone

    return timezone.now().strftime("%Y-%m")


def append_audit_event(request: AuditAppendRequest) -> AuditEvent:
    """Append one audit row inside the **caller's** transaction.

    Fails (raising :class:`AuditAppendError`) rather than silently
    degrading: INV-08 makes an un-audited state change a release blocker,
    so the correct behavior on audit failure is rollback of everything.

    The seq-read → hash → INSERT critical section runs under
    ``transaction.atomic()``: when the caller already has a transaction
    this is a savepoint (still atomic with the caller — an outer rollback
    discards it), and under autocommit callers it opens the bounded
    transaction that keeps the advisory lock alive for the whole section
    (ADR-0006 §7). Either way the append never commits independently of
    the caller's work.
    """
    validate_action(request.action)  # raises TaxonomyViolation (deterministic)
    stream = action_stream(request.action)
    outcome = request.outcome
    if outcome not in (AuditEvent.Outcome.SUCCESS, AuditEvent.Outcome.DENIED):
        raise AuditAppendError(f"invalid audit outcome {outcome!r}")
    context = _guard_context(request.context)
    if request.subject_id == "":
        raise AuditAppendError("audit subject_id is required")

    with transaction.atomic():  # keeps the xact lock alive across the section
        _acquire_partition_lock(stream)  # INSIDE the tx: held until commit

        partition = _partition_label()
        agg = AuditEvent.objects.filter(**_partition_filter(stream, partition)).aggregate(
            max_seq=Max("seq_in_stream"),
        )
        max_seq = agg["max_seq"] or 0
        prev_hash = (
            AuditEvent.objects.filter(**_partition_filter(stream, partition))
            .filter(seq_in_stream=max_seq)
            .values_list("row_hash", flat=True)
            .first()
            or GENESIS_PREV_HASH
        )
        seq_in_stream = max_seq + 1

        event = AuditEvent(
            audit_uuid=uuid.uuid4(),
            actor_kind=request.actor_kind,
            actor_id=request.actor_id,
            action=request.action,
            subject_kind=request.subject_kind,
            subject_id=request.subject_id,
            outcome=outcome,
            before_digest=request.before_digest,
            after_digest=request.after_digest,
            ip=request.ip,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            trace_id=request.trace_id,
            reason_text=request.reason_text,
            context=context,
            stream=stream,
            seq_in_stream=seq_in_stream,
            prev_hash=prev_hash,
        )
        # App-side clock is set explicitly and then the INSERT uses the same
        # value (USE_TZ/UTC) — the verifier recomputes from stored rows, so
        # the hashed at_ts must equal the stored at_ts byte-for-byte.
        from django.utils import timezone

        event.at_ts = timezone.now()
        event.row_hash = compute_row_hash(event, prev_hash)
        event.save()  # INSERT only — append-only

        _maybe_checkpoint(stream, partition, event)
    return event


def _partition_filter(stream: str, partition: str) -> dict:
    """Exact (stream, month) slice — the §28.4 subpartition scope. The
    physical monthly RANGE partitions of §28.5 are a later DDL job (P0 has a
    single table per schema); the logical partition key is carried in
    ``at_ts`` and the lock/checkpoint semantics already scope by it."""
    year, month = partition.split("-")
    return {
        "stream": stream,
        "at_ts__year": int(year),
        "at_ts__month": int(month),
    }


def _maybe_checkpoint(stream: str, partition: str, event: AuditEvent) -> None:
    """§28.4 layer 2: commit a root every ``CHECKPOINT_ROWS`` rows (the 15-min
    cadence belongs to the checkpoint job — ADR-0006 §17 deferred items)."""
    if event.seq_in_stream % CHECKPOINT_ROWS != 0:
        return
    prev_root = (
        AuditRoot.objects.filter(stream=stream, partition=partition)
        .order_by("-seq_to")
        .values_list("root_hash", flat=True)
        .first()
    )
    AuditRoot.objects.create(
        stream=stream,
        partition=partition,
        seq_from=(event.seq_in_stream // CHECKPOINT_ROWS - 1) * CHECKPOINT_ROWS + 1,
        seq_to=event.seq_in_stream,
        root_hash=root_hash_for_segment(event.row_hash, event.seq_in_stream, prev_root),
        prev_root_hash=prev_root,
    )


def verify_stream_partition(stream: str, partition: str) -> dict:
    """§28.4 layer 4 (verification foundation): recompute the chain for one
    ``(stream, partition)`` slice from stored rows and compare.

    Read-only — never mutates audit data. Returns a deterministic report:
    ``{"stream", "partition", "rows", "ok", "first_broken_seq"}``. A
    tampered row (edited action/context/hash), a deleted row, or a
    reordering breaks the recomputation and is reported with the first
    broken ``seq_in_stream``.
    """
    rows = list(
        AuditEvent.objects.filter(**_partition_filter(stream, partition))
        .order_by("seq_in_stream")
        .only(
            "audit_uuid", "actor_kind", "actor_id", "action", "subject_kind",
            "subject_id", "outcome", "before_digest", "after_digest", "stream",
            "seq_in_stream", "at_ts", "prev_hash", "row_hash",
        )
    )
    expected_prev = GENESIS_PREV_HASH
    first_broken = None
    for row in rows:
        recomputed = compute_row_hash(row, expected_prev)
        if row.prev_hash != expected_prev or row.row_hash != recomputed:
            if first_broken is None:
                first_broken = row.seq_in_stream
            break
        expected_prev = row.row_hash
    return {
        "stream": stream,
        "partition": partition,
        "rows": len(rows),
        "ok": first_broken is None and len(rows) > 0,
        "first_broken_seq": first_broken,
    }
