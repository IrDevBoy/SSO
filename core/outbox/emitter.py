"""Generic transactional-outbox emitter (P0.6.2-B; §29.4/§29.5, §34.4).

Cross-cutting infrastructure (§7.1/§55.7): the outbox is written by the
owning aggregate's transaction and read by the future relay.  Dependency
direction is strictly **context → core**: this module MUST NOT import any
``contexts.*`` package — the caller (identity services) supplies every value
explicitly, including the RFC 9562 UUIDv7 ``event_id`` (generated with the
caller's own id mechanism; the reverse import is forbidden, ADR-0004).

Contract (nothing invented — every value is a column of
``core.outbox.models.OutboxEvent`` / §29.5):

* the caller owns the transaction: this helper performs **no**
  ``transaction.atomic()`` of its own, no publishing, no Redis/Valkey, no
  Celery — a crash or rollback discards the row with the domain write
  (atomic publish-intent, §29.4);
* ``seq`` = ``MAX(seq) + 1`` for the subject, allocated under the caller's
  already-held aggregate row lock (BD-1).  Rows inserted earlier in the same
  transaction are visible to the ``MAX`` aggregate, so multi-event
  transactions produce strictly increasing, contiguous sequences; a rolled
  back transaction leaves no material gap (ADR-0004);
* ``event_type`` must be in the caller-provided allowed set (BD-7 "names are
  contracts" — no invention);
* ``payload_hash`` = SHA-256 hex over canonical JSON of the payload, per
  BD-4: ``json.dumps(payload, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False).encode("utf-8")`` — payload only, never the envelope;
  exactly 64 lowercase hex chars;
* trace/request/correlation coordinates are explicit optional arguments,
  stored NULL when unavailable (BD-6 — no middleware, no thread-locals);
* rows are always ``PENDING`` (§34.4) — the relay phase owns every other
  state, plus ``source``/``time``/``schemaurl`` envelope construction (BD-9;
  OQ-01 unresolved).
"""

from __future__ import annotations

import hashlib
import json
import uuid

from django.db import models

from core.outbox.models import OutboxEvent

__all__ = ["emit_outbox_event"]


def canonical_payload_bytes(payload: dict) -> bytes:
    """BD-4 canonical JSON encoding (the exact bytes that are hashed)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def payload_hash(payload: dict) -> str:
    """BD-4: SHA-256 hex digest over the canonical payload JSON — 64 chars."""
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()


def emit_outbox_event(
    *,
    event_type: str,
    allowed_event_types: frozenset[str] | set[str],
    subject: str,
    payload: dict,
    event_id: uuid.UUID,
    partition_key: str | None = None,
    traceparent: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    metadata: dict | None = None,
) -> OutboxEvent:
    """Create one PENDING outbox row inside the caller's transaction.

    Arguments:
        event_type: the §29.3 catalog name; must be in
            ``allowed_event_types`` (the caller's context-owned catalog) —
            anything else raises :class:`ValueError` (no invented types).
        allowed_event_types: the caller's catalog constants (BD-7).
        subject: aggregate coordinate, ``identity:<uuid>`` (BD-2).
        payload: nudge payload (§29.7) — hashed per BD-4.
        event_id: caller-generated UUIDv7 (CloudEvents ``id``; §29.5).
        partition_key: stream key; §29.4 pins it to the identity-id hash —
            the caller passes ``identity:<uuid>`` (BD-2 namespace).
        traceparent / request_id / correlation_id: explicit optional
            observability coordinates (BD-6); NULL when unavailable.
        metadata: explicit optional dict (BD-6) — stored as-is.

    Returns the persisted :class:`OutboxEvent` (still uncommitted; the
    caller's transaction commits or rolls it back atomically with the
    domain mutation).
    """
    if event_type not in allowed_event_types:
        raise ValueError(
            f"event type {event_type!r} is not in the approved catalog "
            "(§29.3: names are contracts — no invention)"
        )
    seq = (
        OutboxEvent.objects.filter(subject=subject)
        .aggregate(max_seq=models.Max("seq"))["max_seq"]
        or 0
    ) + 1
    return OutboxEvent.objects.create(
        subject=subject,
        seq=seq,
        event_id=event_id,
        event_type=event_type,
        dataversion=1,
        payload=payload,
        payload_hash=payload_hash(payload),
        partition_key=partition_key,
        publish_state="PENDING",
        trace_id=traceparent,
        request_id=request_id,
        correlation_id=correlation_id,
        metadata=metadata,
    )
