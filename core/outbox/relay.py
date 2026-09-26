"""Transactional-outbox relay loop (P0.7; §29.4, §34.4, ADR-0005).

Owner-approved decisions implemented here (ADR-0005 records them):

- **PD-2 (A):** claim = ``SELECT … FOR UPDATE SKIP LOCKED`` with predicate
  ``publish_state='PENDING' AND available_at <= now()`` → XADD →
  ``PUBLISHED``. No intermediate CLAIMED/IN_FLIGHT state, no migration.

- **PD-3 (B):** free publication — no per-subject FIFO blocking. Ordering
  guarantees live in the consumer contract (gap detection on ``seq`` +
  refetch, §29.4/§29.6).

- **PD-4 (A):** failure → ``attempts += 1`` and
  ``available_at = now() + backoff`` (1 s→15 m exponential + jitter);
  claim predicate includes ``available_at <= now()``. The §29.4
  per-consumer-group vs single-``available_at`` tension is preserved
  verbatim — no new state, table, or column.

- **PD-5 (A):** at ``attempts >= 5`` (N=5, §29.4) the event is parked:
  XADD to ``dlq.<group>`` + ``publish_state=FAILED``. No auto-purge of
  FAILED (retention is OPEN). ``last_error`` holds a **safe error
  category** only — never payload/PII/secret (invariant #10).

- **PD-6 (V1):** ``PUBLISHED`` is the terminal relay state; ``ACKED`` is
  reserved/deferred — no transition to it exists in this codebase.

- **PD-7 (A):** PEL reclaim via ``XAUTOCLAIM`` with a config-backed
  min-idle-time (:mod:`core.outbox.conf`); the outbox (PG) remains the
  source of truth regardless of transport state.

Transaction boundary (PD-2, at-least-once): each batch is claimed under a
short transaction (``FOR UPDATE SKIP LOCKED``), the rows are materialized,
and the transaction commits immediately — the row lock is NOT held across
the network round-trip to Valkey. Publish success then flips
``PENDING → PUBLISHED`` in a separate short transaction. Consequences
(deliberate, at-least-once):

- crash after commit, before XADD        → row still PENDING → republished (at-least-once)
- crash after XADD, before PUBLISHED     → duplicate delivery possible (expected; consumers dedupe on ``event.id``, §29.6)
- crash after PUBLISHED                  → done
- Valkey unavailable                     → rows stay PENDING with backoff (PD-4)

Because claim and publish are separate short transactions, the ``FOR
UPDATE SKIP LOCKED`` mutual exclusion holds only for the claim itself; two
relays could in principle both XADD the same row if a claim crashed between
commit and publish and another relay picked it up. This is the approved
PD-2 shape: at-least-once + consumer dedupe is the correctness contract,
not exactly-once.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from core.outbox import backoff as backoff_mod
from core.outbox.conf import RelaySettings
from core.outbox.models import OutboxEvent
from core.outbox.envelope import EnvelopeError, build_envelope, envelope_json
from core.outbox.transport import StreamsTransport, TransportError

logger = logging.getLogger("uiap.relay")

__all__ = [
    "ClaimedRow",
    "RelayCounters",
    "Relay",
    "claim_batch",
]


@dataclass(frozen=True)
class ClaimedRow:
    """A PENDING row materialized from a SKIP LOCKED claim transaction."""

    id: int
    subject: str
    seq: int
    event_id: str
    event_type: str
    dataversion: int
    payload: dict
    partition_key: str | None
    trace_id: str | None
    request_id: str | None
    correlation_id: str | None
    metadata: dict | None
    attempts: int
    # envelope construction happens after the claim tx commits; the row is
    # stored pre-built so the publish path never re-queries.
    envelope: dict | None = None
    envelope_bytes: bytes | None = None


@dataclass
class RelayCounters:
    """Safe telemetry (invariant #10: no payload/PII in any field)."""

    claimed: int = 0
    published: int = 0
    retried: int = 0
    failed: int = 0
    reclaimed: int = 0
    transport_unavailable: int = 0
    publish_latency_ms_total: float = 0.0
    categories: dict = field(default_factory=dict)

    def note_error(self, category: str) -> None:
        self.categories[category] = self.categories.get(category, 0) + 1

    @property
    def publish_latency_ms_avg(self) -> float:
        return (
            self.publish_latency_ms_total / self.published if self.published else 0.0
        )


def claim_batch(*, batch_size: int, source: str | None) -> list[ClaimedRow]:
    """Claim up to ``batch_size`` PENDING rows (PD-2) and build envelopes.

    One short transaction: ``SELECT … FOR UPDATE SKIP LOCKED`` with the
    PD-4 predicate (``PENDING AND available_at <= now()``), ordered by the
    claim index (``available_at``). Envelopes are built inside the claim so
    a missing ``source`` fails fast *before* any publish attempt — the
    refusing behavior is the OQ-01 policy (no invented issuer, no publish).

    The transaction commits on return; locks are never held across the
    transport round-trip (PD-2 boundary, documented in the module docstring).
    """
    with transaction.atomic():
        rows = (
            OutboxEvent.objects.select_for_update(skip_locked=True)
            .filter(publish_state="PENDING", available_at__lte=timezone.now())
            .order_by("available_at", "id")[:batch_size]
        )
        claimed: list[ClaimedRow] = []
        for row in rows:
            try:
                env = build_envelope(source=source, row=row)
            except EnvelopeError:
                # OQ-01 policy: refuse to publish rather than invent source.
                # The row stays PENDING (untouched) — surfaced via counters.
                logger.error(
                    "relay claim: refusing to publish event_id=%s subject=%s "
                    "seq=%s attempts=%s: missing verified source (OQ-01 OPEN)",
                    row.event_id, row.subject, row.seq, row.attempts,
                )
                continue
            claimed.append(
                ClaimedRow(
                    id=row.id,
                    subject=row.subject,
                    seq=row.seq,
                    event_id=str(row.event_id),
                    event_type=row.event_type,
                    dataversion=row.dataversion,
                    payload=row.payload,
                    partition_key=row.partition_key,
                    trace_id=row.trace_id,
                    request_id=row.request_id,
                    correlation_id=row.correlation_id,
                    metadata=row.metadata,
                    attempts=row.attempts,
                    envelope=env,
                    envelope_bytes=envelope_json(env),
                )
            )
        return claimed


class Relay:
    """The P0.7 relay: claim → XADD → PUBLISHED (PD-2), retry/DLQ (PD-4/5)."""

    def __init__(
        self,
        transport: StreamsTransport,
        *,
        settings: RelaySettings,
        source: str | None,
        rng: random.Random | None = None,
    ):
        self.transport = transport
        self.settings = settings
        # OQ-01: source must come from verified deployment config. The Relay
        # does not read it itself — the caller passes it; ``build_envelope``
        # hard-fails on missing/empty (refuse-to-publish policy).
        self.source = source.strip() if source and source.strip() else None
        self.rng = rng or random.Random()
        self.counters = RelayCounters()

    # -- core loop -----------------------------------------------------------

    def process_batch(self) -> int:
        """One claim→publish cycle. Returns number of rows published."""
        claimed = claim_batch(
            batch_size=self.settings.claim_batch, source=self.source
        )
        self.counters.claimed += len(claimed)
        published = 0
        for row in claimed:
            if self._publish(row):
                published += 1
        return published

    def run_forever(self, *, poll_interval_seconds: float = 1.0) -> None:
        """Long-running loop with heartbeat logging (§45.4 relay heartbeat)."""
        self.transport.ensure_group()
        logger.info(
            "relay start: stream=%s group=%s consumer=%s claim_batch=%s idle_ms=%s",
            self.settings.stream, self.settings.group, self.settings.consumer,
            self.settings.claim_batch, self.settings.idle_ms,
        )
        while True:
            started = time.monotonic()
            try:
                self.process_batch()
            except TransportError as exc:
                self.counters.transport_unavailable += 1
                self.counters.note_error(backoff_mod.categorize_error(exc))
                logger.warning("relay cycle transport error (category-safe): %s", exc)
            self.reclaim_idle()
            elapsed = time.monotonic() - started
            logger.debug("relay cycle done in %.3fs", elapsed)
            time.sleep(max(0.0, poll_interval_seconds - elapsed))

    # -- publish / retry / park ----------------------------------------------

    def _publish(self, row: ClaimedRow) -> bool:
        """XADD then flip to PUBLISHED; on transport failure schedule retry.

        Crash windows (tested, at-least-once):
          - dies here before XADD        → row stays PENDING → republished later
          - XADD succeeds, dies before the UPDATE → duplicate delivery
            (expected; consumers dedupe on ``event.id``, §29.6)
        """
        started = time.monotonic()
        try:
            self.transport.publish(row.envelope_bytes)
        except TransportError as exc:
            category = backoff_mod.categorize_error(exc)
            self.counters.note_error(category)
            self._schedule_retry(row, category)
            return False
        # XADD succeeded — separate short transaction for the state flip
        # (PD-2 boundary: never hold locks across network round-trips).
        with transaction.atomic():
            updated = OutboxEvent.objects.filter(
                id=row.id, publish_state="PENDING"
            ).update(
                publish_state="PUBLISHED", published_at=timezone.now()
            )
        if not updated:
            # Already flipped by a concurrent relay (duplicate XADD happened).
            self.counters.note_error("concurrent_publish_race")
            logger.warning(
                "relay publish race: event_id=%s already transitioned "
                "(duplicate delivery possible; consumer dedupe applies)",
                row.event_id,
            )
            return False
        self.counters.published += 1
        self.counters.publish_latency_ms_total += (time.monotonic() - started) * 1000.0
        logger.info(
            "relay published event_id=%s subject=%s type=%s seq=%s",
            row.event_id, row.subject, row.event_type, row.seq,
        )
        return True

    def _schedule_retry(self, row: ClaimedRow, category: str) -> None:
        """PD-4: attempts += 1; available_at = now + backoff (or park at N=5)."""
        new_attempts = row.attempts + 1
        if new_attempts >= backoff_mod.RETRY_BUDGET:
            self._park(row, new_attempts, category)
            return
        delay = backoff_mod.next_backoff_seconds(new_attempts, rng=self.rng)
        with transaction.atomic():
            OutboxEvent.objects.filter(id=row.id, publish_state="PENDING").update(
                attempts=new_attempts,
                available_at=timezone.now() + timedelta(seconds=delay),
                last_error=category,
            )
        self.counters.retried += 1
        logger.warning(
            "relay retry scheduled event_id=%s attempts=%s category=%s",
            row.event_id, new_attempts, category,
        )

    def _park(self, row: ClaimedRow, new_attempts: int, category: str) -> None:
        """PD-5: N=5 → XADD to dlq.<group> + publish_state=FAILED.

        No auto-purge (FAILED retention OPEN). ``last_error`` = safe category.
        If the DLQ XADD itself fails, the row stays PENDING and the retry
        budget is re-consumed later — at-least-once never degrades to loss.
        """
        try:
            self.transport.publish_dlq(row.envelope_bytes, error_category=category)
        except TransportError as exc:
            dlq_category = backoff_mod.categorize_error(exc)
            self.counters.note_error(dlq_category)
            delay = backoff_mod.next_backoff_seconds(new_attempts, rng=self.rng)
            with transaction.atomic():
                OutboxEvent.objects.filter(id=row.id, publish_state="PENDING").update(
                    attempts=row.attempts,  # budget not consumed; park retried later
                    available_at=timezone.now() + timedelta(seconds=delay),
                    last_error=dlq_category,
                )
            logger.warning(
                "relay dlq publish failed event_id=%s category=%s (row stays PENDING)",
                row.event_id, dlq_category,
            )
            return
        with transaction.atomic():
            OutboxEvent.objects.filter(id=row.id, publish_state="PENDING").update(
                publish_state="FAILED",
                attempts=new_attempts,
                last_error=category,
            )
        self.counters.failed += 1
        logger.error(
            "relay parked event_id=%s subject=%s type=%s seq=%s attempts=%s "
            "category=%s (dlq=%s; no auto-purge — FAILED retention OPEN)",
            row.event_id, row.subject, row.event_type, row.seq, new_attempts,
            category, self.transport.dlq_stream,
        )

    # -- PEL reclaim (PD-7) ---------------------------------------------------

    def reclaim_idle(self) -> int:
        """XAUTOCLAIM idle messages back to this consumer (PD-7, tunable).

        Transport-side bookkeeping only: PG outbox state is untouched here —
        the outbox remains the source of truth. Counted for observability.
        """
        try:
            claimed = self.transport.autoclaim(
                self.settings.idle_ms, count=self.settings.claim_batch
            )
        except TransportError as exc:
            self.counters.note_error(backoff_mod.categorize_error(exc))
            return 0
        self.counters.reclaimed += len(claimed)
        if claimed:
            logger.info(
                "relay reclaimed %d idle PEL entries (min_idle_ms=%s)",
                len(claimed), self.settings.idle_ms,
            )
        return len(claimed)
