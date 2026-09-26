"""Valkey/Redis Streams transport for the relay (P0.7; §29.4, ADR-0005).

Thin wrapper over ``redis-py`` (already a project dependency:
``redis>=5,<7`` — no new dependency needed) speaking the Redis protocol to
Valkey (App. A / OQ-12 default). Stream/group/consumer names come
exclusively from :mod:`core.outbox.conf` (PD-8) — no invented literals.

Key semantics implemented here:

- ``XADD <stream> * <field> <value>`` — publish (auto-ID; ordering comes
  from the stream entry order, and per-subject ordering is a
  consumer-side gap-detection concern per owner decision PD-3 — the relay
  never blocks per subject);
- group creation with ``MKSTREAM`` (idempotent ``XGROUP CREATE ... 0``);
- ``XREADGROUP`` as the *transport-side* delivery mechanism;
- ``XAUTOCLAIM`` for PEL reclaim after the configured min-idle-time
  (owner decision PD-7 — a tunable mechanism, not an architectural fact);
- ``XACK`` for group-level acknowledgment.

Nothing here touches the PostgreSQL outbox state machine — that is the
relay's job (``core.outbox.relay``).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "StreamsTransport",
    "TransportError",
]


class TransportError(Exception):
    """Raised on transport-level failures (never carries payload data)."""


class StreamsTransport:
    """Config-bound Redis Streams client (Valkey-compatible)."""

    def __init__(self, client: Any, *, stream: str, group: str, consumer: str,
                 dlq_stream: str):
        self._client = client
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.dlq_stream = dlq_stream  # §29.4 naming: dlq.<group>

    # -- group / delivery ---------------------------------------------------

    def ensure_group(self) -> None:
        """Idempotently create the consumer group at position 0 (MKSTREAM)."""
        try:
            self._client.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except Exception as exc:  # redis-py raises ResponseError on BUSYGROUP
            if "BUSYGROUP" in str(exc):
                return
            raise TransportError(f"group create failed: {type(exc).__name__}") from exc

    def publish(self, envelope_bytes: bytes) -> str:
        """XADD one envelope (canonical JSON bytes) to the main stream."""
        try:
            return self._client.xadd(
                self.stream, {"envelope": envelope_bytes.decode("utf-8")}
            )
        except Exception as exc:
            raise TransportError(
                f"xadd failed: {type(exc).__name__}"
            ) from exc

    def publish_dlq(self, envelope_bytes: bytes, *, error_category: str) -> str:
        """XADD a parked event to the DLQ stream (``dlq.<group>``, §29.4)."""
        try:
            return self._client.xadd(
                self.dlq_stream,
                {
                    "envelope": envelope_bytes.decode("utf-8"),
                    "error_category": error_category,
                },
            )
        except Exception as exc:
            raise TransportError(
                f"dlq xadd failed: {type(exc).__name__}"
            ) from exc

    def read_group(self, count: int, block_ms: int | None = None) -> list[tuple[str, str, dict]]:
        """XREADGROUP ``>`` batch. Returns [(entry_id, stream, fields)]."""
        try:
            if block_ms is None:
                result = self._client.xreadgroup(
                    self.group, self.consumer, {self.stream: ">"}, count=count
                )
            else:
                result = self._client.xreadgroup(
                    self.group, self.consumer, {self.stream: ">"},
                    count=count, block=block_ms,
                )
        except Exception as exc:
            raise TransportError(
                f"xreadgroup failed: {type(exc).__name__}"
            ) from exc
        entries: list[tuple[str, str, dict]] = []
        for _stream_name, stream_entries in result or []:
            for entry_id, fields in stream_entries:
                entries.append((entry_id, _stream_name, fields))
        return entries

    def ack(self, entry_id: str) -> None:
        try:
            self._client.xack(self.stream, self.group, entry_id)
        except Exception as exc:
            raise TransportError(f"xack failed: {type(exc).__name__}") from exc

    # -- PEL reclaim (PD-7: XAUTOCLAIM, min-idle-time tunable) ---------------

    def autoclaim(self, min_idle_ms: int, count: int) -> list[tuple[str, str, dict]]:
        """XAUTOCLAIM messages idle ≥ ``min_idle_ms`` to this consumer.

        Returns [(entry_id, stream, fields)] — reclaim is transport-side
        bookkeeping; PostgreSQL outbox state is untouched by this module.
        """
        try:
            cursor, claimed, _ = self._client.xautoclaim(
                self.stream, self.group, self.consumer,
                min_idle_time=min_idle_ms, start_id="0-0", count=count,
            )
        except Exception as exc:
            raise TransportError(
                f"xautoclaim failed: {type(exc).__name__}"
            ) from exc
        return [(entry_id, self.stream, fields) for entry_id, fields in claimed or []]

    # -- observability -------------------------------------------------------

    def stream_length(self) -> int:
        try:
            return int(self._client.xlen(self.stream))
        except Exception as exc:
            raise TransportError(f"xlen failed: {type(exc).__name__}") from exc

    def dlq_length(self) -> int:
        try:
            return int(self._client.xlen(self.dlq_stream))
        except Exception as exc:
            raise TransportError(f"dlq xlen failed: {type(exc).__name__}") from exc

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False
