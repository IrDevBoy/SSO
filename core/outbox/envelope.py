"""CloudEvents 1.0-compatible envelope construction (P0.7, §29.5, ADR-0005).

The relay builds the §29.5 envelope from an outbox row — nothing invented:

- ``id``            = outbox ``event_id`` (UUIDv7; invariant #11)
- ``type``          = outbox ``event_type``
- ``subject``       = outbox ``subject`` (``identity:<uuid>``, BD-2)
- ``time``          = outbox ``created_at`` (RFC 3339 UTC)
- ``data``          = outbox ``payload``
- ``specversion``   = ``"1.0"`` (transport-level constant, §29.5 shape)
- ``datacontenttype`` = ``"application/json"`` (§29.5 shape)
- ``source``        = configured value ONLY (``UIAP_RELAY_SOURCE``);
                      missing/empty is a hard construction error — the relay
                      never invents an issuer (OQ-01 OPEN; BD-9, ADR-0004).
- ``schemaurl``     = deliberately NOT emitted (invariant #14)
- ``dataversion``   = outbox ``dataversion``
- ``seq``           = outbox ``seq`` (per-subject monotonic, §29.4)
- ``partition_key`` = outbox ``partition_key``
- ``traceparent``   = outbox ``trace_id`` (the stored traceparent value, BD-6)
- ``request_id``    / ``correlation_id`` = outbox columns
- ``metadata``      = outbox ``metadata`` verbatim (already source-backed:
                      ADR-0004 BD-6 wrote only ``{"region": ...}``); the relay
                      never fabricates ``producer``/``test`` (PD-8).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone

__all__ = ["EnvelopeError", "build_envelope"]


class EnvelopeError(Exception):
    """Raised when the envelope cannot be built without inventing values."""


def _rfc3339(dt: datetime) -> str:
    """RFC 3339 UTC timestamp (§29.5 ``time``)."""
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, dt_timezone.utc)
    return dt.astimezone(dt_timezone.utc).isoformat().replace("+00:00", "Z")


def build_envelope(*, source: str | None, row) -> dict:
    """Build the §29.5 CloudEvents-compatible envelope from an outbox row.

    ``source`` must be a non-empty, caller-verified configuration value.
    A missing/empty/whitespace source raises :class:`EnvelopeError` — the
    relay refuses to publish rather than inventing an issuer (OQ-01).
    """
    if source is None or not str(source).strip():
        raise EnvelopeError(
            "CloudEvents 'source' is required and no verified value exists "
            "(OQ-01 OPEN: the relay must not invent an issuer; provide "
            "UIAP_RELAY_SOURCE from deployment config)."
        )
    metadata = row.metadata if isinstance(row.metadata, dict) else None
    envelope = {
        "specversion": "1.0",
        "id": str(row.event_id),
        "type": row.event_type,
        "source": str(source).strip(),
        "subject": row.subject,
        "time": _rfc3339(row.created_at),
        "datacontenttype": "application/json",
        "dataversion": row.dataversion,
        "seq": row.seq,
        "partition_key": row.partition_key,
        "data": row.payload,
    }
    if row.trace_id:
        envelope["traceparent"] = row.trace_id
    if row.request_id:
        envelope["request_id"] = row.request_id
    if row.correlation_id:
        envelope["correlation_id"] = row.correlation_id
    if metadata is not None:
        envelope["metadata"] = metadata
    return envelope


def envelope_json(envelope: dict) -> bytes:
    """Canonical JSON bytes for XADD (sort_keys for deterministic transport)."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
