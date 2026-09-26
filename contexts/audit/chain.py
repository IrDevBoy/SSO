"""§28.4 hash-chain mathematics — pure functions, unit-testable without a DB.

Architecture contract (§28.4 V1 structure, verbatim requirements):

* Chain scope: within each ``(stream, month-partition)`` subpartition, rows
  form a hash chain.
* Formula: ``row_hash = H(row_hash_input || prev_hash)`` — H is SHA-256
  (the repository's hash convention: ADR-0004 BD-4, payload_hash).
* ``row_hash_input`` is the canonical JSON of the row's contract fields
  (the redaction-safe fields — digests, ids, action, stream, seq; secret /
  PII values are excluded from hot rows by §28.6 construction, so the chain
  input never carries them).
* Genesis rows (first row of a subpartition) chain from 64 zeros — the
  deterministic "no predecessor" value (kept constant and documented).

The checkpoint commitment (§28.4 layer 2) is a hash over the chain segment:
``root_hash = H(last_row_hash || seq_to)`` chained to the previous root via
``prev_root_hash``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

__all__ = [
    "GENESIS_PREV_HASH",
    "CHECKPOINT_ROWS",
    "compute_row_hash",
    "row_hash_input",
    "root_hash_for_segment",
]

#: Deterministic predecessor for the first row of a subpartition chain.
GENESIS_PREV_HASH = "0" * 64

#: §28.4 layer 2: checkpoint every 5,000 rows (or 15 min — the time bound is
#: the checkpoint job's cadence, ADR-0006 §17; the row-count bound is
#: enforced inline by the append service).
CHECKPOINT_ROWS = 5_000

#: Fields that make up ``row_hash_input`` — the §28.2 contract fields that
#: are redaction-safe by construction (ids, digests, taxonomy names).
_HASH_FIELDS = (
    "audit_uuid",
    "actor_kind",
    "actor_id",
    "action",
    "subject_kind",
    "subject_id",
    "outcome",
    "before_digest",
    "after_digest",
    "stream",
    "seq_in_stream",
    "at_ts",
)


def _canonical(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def row_hash_input(event) -> bytes:
    """Canonical JSON bytes of the chain-relevant fields (BD-4 convention:
    ``sort_keys=True, separators=(",", ":"), ensure_ascii=False``)."""
    payload = {field: _canonical(getattr(event, field)) for field in _HASH_FIELDS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_row_hash(event, prev_hash: str) -> str:
    """§28.4: ``row_hash = H(row_hash_input || prev_hash)`` (SHA-256)."""
    h = hashlib.sha256()
    h.update(row_hash_input(event))
    h.update(prev_hash.encode("ascii"))
    return h.hexdigest()


def root_hash_for_segment(last_row_hash: str, seq_to: int, prev_root_hash: str | None) -> str:
    """§28.4 layer 2: the segment commitment chained to the previous root."""
    h = hashlib.sha256()
    h.update(last_row_hash.encode("ascii"))
    h.update(str(seq_to).encode("ascii"))
    h.update((prev_root_hash or GENESIS_PREV_HASH).encode("ascii"))
    return h.hexdigest()
