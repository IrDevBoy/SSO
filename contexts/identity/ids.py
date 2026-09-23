"""RFC 9562 UUIDv7 generation for identity PKs (§11.1: ``id: uuid (v7)``).

Decision D-2 (ADR 0002): hand-rolled, zero new dependencies — Python 3.13's
stdlib ``uuid`` has no ``uuid7`` and PostgreSQL 17 has no native ``uuidv7()``
function, so the identifier is generated application-side and stored in a
plain ``uuid`` column (no DB default; identity ids are immutable ``sub``s).

Determinism / concurrency contract (deliberate, tested):

* **Single-process monotonicity:** within one process, generated ids are
  strictly ordered by ``(unix_ts_ms, counter)`` — the 12-bit ``rand_a``
  field carries a per-millisecond monotonic counter (RFC 9562 §6.2
  "counter" mechanism).  Thread safety comes from a module lock, not from
  any OS/global service.
* **Clock rollback:** if the wall clock stalls or moves backwards, the
  generator holds the last timestamp and keeps incrementing the counter
  (values never go backwards; RFC-mandated monotonic behavior).  If the
  counter exhausts 4096 values inside one millisecond, the timestamp is
  advanced by exactly one millisecond (deterministic, documented).
* **Cross-process uniqueness:** 62 fresh random bits (``os.urandom``) per
  value; combined with the timestamp+counter prefix, cross-process
  collision probability is cryptographically negligible.
* **No hidden global side effects:** the only mutable state is the
  ``(last_ts, counter)`` pair guarded by the lock, justified by the
  monotonicity contract above; ``_time_ms`` is a module function so tests
  can inject a deterministic clock.
"""

import os
import threading
import time
import uuid

_lock = threading.Lock()
_last_ts_ms = 0
_counter = 0

_COUNTER_MODULUS = 0x1000  # 12-bit rand_a field (RFC 9562)


def _time_ms() -> int:
    """Injectable clock (UTC unix milliseconds); tests monkeypatch this."""
    return time.time_ns() // 1_000_000


def uuid7() -> uuid.UUID:
    """Generate an RFC 9562 UUIDv7 (48-bit ms timestamp + 12-bit counter + 62 random bits)."""
    global _last_ts_ms, _counter
    with _lock:
        ts_ms = _time_ms()
        if ts_ms <= _last_ts_ms:
            # Same millisecond (or clock rollback): hold the timestamp and
            # advance the counter — ordering never regresses.
            _counter += 1
            if _counter >= _COUNTER_MODULUS:
                _counter = 1
                ts_ms = _last_ts_ms + 1
            else:
                ts_ms = _last_ts_ms
        else:
            _counter = 0
        _last_ts_ms = ts_ms
        counter = _counter

    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (
        ((ts_ms & ((1 << 48) - 1)) << 80)
        | (0x7 << 76)  # version = 7
        | ((counter & 0xFFF) << 64)  # rand_a = monotonic counter
        | (0b10 << 62)  # RFC 9562 variant
        | rand_b
    )
    return uuid.UUID(int=value)
