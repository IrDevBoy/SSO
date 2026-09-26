"""Retry/backoff policy for the relay (owner-approved PD-4/PD-5).

§29.4 contract: exponential retry 1 s → 15 m + jitter, poison at N=5.
Owner decision PD-4: ``available_at`` is the relay-side eligibility time and
the failure path updates ``attempts`` + ``available_at`` accordingly.
Owner decision PD-5: after the retry budget the event is parked in the DLQ
stream and ``publish_state=FAILED``; FAILED retention stays OPEN (no purge).

The §29.4 tension is deliberately PRESERVED (owner instruction): the doc
describes retry "per consumer group" while the outbox row carries a single
``available_at``. P0.7 adds no per-group backoff state, table, or column and
invents no new semantics to reconcile them.
"""

from __future__ import annotations

import random

__all__ = [
    "BACKOFF_BASE_SECONDS",
    "BACKOFF_MAX_SECONDS",
    "RETRY_BUDGET",
    "categorize_error",
    "next_backoff_seconds",
]

# §29.4: exponential 1 s → 15 m + jitter (locked contract values).
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 15 * 60.0

# §29.4: N=5 attempts then park (DLQ + FAILED, PD-5).
RETRY_BUDGET = 5

# Full jitter range as a fraction of the computed backoff
# (jitter ∈ [0.5x, 1.5x), bounds are implementation-owned, PD-4).
_JITTER_LOW = 0.5
_JITTER_HIGH = 1.5


def next_backoff_seconds(attempts: int, rng: random.Random | None = None) -> float:
    """Exponential backoff with jitter after ``attempts`` failed attempts.

    attempts=1 → ~1 s … attempts≥4 → capped at 15 m. Jitter stays inside the
    documented [0.5x, 1.5x) band. Result is clamped to [base, max].
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    rng = rng or random.Random()
    raw = min(BACKOFF_BASE_SECONDS * (2 ** (attempts - 1)), BACKOFF_MAX_SECONDS)
    jittered = raw * rng.uniform(_JITTER_LOW, _JITTER_HIGH)
    return float(min(max(jittered, BACKOFF_BASE_SECONDS), BACKOFF_MAX_SECONDS))


def categorize_error(exc: Exception) -> str:
    """Map an exception to a **safe error category** (no payload/PII/secret).

    Categories are enumerated and coarse on purpose: ``last_error`` and log
    lines must never echo event payload, credentials, or user data
    (invariant #10, §41.4/§42 T-22).
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    if "timeout" in text or "timed out" in text:
        return "transport_timeout"
    if "connection" in text or "connect" in text or "refused" in text or "unavailable" in text:
        return "transport_unavailable"
    if "authentication" in text or "auth" in text or "permission" in text or "forbidden" in text:
        return "auth_or_permission"
    if "memory" in text:
        return "resource_exhausted"
    return "unknown_error"
