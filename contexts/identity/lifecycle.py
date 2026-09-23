"""Identity lifecycle and credential transition maps (§11.4, §12.0).

Pure data + pure validation — deliberately **Django-free** so the unit tier
can prove the state machine without any database (the DB-bound orchestration
lives in :mod:`contexts.identity.services`).  These maps are the executable
form of the §11.4 state diagram; the CHECK constraints in the models mirror
the status enums, and the transition validation raises instead of coercing.

D-1 (ADR 0002): ``ABANDONED`` is part of the status set because §11.4's
state machine defines it (``PROVISIONAL --> ABANDONED``), even though the
§11.2 status enumeration omits it — the discrepancy is documented, the
machine is authoritative.
"""

from __future__ import annotations


class TransitionForbidden(Exception):
    """A transition outside the architecture's allowed edges was attempted."""

    def __init__(self, kind: str, current: str, to: str) -> None:
        self.kind = kind
        self.current = current
        self.to = to
        super().__init__(f"forbidden {kind} transition {current!r} -> {to!r}")


# ---------------------------------------------------------------------------
# Identity lifecycle (§11.4 — exactly the diagram edges, nothing invented).
# Terminal states (DELETED / ABANDONED / MERGED) have empty successor sets.
# ---------------------------------------------------------------------------
IDENTITY_TRANSITIONS: dict[str, frozenset[str]] = {
    "PROVISIONAL": frozenset({"ACTIVE", "ABANDONED"}),
    "ACTIVE": frozenset({"SUSPENDED", "LOCKED", "PENDING_DELETION", "MERGED"}),
    "SUSPENDED": frozenset({"ACTIVE", "PENDING_DELETION", "MERGED"}),
    "LOCKED": frozenset({"ACTIVE", "PENDING_DELETION"}),
    "PENDING_DELETION": frozenset({"ACTIVE", "DELETED"}),
    "DELETED": frozenset(),
    "ABANDONED": frozenset(),
    "MERGED": frozenset(),
}

IDENTITY_STATUSES: frozenset[str] = frozenset(IDENTITY_TRANSITIONS)
#: Terminal: closed_at set, tombstone semantics (INV-01), no outgoing edges.
IDENTITY_TERMINAL_STATUSES: frozenset[str] = frozenset({"DELETED", "ABANDONED", "MERGED"})
#: Live (non-terminal) — the partial "ops scans" index condition (§34.4).
IDENTITY_LIVE_STATUSES: frozenset[str] = IDENTITY_STATUSES - IDENTITY_TERMINAL_STATUSES

IDENTITY_TYPES: frozenset[str] = frozenset({"HUMAN", "ORGANIZATION", "SERVICE"})
VERIFICATION_LEVELS: frozenset[str] = frozenset({"UNVERIFIED", "IAL1", "IAL2"})


# ---------------------------------------------------------------------------
# Credential header lifecycle (§12.0: "PENDING → ACTIVE → STALE →
# REVOKED (terminal) | EXPIRED" — the chain edges, nothing invented).
# ---------------------------------------------------------------------------
CREDENTIAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"ACTIVE"}),
    "ACTIVE": frozenset({"STALE", "REVOKED", "EXPIRED"}),
    "STALE": frozenset({"REVOKED"}),
    "REVOKED": frozenset(),
    "EXPIRED": frozenset(),
}

CREDENTIAL_STATUSES: frozenset[str] = frozenset(CREDENTIAL_TRANSITIONS)

#: §12.0 header kinds — derived from the §12.1 method matrix / §34.4 typed
#: secret tables (password, email, phone, totp, passkey, recovery codes).
CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {"PASSWORD", "EMAIL", "PHONE", "TOTP", "PASSKEY", "RECOVERY_CODES"}
)


def validate_transition(
    transitions: dict[str, frozenset[str]], current: str, to: str, *, kind: str
) -> None:
    """Raise :class:`TransitionForbidden` unless ``current -> to`` is an edge."""
    if to not in transitions.get(current, frozenset()):
        raise TransitionForbidden(kind, current, to)
