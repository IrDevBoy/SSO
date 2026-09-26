"""§28.3 audit action taxonomy — names are contracts (like §29.3 events).

Closed set extracted verbatim from the §28.3 audited set; this module owns
the closed-set validation for the append service. Names not in this set are
refused (no silent invention, no silent growth); additions are spec changes
(§28.3: "versioned with the document") → §57 ADR process.

§28.5 streams — the audit is grouped into five streams:
  SEC | IDN | APP | ADM | POL (§28.2 ``stream`` column, §28.5 stream list).
Every audited action maps to exactly one stream; the mapping below is the
P0.7.2 scope slice of the §28.3 taxonomy — only actions whose *producer
paths exist* in this repository (identity/credential/password mutations,
§28.3 "Identity" and "Credentials" bullets). The rest of the §28.3 catalog
belongs to contexts that do not exist yet (no invention, no placeholders).
"""

from __future__ import annotations

from types import MappingProxyType

__all__ = [
    "AUDIT_ACTIONS",
    "AuditStream",
    "TaxonomyViolation",
    "action_stream",
    "validate_action",
]


class AuditStream:
    """§28.2/§28.5 audit streams (closed set)."""

    SEC = "SEC"  # §28.5: security — 5 y retention (R-31)
    IDN = "IDN"  # §28.5: identity — 3 y after anonymization transition (R-31)
    APP = "APP"  # §28.5: applications — 1 y (R-31)
    ADM = "ADM"  # §28.5: admin — 7 y (R-31)
    POL = "POL"  # §28.5: policy — 7 y (R-31)


class TaxonomyViolation(Exception):
    """An action name outside the §28.3 closed taxonomy was submitted."""


def _s(action: str, stream: str) -> tuple[str, str]:
    return action, stream


# §28.3 taxonomy slice — only existing producer paths (§28.3 Identity /
# Credentials bullets; every name verbatim from the architecture text).
# Mapping action→stream follows the §28.5 stream semantics:
#   identity.* → IDN; credential.* / password.* → SEC (credential state is
#   security-relevant; §28.5 gives SEC to security-relevant writes).
_TAXONOMY_PAIRS: tuple[tuple[str, str], ...] = (
    _s("identity.created", AuditStream.IDN),
    _s("identity.activated", AuditStream.IDN),
    _s("identity.suspended", AuditStream.IDN),
    _s("identity.reinstated", AuditStream.IDN),
    _s("identity.locked", AuditStream.IDN),
    _s("identity.unlocked", AuditStream.IDN),
    _s("identity.deletion_requested", AuditStream.IDN),
    _s("identity.deleted", AuditStream.IDN),
    _s("credential.added", AuditStream.SEC),
    _s("credential.verified", AuditStream.SEC),
    _s("credential.revoked", AuditStream.SEC),
    _s("password.changed", AuditStream.SEC),
)

_TAXONOMY: MappingProxyType[str, str] = MappingProxyType(dict(_TAXONOMY_PAIRS))

#: The closed set — every audited action in P0.7.2, verbatim §28.3 names.
AUDIT_ACTIONS: frozenset[str] = frozenset(_TAXONOMY.keys())

#: Mapping of action → §28.2 stream. Immutable.
ACTION_STREAMS: MappingProxyType[str, str] = _TAXONOMY


def validate_action(action: str) -> str:
    """Refuse anything outside the §28.3 closed taxonomy (deterministic)."""
    if action not in _TAXONOMY:
        raise TaxonomyViolation(
            f"audit action {action!r} is not in the §28.3 closed taxonomy — "
            "inventing audit actions is forbidden; additions go through the "
            "§57 ADR process (§28.3: versioned with the document)."
        )
    return action


def action_stream(action: str) -> str:
    """The §28.5 stream for a taxonomy action (validated first)."""
    validate_action(action)
    return _TAXONOMY[action]
