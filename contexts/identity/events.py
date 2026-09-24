"""§29.3 event catalog — P0.6.2-B (BD-3/BD-7).

``docs/ARCHITECTURE.md:2300``: "Event catalog (V1) — **names are contracts**".
This module is the P0.6.2-B form of that contract: explicit constants for the
events whose runtime mutation paths actually exist in
:mod:`contexts.identity.services`, each mapped to its §29.3 catalog name.
``dataversion`` is 1 — the §29.5 envelope's initial version lane and the
``OutboxEvent.dataversion`` default established in P0.4.

Deliberately absent (BD-3; their mutations do not exist yet — no invention):

* ``identity.provisional_expired`` — the §11.4 PROVISIONAL-TTL sweeper is a
  future worker; no runtime path emits it.
* ``password.imported`` — the legacy-import service path does not exist
  (only the §12.2 ``legacy_import`` policy floor does).
* everything else in §29.3 belongs to contexts that are not implemented
  (email/phone/mfa/authn/session/…).

Plain string constants (BD-7: no registry framework, no event-schemas/
artifacts this phase — the §29.3 registry artifact is a later deliverable).
"""

from __future__ import annotations

# --- identity lifecycle (§29.3 line 1) --------------------------------------
IDENTITY_CREATED = "identity.created"
IDENTITY_ACTIVATED = "identity.activated"
IDENTITY_SUSPENDED = "identity.suspended"
IDENTITY_REINSTATED = "identity.reinstated"
IDENTITY_LOCKED = "identity.locked"
IDENTITY_UNLOCKED = "identity.unlocked"
IDENTITY_DELETION_REQUESTED = "identity.deletion_requested"
IDENTITY_DELETED = "identity.deleted"

# --- credential lifecycle (§29.3 line 2) ------------------------------------
CREDENTIAL_ADDED = "credential.added"
CREDENTIAL_VERIFIED = "credential.verified"
CREDENTIAL_REVOKED = "credential.revoked"

# --- password (§29.3 line 4) -------------------------------------------------
PASSWORD_CHANGED = "password.changed"

#: The complete P0.6.2-B emit set — every name must appear verbatim in the
#: §29.3 catalog (ARCHITECTURE.md:2302).  Tested exactly (unit tier).
EVENT_TYPES: frozenset[str] = frozenset(
    {
        IDENTITY_CREATED,
        IDENTITY_ACTIVATED,
        IDENTITY_SUSPENDED,
        IDENTITY_REINSTATED,
        IDENTITY_LOCKED,
        IDENTITY_UNLOCKED,
        IDENTITY_DELETION_REQUESTED,
        IDENTITY_DELETED,
        CREDENTIAL_ADDED,
        CREDENTIAL_VERIFIED,
        CREDENTIAL_REVOKED,
        PASSWORD_CHANGED,
    }
)

#: §29.5 envelope ``dataversion`` — initial major lane (established P0.4).
DATAVERSION = 1
