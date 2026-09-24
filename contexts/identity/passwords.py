"""Password policy + Argon2id hashing (P0.6.2-A — §12.2, §10.2, R-04).

Django-free like :mod:`contexts.identity.lifecycle` so the unit tier proves
the contract without any database; the DB-bound orchestration (credential +
secret rows, history, wipe) lives in :mod:`contexts.identity.services`.

Architecture contract implemented here (nothing invented):

* **Hash:** Argon2id, initial parameters ``m=19456 KiB (19 MiB), t=2, p=1``
  (§12.2 "Initial Target"), PHC string stored as-is — the PHC string is the
  source of truth for verification and for parameter inspection; the
  long-term target (§12.2 → §50.3: ``m=64 MiB, t=3, p=4``) exists so
  :func:`check_needs_rehash` can compare *stored* params against *policy*.
* **Policy (§12.2 / FR-004):** min 12 (registration default), max 256;
  Unicode NFC; composition rules forbidden (none enforced); no expiry; no
  hints; history = current + 1 prior (R-04, enforced in services).
* **Breach screening (§12.2, OQ-03):** deny-interface only — the corpus
  itself is a separate artifact (OQ-03 disposition: offline k-anon bloom).
  The default checker is deliberately fail-open (see class docstring) and
  the caller must inject a real implementation once OQ-03's corpus ships.

Plaintext discipline (§6.6-2, INV-03): passwords exist only as function
arguments; they are never stored, logged, repr'd, or embedded in exceptions.
"""

from __future__ import annotations

import unicodedata
from typing import Protocol

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# §12.2 Initial Target (2024 OWASP rev): m=19 MiB, t=2, p=1.
INITIAL_MEMORY_KIB = 19_456
INITIAL_TIME_COST = 2
INITIAL_PARALLELISM = 1
# §12.2 → §50.3 long-term raise target: m=64 MiB, t=3, p=4.
TARGET_MEMORY_KIB = 65_536
TARGET_TIME_COST = 3
TARGET_PARALLELISM = 4

# §12.2 / FR-004 length rules.
MIN_PASSWORD_LENGTH = 12       # registration default
LEGACY_FLOOR_LENGTH = 8        # absolute floor, legacy-import boundary ONLY
MAX_PASSWORD_LENGTH = 256      # §12.1 password row / T-29 bounded-KDF note


class PasswordPolicyViolation(Exception):
    """A password outside the §12.2 policy was submitted (message is safe)."""


class PasswordHistoryConflict(Exception):
    """The submitted password equals the immediately-previous one (R-04)."""


class BreachDenier(Protocol):
    """OD-3 boundary: k-anonymity breach-screening seam (§12.2, OQ-03).

    ``deny`` receives the *normalized* candidate password and returns True
    when the password is known-compromised.  Implementations MUST NOT log,
    persist, or transmit the password itself; a k-anonymity implementation
    transmits only a truncated hash prefix.
    """

    def deny(self, normalized_password: str) -> bool:  # pragma: no cover - protocol
        ...


class AllowAllBreachDenier:
    """Default breach denier (OD-3): always-allow stub, explicit not None.

    OQ-03 has not shipped its corpus artifact yet; rather than invent a
    semi-working screen, the boundary is typed, injectable, and the
    fail-open default is *documented here* so wiring a real denier later is
    a one-line change at the service call site, not a redesign.
    """

    def deny(self, normalized_password: str) -> bool:  # noqa: ARG002 - protocol arg
        return False


_hasher = PasswordHasher(
    memory_cost=INITIAL_MEMORY_KIB,
    time_cost=INITIAL_TIME_COST,
    parallelism=INITIAL_PARALLELISM,
    hash_len=32,
    salt_len=16,
    type=Type.ID,  # argon2id — §12.2
)


def normalize(raw: str) -> str:
    """§12.2: Unicode NFC.  No case folding, no alias-style lowering of secrets."""
    return unicodedata.normalize("NFC", raw)


def validate(
    raw: str, *, legacy_import: bool = False, breach: BreachDenier | None = None
) -> str:
    """Validate + normalize a candidate password; returns the normalized form.

    Raises :class:`PasswordPolicyViolation` with a policy message that never
    contains any part of the password.  ``legacy_import=True`` allows the
    8-char absolute floor (§12.2: "8 as absolute floor for legacy import").
    """
    pw = normalize(raw)
    minimum = LEGACY_FLOOR_LENGTH if legacy_import else MIN_PASSWORD_LENGTH
    if len(pw) < minimum:
        raise PasswordPolicyViolation(
            f"password must be at least {minimum} characters"
            + (" (legacy-import floor)" if legacy_import else "")
        )
    if len(pw) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyViolation(
            f"password must be at most {MAX_PASSWORD_LENGTH} characters"
        )
    # Composition rules are forbidden (§12.2) — deliberately not enforced.
    # Expiry/hints do not exist (§12.2) — nothing to enforce here.
    if breach is not None and breach.deny(pw):
        raise PasswordPolicyViolation(
            "password is known-compromised and is rejected (breach deny)"
        )
    return pw


def hash_password(normalized_password: str) -> str:
    """Argon2id-hash a *normalized* password; returns the PHC string."""
    return _hasher.hash(normalized_password)


class PasswordVerificationFailed(Exception):
    """Verification failed (wrong password / malformed hash / backend error)."""


def verify(phc: str, normalized_password: str) -> bool:
    """Constant-ish verify against a stored PHC string (§12.2 verify path)."""
    try:
        return _hasher.verify(phc, normalized_password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError) as exc:
        # Never echo the password (it is not in the exception); keep context minimal.
        raise PasswordVerificationFailed(f"password verification error: {type(exc).__name__}") from exc


def check_needs_rehash(phc: str) -> bool:
    """True when the *stored* PHC parameters are below current policy
    (§12.2 rehash-on-login: "params stored per-hash for transparent upgrade
    on next successful login")."""
    return _hasher.check_needs_rehash(phc)


def stored_params(phc: str) -> tuple[int, int, int]:
    """Extract ``(memory_kib, time_cost, parallelism)`` from a PHC string —
    proves params are per-hash inspectable (each parameter verifiable)."""
    # PHC: $argon2id$v=19$m=<m>,t=<t>,p=<p>$...
    body = phc.split("$")[3]
    fields = dict(part.split("=", 1) for part in body.split(","))
    return int(fields["m"]), int(fields["t"]), int(fields["p"])
