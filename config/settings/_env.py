"""
Internal environment-parsing helpers for UIAP settings (P0.3, decision G-4).

Internal implementation module ONLY (underscore-prefixed): no public API, no
domain logic, no third-party dependencies. Parsing is deterministic and
strict — malformed configuration is a clear error, never silently coerced
(§54.1: config via env vars (non-secret); §41.4: secrets never defaulted).
"""

import os

from django.core.exceptions import ImproperlyConfigured

# Environment identity values (decision G-2). UIAP_ENV is the *identity* only;
# it never selects the settings module — DJANGO_SETTINGS_MODULE remains the
# sole selection mechanism (the two contracts are deliberately kept separate).
ALLOWED_ENVIRONMENTS = ("dev", "test", "staging", "prod")


def validate_environment(raw: str | None) -> str:
    """Validate the UIAP_ENV identity value.

    Unset/empty is tolerated (no architecture mandate requires it at this
    level); a present-but-unknown value is a hard configuration error.
    Comparison is exact (case-sensitive) to avoid ambiguous identities.
    """
    if raw is None:
        return ""
    value = raw.strip()
    if not value:
        return ""
    if value not in ALLOWED_ENVIRONMENTS:
        raise ImproperlyConfigured(
            f"UIAP_ENV={value!r} is invalid. Allowed values: "
            f"{', '.join(ALLOWED_ENVIRONMENTS)}."
        )
    return value


def env_bool(name: str, default: bool) -> bool:
    """Strict boolean environment variable.

    Unset -> ``default``. Only ``true``/``false`` (case-insensitive, with
    surrounding whitespace tolerated) are valid; empty or any other value is
    a configuration error — malformed values are never silently accepted.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise ImproperlyConfigured(
        f"{name}={raw!r} is not a valid boolean. Use true/false (case-insensitive)."
    )


def env_host_list(name: str, default: list[str]) -> list[str]:
    """Comma-separated host-list environment variable.

    Unset -> ``default`` (copy). When set, items are stripped and empty items
    dropped — so a set-but-empty variable yields ``[]`` (fail-closed: no hosts
    allowed), an explicit and testable semantic.
    """
    raw = os.environ.get(name)
    if raw is None:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def required_secret(name: str) -> str:
    """Fail-fast secret fetch (staging/prod).

    Missing AND empty are both boot errors (§41.4: an empty string is not a
    secret; secrets arrive via environment/KMS/Vault injection — there is no
    code-level fallback).
    """
    try:
        value = os.environ[name]
    except KeyError as exc:
        raise ImproperlyConfigured(
            f"{name} is not set. It must arrive via environment/KMS/Vault "
            "injection — there is no code-level fallback (§41.4)."
        ) from exc
    if not value:
        raise ImproperlyConfigured(
            f"{name} is empty. An empty secret is not a secret — refusing to boot (§41.4)."
        )
    return value
