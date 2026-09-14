"""
Production settings — P0.2 skeleton level.

Production-shaped: DEBUG hard-off, strict hosts, secret from the environment
with fail-fast (§41.4: secrets come from KMS/Vault injection — never code, and
never a code-level fallback). No database/cache/Celery/logging/security-
middleware config at this level — later sub-phases wire those.
"""

import os

from django.core.exceptions import ImproperlyConfigured

from config.settings.base import *  # noqa: F401,F403

DEBUG = False  # hard-off; never env-overridable

ALLOWED_HOSTS = [h.strip() for h in os.environ.get("UIAP_ALLOWED_HOSTS", "").split(",") if h.strip()]

# Fail fast: production boots with a real secret or not at all (§41.4).
# Missing AND empty are both boot errors — an empty string is not a secret.
try:
    SECRET_KEY = os.environ["UIAP_SECRET_KEY"]
except KeyError as exc:
    raise ImproperlyConfigured(
        "UIAP_SECRET_KEY is not set. Production must receive the secret via "
        "environment/KMS/Vault injection — there is no code-level fallback (§41.4)."
    ) from exc
if not SECRET_KEY:
    raise ImproperlyConfigured(
        "UIAP_SECRET_KEY is empty. An empty secret is not a secret — refusing to boot (§41.4)."
    )
