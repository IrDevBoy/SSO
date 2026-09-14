"""
UIAP base settings — P0.3 level.

Configuration contract (§54.1): non-secret parameters arrive as environment
variables; secrets NEVER live in code and arrive via KMS/Vault injection at
runtime (§41.4) — production settings fail fast rather than fall back.

Two deliberately separate contracts (P0.3 decisions):
  - UIAP_ENV               = environment identity (validated; identity ONLY)
  - DJANGO_SETTINGS_MODULE = Django settings selection (the ONLY selector)

Explicitly ABSENT (each lands in its own later sub-phase per the §60 plan):

  - DATABASES     -> database-foundation sub-phase (§34: schema-per-context,
                     5 DB roles, psycopg) — no DB touches the skeleton.
  - CACHES        -> cache sub-phase (§35.3: Valkey, never source of truth).
  - Celery config -> worker sub-phase (§36.1: JSON-only serializers, T-25).
  - Logging       -> observability sub-phase (§45).
  - Rate limiting -> rate-limit sub-phase (§24.6).
  - Middleware    -> framework defaults only (see below); real security
                    middleware is a later sub-phase.
  - INSTALLED_APPS contains ONLY Django's minimum-boot set. The bounded
    contexts (§9.1) are NOT registered — app registration happens per
    context when each is actually built.
"""

import os
from pathlib import Path

from config.settings._env import validate_environment

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# --- Environment identity (G-2; §54.1 per-env app configs) -------------------
# Identity ONLY — never a settings selector. Unset/empty is tolerated (no
# architecture mandate requires it); a present-but-unknown value is a hard,
# clear configuration error rather than silent tolerance.
UIAP_ENV = validate_environment(os.environ.get("UIAP_ENV"))

# --- Applications: Django minimum-boot set ONLY -----------------------------
# django.contrib.admin is deliberately ABSENT (App. A: admin-free platform;
# hosted pages are UIAP-owned §7.2). auth/contenttypes stay because core
# Django machinery (migrations framework, auth stack) presumes them; no
# domain behavior derives from them in this skeleton.
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
]

MIDDLEWARE = [
    # Framework defaults, stripped of everything domain/security-specific
    # (no security middleware here — it is a later sub-phase per the plan).
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# --- URL routing ------------------------------------------------------------
ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

ASGI_APPLICATION = "config.asgi.application"
WSGI_APPLICATION = "config.wsgi.application"

# --- Internationalization (§53: fa + en; UTC everywhere, §34.6/§33.8) -------
LANGUAGE_CODE = "en-us"  # default UI locale; fa is enabled via LOCALE_PATHS
TIME_ZONE = "UTC"        # §34.6: storage UTC, always; no local-time expiry math
USE_I18N = True          # §53: i18n from the first deploy (not bolted on later)
USE_TZ = True            # timezone-aware datetimes only (never naive)

LOCALE_PATHS = [BASE_DIR / "locale"]  # locale/fa + locale/en trees exist

# --- Static / media (skeleton-level: no serving config, no CDN wiring) ------
STATIC_URL = "static/"

# --- Default auto field -----------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Environment-sourced flags ----------------------------------------------
# DEBUG/ALLOWED_HOSTS are per-environment concerns (§54.1): base is the
# conservative baseline (off), dev relaxes via its env contract, staging/prod
# hard-code the safe values. Base provides no secret material at all (§41.4).
DEBUG = False
