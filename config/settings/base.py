"""
UIAP base settings — P0.4 level.

Configuration contract (§54.1): non-secret parameters arrive as environment
variables; secrets NEVER live in code and arrive via KMS/Vault injection at
runtime (§41.4) — production settings fail fast rather than fall back.

Two deliberately separate contracts (P0.3 decisions):
  - UIAP_ENV               = environment identity (validated; identity ONLY)
  - DJANGO_SETTINGS_MODULE = Django settings selection (the ONLY selector)

P0.4 adds the database foundation (§34):
  - DATABASES via django.db.backends.postgresql (psycopg 3), configured from
    the UIAP_DB_* contract; NO SQLite anywhere (§51.1).
  - staging/prod are fail-closed: missing/empty required DB configuration is
    a boot error (§41.4 posture, applied to the DB contract).
  - dev/test tolerate unset DB parameters with neutral defaults so local
    tooling (checks, unit tier) keeps booting without a live server; nothing
    here ever points at SQLite.
  - The migration connection pins ``search_path=uiap_migration`` so Django's
    ``django_migrations`` bookkeeping table is created in the infrastructure
    schema (ADR 0001, decisions A-1/A-3/A-5) — the eight domain schemas and
    role/grant model are provisioned by the CI-owned bootstrap SQL
    (deploy/db/bootstrap/001_schemas_roles.sql, decision A-4), never by code.

Explicitly ABSENT (each lands in its own later sub-phase per the §60 plan):

  - CACHES        -> cache sub-phase (§35.3: Valkey, never source of truth).
  - Celery config -> worker sub-phase (§36.1: JSON-only serializers, T-25).
  - Logging       -> observability sub-phase (§45).
  - Rate limiting -> rate-limit sub-phase (§24.6).
  - Middleware    -> framework defaults only (see below); real security
                    middleware is a later sub-phase.
  - INSTALLED_APPS carries the Django minimum-boot set, the outbox
    infrastructure app (P0.4), and the FIRST bounded context app — identity
    (P0.6.1, §9.1). Contexts register exactly when their storage foundation
    lands; no other context is registered yet.
"""

import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from config.settings._env import validate_environment

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# --- Environment identity (G-2; §54.1 per-env app configs) -------------------
# Identity ONLY — never a settings selector. Unset/empty is tolerated (no
# architecture mandate requires it); a present-but-unknown value is a hard,
# clear configuration error rather than silent tolerance.
UIAP_ENV = validate_environment(os.environ.get("UIAP_ENV"))

# --- Applications: Django minimum-boot set + outbox infrastructure ---------
# django.contrib.admin is deliberately ABSENT (App. A: admin-free platform;
# hosted pages are UIAP-owned §7.2). auth/contenttypes stay because core
# Django machinery (migrations framework, auth stack) presumes them; no
# domain behavior derives from them in this skeleton and P0.4 runs ONLY the
# targeted `migrate outbox` (ADR 0001) — no auth/contenttypes tables exist.
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    # Cross-cutting infrastructure subsystem (decision A-2) — NOT a context
    # domain app; app_label "outbox".
    "core.outbox.apps.OutboxConfig",
    # First bounded context (§9.1): identity storage + lifecycle (P0.6.1).
    "contexts.identity.apps.IdentityConfig",
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

# --- Database foundation (§34; P0.4, ADR 0001) -------------------------------
# PostgreSQL 17 via psycopg 3 (pyproject pins psycopg[binary]>=3.2). No SQLite
# fallback exists anywhere (§51.1) — an unset/empty parameter is handled
# explicitly per environment posture, never by silently switching engines.
#
# Parameter postures:
#   staging/prod : fail-closed — missing/empty required parameter is a boot
#                  error (§41.4; the DB endpoint is as security-relevant as
#                  the secret).
#   dev/test     : neutral local defaults keep checks/unit tier bootable
#                  without a live server (existing behavior preserved, no
#                  scope creep); real local DBs come from the env contract.
# Secrets: UIAP_DB_PASSWORD arrives via env/KMS/Vault injection — never
# hardcoded, never defaulted to a literal.

_MIGRATION_SCHEMA = "uiap_migration"

_DB_HOST = os.environ.get("UIAP_DB_HOST", "").strip()
_DB_PORT = os.environ.get("UIAP_DB_PORT", "").strip()
_DB_NAME = os.environ.get("UIAP_DB_NAME", "").strip()
_DB_USER = os.environ.get("UIAP_DB_USER", "").strip()
_DB_PASSWORD = os.environ.get("UIAP_DB_PASSWORD", "")
_DB_SSLMODE = os.environ.get("UIAP_DB_SSLMODE", "prefer").strip()

# Fail-closed gate: a hardened posture is selected by ANY of three
# independent signals (defense in depth):
#   1. the UIAP_ENV identity says staging/prod,
#   2. the DJANGO_SETTINGS_MODULE selector names staging/prod (G-3: real
#      deployments must set it), or
#   3. a staging/prod module is currently being imported on top of this base
#      module (star-import ⇒ it is in sys.modules while base executes) — so
#      importing config.settings.prod is fail-closed regardless of env vars.
# With no signal at all, the neutral dev/test laptop posture applies: unset
# DB parameters fall back to the documented local defaults so checks and the
# unit tier keep booting without a server (S2: preserve dev/test behavior).
if (
    UIAP_ENV in ("staging", "prod")
    or os.environ.get("DJANGO_SETTINGS_MODULE", "").strip().endswith((".staging", ".prod"))
    or any(m in sys.modules for m in ("config.settings.staging", "config.settings.prod"))
):
    # Fail-closed: a missing/empty required DB parameter must not boot
    # (§41.4: the DB endpoint is as security-relevant as the secret — there
    # is no "guess localhost" fallback in hardened postures).
    _missing = [name for name, value in (
        ("UIAP_DB_HOST", _DB_HOST),
        ("UIAP_DB_PORT", _DB_PORT),
        ("UIAP_DB_NAME", _DB_NAME),
        ("UIAP_DB_USER", _DB_USER),
        ("UIAP_DB_PASSWORD", _DB_PASSWORD),
    ) if not value]
    if _missing:
        raise ImproperlyConfigured(
            "Database configuration is required in staging/prod and was "
            f"missing or empty: {', '.join(_missing)} (§41.4: no silent "
            "fallbacks — refuse to boot rather than guess an endpoint)."
        )

# Neutral dev/test defaults apply only where the gate above left them unset:
# local checks and the unit tier boot without a live server (P0.4 S2 rule:
# preserve existing dev/test behavior, no scope creep).
if not _DB_HOST:
    _DB_HOST = "localhost"
if not _DB_PORT:
    _DB_PORT = "5432"
if not _DB_NAME:
    _DB_NAME = "uiap"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _DB_NAME,
        "USER": _DB_USER,
        "PASSWORD": _DB_PASSWORD,
        "HOST": _DB_HOST,
        "PORT": _DB_PORT,
        "OPTIONS": {
            # §34.7 roles: the login roles arrive via the CI-owned bootstrap;
            # sslmode comes from the environment (e.g. require/verify-full).
            "sslmode": _DB_SSLMODE,
            # A-1/A-3: pin the session search_path to the infrastructure
            # schema so Django's `django_migrations` bookkeeping table is
            # created in uiap_migration (never public, never a domain
            # schema). Domain DDL is unaffected: the outbox model carries a
            # fully schema-qualified db_table ('uiap_access"."outbox_events').
            # Single pool for app + migrations in P0; split pools are a later,
            # measured decision (ADR 0001). application_name keeps server-side
            # pg_stat_activity triage unambiguous.
            "options": f"-c search_path={_MIGRATION_SCHEMA} "
            "-c application_name=uiap-django",
        },
        "CONN_MAX_AGE": 0,
        "ATOMIC_REQUESTS": False,
    },
}
