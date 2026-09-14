"""
Test settings — P0.2 skeleton level.

Used by the CI/unit tier (pytest-django with DJANGO_SETTINGS_MODULE=
config.settings.test). Deliberately NO database configuration here: the
database-foundation sub-phase introduces PostgreSQL (never SQLite — §51.1:
"testcontainers, no sqlite stand-ins"). Until then, tests must not touch the
ORM/database at all.
"""

from config.settings.base import *  # noqa: F401,F403

DEBUG = False

# Deterministic, secret-free test runtime (value is not a credential;
# it exists only so Django's checks do not demand an env var in CI).
SECRET_KEY = "django-insecure-p0-skeleton-test-only-not-a-secret"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

# Tests never send mail; the console sink keeps the skeleton dependency-free.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Keep the password hasher cheap in tests (framework-standard test accelerator;
# no domain behavior attached).
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
