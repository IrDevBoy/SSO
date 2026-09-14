"""
WSGI entrypoint — P0.3 security contract (decision G-3).

Deployment entrypoints REQUIRE an explicit ``DJANGO_SETTINGS_MODULE``: a
missing, empty, or whitespace-only value fails clearly instead of silently
booting with development settings. There is NO fallback to dev here — the
environment (or deployment manifest) must choose. ``manage.py`` retains the
local-developer default; server entrypoints do not (§54.1: the environment
selects its configuration).
"""

import os

from django.core.exceptions import ImproperlyConfigured
from django.core.wsgi import get_wsgi_application

_settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "").strip()
if not _settings_module:
    raise ImproperlyConfigured(
        "DJANGO_SETTINGS_MODULE is not set. The WSGI entrypoint requires an "
        "explicit settings module (e.g. config.settings.prod) — there is no "
        "implicit dev fallback (P0.3 security contract)."
    )
os.environ["DJANGO_SETTINGS_MODULE"] = _settings_module  # normalized (stripped)

application = get_wsgi_application()
