"""P0.2 infrastructure tests — Django skeleton validity ONLY.

These tests prove the executable skeleton boots and is internally consistent.
They assert NO domain behavior (none exists), touch NO database (no DATABASES
is configured; SQLite is forbidden per §51.1), and require no services.
"""

import os
import subprocess
import sys

from django.conf import settings


class TestSkeletonValidity:
    """The skeleton loads, is coherent, and carries zero domain surface."""

    def test_settings_module_loads(self):
        # Importing settings proves the settings stack (base <- test) resolves.
        assert settings.DEBUG is False
        assert settings.USE_TZ is True
        assert settings.TIME_ZONE == "UTC"

    def test_urlconf_loads_and_is_empty(self):
        # Root URLconf imports and routes nothing — no endpoint exists in P0.2.
        from config import urls

        assert urls.urlpatterns == []

    def test_wsgi_entrypoint_imports(self):
        from config.wsgi import application  # noqa: F401

    def test_asgi_entrypoint_imports(self):
        from config.asgi import application  # noqa: F401

    def test_root_config_package_imports(self):
        import config  # noqa: F401
        import config.settings  # noqa: F401

    def test_no_domain_apps_registered(self):
        # The bounded contexts (§9.1) are NOT registered in P0.2: app
        # registration happens per context when each is actually built.
        registered = set(settings.INSTALLED_APPS)
        for context_app in (
            "contexts.identity",
            "contexts.access",
            "contexts.profile",
            "contexts.address",
            "contexts.security",
            "contexts.audit",
            "contexts.notification",
            "contexts.org",
            "contexts.platform_admin",
        ):
            assert context_app not in registered

    def test_timezone_and_i18n_match_architecture(self):
        # §34.6/§33.8: UTC, timezone-aware only; §53: i18n on from day one.
        assert settings.USE_I18N is True
        assert settings.USE_TZ is True
        assert settings.TIME_ZONE == "UTC"


class TestEnvironmentSettingsContract:
    """§41.4/§54.1 contract: staging/prod boot with a real secret or not at all.

    Verified in subprocesses so the fail-fast ImportError/KeyError path is
    exercised without polluting the pytest process's Django configuration.
    """

    def _run_import(self, module: str, extra_env: dict[str, str]) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env.update(extra_env)
        env.pop("DJANGO_SETTINGS_MODULE", None)  # isolated module import
        # P0.4 (ADR 0001): staging/prod are fail-closed on DB configuration,
        # so these secret-path tests must supply the full (dummy, non-secret)
        # DB contract — the DB endpoint is now part of the same §41.4 posture.
        env.setdefault("UIAP_DB_HOST", "db.ci.internal")
        env.setdefault("UIAP_DB_PORT", "5432")
        env.setdefault("UIAP_DB_NAME", "uiap")
        env.setdefault("UIAP_DB_USER", "uiap_app")
        env.setdefault("UIAP_DB_PASSWORD", "ci-verification-dummy-password")
        return subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_prod_fails_fast_without_secret(self):
        result = self._run_import("config.settings.prod", {"UIAP_SECRET_KEY": ""})
        assert result.returncode != 0
        assert "UIAP_SECRET_KEY" in result.stderr

    def test_prod_imports_with_secret(self):
        result = self._run_import(
            "config.settings.prod",
            {"UIAP_SECRET_KEY": "ci-verification-dummy-not-a-real-secret"},
        )
        assert result.returncode == 0, result.stderr

    def test_staging_fails_fast_without_secret(self):
        result = self._run_import("config.settings.staging", {"UIAP_SECRET_KEY": ""})
        assert result.returncode != 0
        assert "UIAP_SECRET_KEY" in result.stderr

    def test_staging_imports_with_secret(self):
        result = self._run_import(
            "config.settings.staging",
            {"UIAP_SECRET_KEY": "ci-verification-dummy-not-a-real-secret"},
        )
        assert result.returncode == 0, result.stderr
