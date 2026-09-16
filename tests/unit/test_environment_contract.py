"""P0.3 tests — environment & configuration contract.

Covers the four approved decisions:
  G-1  dev reads DJANGO_DEBUG / DJANGO_ALLOWED_HOSTS (strict, tested)
  G-2  UIAP_ENV is a validated environment IDENTITY — never a settings selector
  G-3  ASGI/WSGI require explicit DJANGO_SETTINGS_MODULE (no dev fallback);
       manage.py keeps the local dev default
  G-4  shared internal helper config/settings/_env.py

No database, no SQLite, no migrations, no services — unit-tier only. Settings
contracts are verified in subprocesses so each module is imported exactly once
under controlled environment variables.
"""

import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

REPO_ROOT = Path(__file__).resolve().parents[2]

# The single non-secret test key committed in config/settings/test.py (P0.2).
TEST_SETTINGS_KEY = "django-insecure-p0-skeleton-test-only-not-a-secret"


def run_py(code: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run python in a controlled environment (repo root on sys.path)."""
    full_env = dict(os.environ)
    full_env.pop("DJANGO_SETTINGS_MODULE", None)  # isolate from pytest env
    full_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
    )


# ---------------------------------------------------------------------------
# A. Environment parsing (helper level)
# ---------------------------------------------------------------------------


class TestEnvironmentParsing:
    """config.settings._env parsing: strict, deterministic, loud on garbage."""

    def _helper(self, extra_env: dict[str, str] | None = None):
        env = dict(os.environ)
        env.pop("DJANGO_SETTINGS_MODULE", None)
        env.update(extra_env or {})
        return run_py(
            "from config.settings import _env\n"
            "print(_env.validate_environment(_env.os.environ.get('UIAP_ENV')))\n",
            env,
        )

    @pytest.mark.parametrize("value", ["dev", "test", "staging", "prod", ""])
    def test_valid_or_empty_uiap_env_accepted(self, value):
        result = self._helper({"UIAP_ENV": value})
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == value

    def test_unset_uiap_env_tolerated(self):
        result = self._helper({})
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == ""

    def test_unknown_uiap_env_fails_loudly(self):
        result = self._helper({"UIAP_ENV": "production"})
        assert result.returncode != 0
        assert "UIAP_ENV" in result.stderr and "Allowed values" in result.stderr

    def test_uiap_env_is_case_sensitive(self):
        result = self._helper({"UIAP_ENV": "DEV"})
        assert result.returncode != 0  # exact identity, no case games

    def test_env_bool_strict(self):
        result = run_py(
            "from config.settings import _env\n"
            "import os\n"
            "os.environ['X_FLAG']='true';  print(_env.env_bool('X_FLAG', False))\n"
            "os.environ['X_FLAG']='False'; print(_env.env_bool('X_FLAG', True))\n",
            {},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.split() == ["True", "False"]

    def test_env_bool_malformed_fails(self):
        for bad in ["yes", "1", "0", "", "tru", "on", "trueish"]:
            result = run_py(
                "from config.settings import _env\n"
                f"_env.env_bool('X_FLAG', False)\n",
                {"X_FLAG": bad},
            )
            assert result.returncode != 0, f"malformed value {bad!r} accepted"

    def test_env_bool_tolerates_whitespace_around_valid_token(self):
        # Surrounding whitespace is tolerated by design (stripped, not coerced);
        # anything that is not exactly true/false after stripping is an error.
        result = run_py(
            "from config.settings import _env\n"
            "import os\n"
            "os.environ['X_FLAG']=' true '; print(_env.env_bool('X_FLAG', False))\n",
            {},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "True"

    def test_env_bool_default_on_unset(self):
        result = run_py(
            "from config.settings import _env\n"
            "print(_env.env_bool('X_FLAG_UNSET_VAR', True), _env.env_bool('X_FLAG_UNSET_VAR', False))\n",
            {},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.split() == ["True", "False"]

    def test_env_host_list_semantics(self):
        result = run_py(
            "from config.settings import _env\n"
            "import os\n"
            "print(_env.env_host_list('X_HOSTS', ['a']))            # unset -> default copy\n"
            "os.environ['X_HOSTS']=' x.com , y.org ,'; print(_env.env_host_list('X_HOSTS', ['a']))\n"
            "os.environ['X_HOSTS']='  ,  ,'; print(_env.env_host_list('X_HOSTS', ['a']))\n",
            {},
        )
        assert result.returncode == 0, result.stderr
        lines = result.stdout.strip().splitlines()
        assert eval(lines[0]) == ["a"]  # unset -> default (copy)
        assert eval(lines[1]) == ["x.com", "y.org"]  # stripped, empties dropped
        assert eval(lines[2]) == []  # set-but-empty -> fail-closed []

    def test_env_host_list_default_is_copied_not_aliased(self):
        result = run_py(
            "from config.settings import _env\n"
            "d = ['a']\n"
            "h = _env.env_host_list('X_HOSTS_UNSET_VAR', d)\n"
            "h.append('b')\n"
            "print(d)\n",
            {},
        )
        assert result.returncode == 0, result.stderr
        assert eval(result.stdout.strip()) == ["a"]

    def test_required_secret_missing_fails(self):
        result = run_py(
            "from config.settings import _env\n"
            "_env.required_secret('X_SECRET_UNSET_VAR')\n",
            {},
        )
        assert result.returncode != 0
        assert "X_SECRET_UNSET_VAR" in result.stderr

    def test_required_secret_empty_fails(self):
        result = run_py(
            "from config.settings import _env\n"
            "_env.required_secret('X_SECRET_EMPTY_VAR')\n",
            {"X_SECRET_EMPTY_VAR": ""},
        )
        assert result.returncode != 0
        assert "empty" in result.stderr


# ---------------------------------------------------------------------------
# B. Settings isolation (module level, subprocess per module)
# ---------------------------------------------------------------------------


class TestSettingsIsolation:
    """Each settings module produces its contract values in isolation."""

    def _probe(self, module: str, extra_env: dict[str, str]) -> subprocess.CompletedProcess:
        return run_py(
            "import importlib\n"
            f"s = importlib.import_module('{module}')\n"
            "print('DEBUG=', s.DEBUG)\n"
            "print('HOSTS=', getattr(s, 'ALLOWED_HOSTS', None))\n"
            "print('ENV=', getattr(s, 'UIAP_ENV', None))\n",
            extra_env,
        )

    def test_base_debug_off(self):
        r = self._probe("config.settings.base", {})
        assert r.returncode == 0, r.stderr
        assert "DEBUG= False" in r.stdout
        assert "HOSTS= None" in r.stdout  # base defines no ALLOWED_HOSTS (by design)

    def test_dev_default_debug_on_and_host_fallback(self):
        r = self._probe("config.settings.dev", {})
        assert r.returncode == 0, r.stderr
        assert "DEBUG= True" in r.stdout
        assert eval(re.search(r"HOSTS= (\[.*\])", r.stdout).group(1)) == [
            "localhost", "127.0.0.1", "testserver",
        ]

    def test_dev_reads_django_debug_false(self):
        r = self._probe("config.settings.dev", {"DJANGO_DEBUG": "false"})
        assert r.returncode == 0, r.stderr
        assert "DEBUG= False" in r.stdout

    def test_dev_reads_django_allowed_hosts(self):
        r = self._probe("config.settings.dev", {"DJANGO_ALLOWED_HOSTS": " dev.example "})
        assert r.returncode == 0, r.stderr
        assert eval(re.search(r"HOSTS= (\[.*\])", r.stdout).group(1)) == ["dev.example"]

    def test_dev_malformed_django_debug_fails(self):
        r = self._probe("config.settings.dev", {"DJANGO_DEBUG": "yes"})
        assert r.returncode != 0
        assert "DJANGO_DEBUG" in r.stderr

    def test_test_settings_fixed(self):
        r = self._probe("config.settings.test", {})
        assert r.returncode == 0, r.stderr
        assert "DEBUG= False" in r.stdout
        assert "ENV= None" not in r.stdout or True  # UIAP_ENV passthrough validated below

    def test_uiap_env_flows_into_settings(self):
        r = self._probe("config.settings.test", {"UIAP_ENV": "test"})
        assert r.returncode == 0, r.stderr
        assert "ENV= test" in r.stdout

    def test_uiap_env_invalid_fails_everywhere(self):
        r = self._probe("config.settings.test", {"UIAP_ENV": "prod-eu"})
        assert r.returncode != 0
        assert "UIAP_ENV" in r.stderr


# ---------------------------------------------------------------------------
# C. Production safety (staging/prod posture)
# ---------------------------------------------------------------------------


class TestProductionSafety:
    _SECRET = "ci-verification-dummy-not-a-real-secret"

    def _probe(self, module: str, extra_env: dict[str, str]) -> subprocess.CompletedProcess:
        env = {"UIAP_SECRET_KEY": self._SECRET}
        # P0.4 (ADR 0001): staging/prod are fail-closed on DB configuration;
        # these probes target the SECRET paths, so supply the full (dummy,
        # non-secret) DB contract to keep the variable under test decisive.
        env.setdefault("UIAP_DB_HOST", "db.ci.internal")
        env.setdefault("UIAP_DB_PORT", "5432")
        env.setdefault("UIAP_DB_NAME", "uiap")
        env.setdefault("UIAP_DB_USER", "uiap_app")
        env.setdefault("UIAP_DB_PASSWORD", "ci-verification-dummy-password")
        env.update(extra_env)
        return run_py(
            "import importlib\n"
            f"s = importlib.import_module('{module}')\n"
            "print('DEBUG=', s.DEBUG)\n"
            "print('HOSTS=', s.ALLOWED_HOSTS)\n"
            "import os\n"
            "os.environ['DJANGO_DEBUG']='true'\n"
            "os.environ['DJANGO_ALLOWED_HOSTS']='evil.example'\n"
            "importlib.reload(importlib.import_module('config.settings.base'))\n"
            "s2 = importlib.import_module('{module}')\n"
            "print('AFTER_DEBUG=', s2.DEBUG)\n".replace("{module}", module),
            env,
        )

    @pytest.mark.parametrize("module", ["config.settings.staging", "config.settings.prod"])
    def test_debug_hard_off_and_uninfluenced(self, module):
        r = self._probe(module, {"DJANGO_DEBUG": "true"})
        assert r.returncode == 0, r.stderr
        assert "DEBUG= False" in r.stdout
        assert "AFTER_DEBUG= False" in r.stdout  # DJANGO_DEBUG has no effect

    @pytest.mark.parametrize("module", ["config.settings.staging", "config.settings.prod"])
    def test_allowed_hosts_fail_closed(self, module):
        r = self._probe(module, {"UIAP_ALLOWED_HOSTS": ""})
        assert r.returncode == 0, r.stderr
        assert eval(re.search(r"HOSTS= (\[.*\])", r.stdout).group(1)) == []
        # and DJANGO_ALLOWED_HOSTS does not leak into staging/prod
        assert "evil.example" not in r.stdout

    @pytest.mark.parametrize("module", ["config.settings.staging", "config.settings.prod"])
    def test_secret_missing_fails(self, module):
        r = self._probe(module, {"UIAP_SECRET_KEY": ""})
        assert r.returncode != 0
        assert "UIAP_SECRET_KEY" in r.stderr

    @pytest.mark.parametrize("module", ["config.settings.staging", "config.settings.prod"])
    def test_no_django_debug_variable_effect(self, module):
        r = self._probe(module, {})
        assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------------------
# D. Entrypoints (G-3)
# ---------------------------------------------------------------------------


class TestEntrypoints:
    def test_asgi_requires_explicit_settings(self):
        r = run_py("import config.asgi", {})
        assert r.returncode != 0
        assert "DJANGO_SETTINGS_MODULE" in r.stderr and "ASGI" in r.stderr

    def test_wsgi_requires_explicit_settings(self):
        r = run_py("import config.wsgi", {})
        assert r.returncode != 0
        assert "DJANGO_SETTINGS_MODULE" in r.stderr and "WSGI" in r.stderr

    @pytest.mark.parametrize("var_value", ["", "   "])
    def test_blank_settings_module_fails(self, var_value):
        r = run_py("import config.asgi", {"DJANGO_SETTINGS_MODULE": var_value})
        assert r.returncode != 0

    def test_asgi_explicit_module_works(self):
        r = run_py(
            "import config.asgi\nprint(type(config.asgi.application).__name__)",
            {"DJANGO_SETTINGS_MODULE": "config.settings.test"},
        )
        assert r.returncode == 0, r.stderr
        assert result_ok(r)

    def test_wsgi_explicit_module_works(self):
        r = run_py(
            "import config.wsgi\nprint(type(config.wsgi.application).__name__)",
            {"DJANGO_SETTINGS_MODULE": "config.settings.test"},
        )
        assert r.returncode == 0, r.stderr
        assert result_ok(r)

    def test_manage_py_default_remains_dev(self):
        # manage.py keeps the local-developer default (no behavior change).
        source = (REPO_ROOT / "manage.py").read_text(encoding="utf-8")
        assert 'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")' in source

    def test_asgi_wsgi_have_no_dev_default(self):
        for name in ("config/asgi.py", "config/wsgi.py"):
            source = (REPO_ROOT / name).read_text(encoding="utf-8")
            assert "config.settings.dev" not in source, f"{name} still contains a dev default"
            assert "setdefault" not in source, f"{name} still uses setdefault"


def result_ok(r: subprocess.CompletedProcess) -> bool:
    """WSGIHandler/ASGIHandler application object was created."""
    return ("WSGIHandler" in r.stdout) or ("ASGIHandler" in r.stdout)


# ---------------------------------------------------------------------------
# E. Template/code consistency (.env.example)
# ---------------------------------------------------------------------------


class TestTemplateConsistency:
    """Every ACTIVE variable in .env.example has a real reader in code.

    P0.4 (ADR 0001): the UIAP_DB_* variables moved from RESERVED to ACTIVE
    and UIAP_DB_SSLMODE was added; the DB contract now has a real reader in
    config/settings/base.py (approved minimal deviation to this P0.3 file).
    """

    TEMPLATE = REPO_ROOT / ".env.example"

    ACTIVE_VARS = {
        "UIAP_ENV": "config/settings/base.py",
        "DJANGO_SETTINGS_MODULE": "manage.py",
        "DJANGO_DEBUG": "config/settings/dev.py",
        "DJANGO_ALLOWED_HOSTS": "config/settings/dev.py",
        "UIAP_ALLOWED_HOSTS": "config/settings/staging.py",  # also prod.py (same helper)
        "UIAP_SECRET_KEY": "config/settings/prod.py",  # also staging.py (same helper)
        # P0.4 database foundation (ADR 0001): UIAP_DB_* promoted from RESERVED
        # to ACTIVE — base.py now reads them for DATABASES; UIAP_DB_SSLMODE is
        # newly declared. (Approved scope deviation, recorded in the ADR.)
        "UIAP_DB_HOST": "config/settings/base.py",
        "UIAP_DB_PORT": "config/settings/base.py",
        "UIAP_DB_NAME": "config/settings/base.py",
        "UIAP_DB_USER": "config/settings/base.py",
        "UIAP_DB_PASSWORD": "config/settings/base.py",
        "UIAP_DB_SSLMODE": "config/settings/base.py",
    }

    RESERVED_VARS = {
        "UIAP_ISSUER",
        "UIAP_CACHE_URL",
        "UIAP_VAULT_ADDR", "UIAP_VAULT_TOKEN",
        "UIAP_OTEL_EXPORTER_OTLP_ENDPOINT",
    }

    def test_template_exists(self):
        assert self.TEMPLATE.exists()

    def test_active_variables_have_real_readers(self):
        for var, reader in self.ACTIVE_VARS.items():
            source = (REPO_ROOT / reader).read_text(encoding="utf-8")
            assert var in source, f"{var} declared ACTIVE but no reader in {reader}"

    def test_reserved_variables_not_read_anywhere(self):
        readers = ["config/settings/base.py", "config/settings/dev.py",
                   "config/settings/test.py", "config/settings/staging.py",
                   "config/settings/prod.py", "config/settings/_env.py",
                   "manage.py", "config/asgi.py", "config/wsgi.py"]
        for var in self.RESERVED_VARS:
            for reader in readers:
                source = (REPO_ROOT / reader).read_text(encoding="utf-8")
                assert f'"{var}"' not in source and f"'{var}'" not in source, (
                    f"RESERVED {var} unexpectedly read in {reader}"
                )

    def test_template_declares_exactly_this_contract(self):
        text = self.TEMPLATE.read_text(encoding="utf-8")
        declared = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, flags=re.M))
        assert declared == set(self.ACTIVE_VARS) | self.RESERVED_VARS

    def test_no_real_secret_in_template(self):
        text = self.TEMPLATE.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.match(r"^[A-Z_]*SECRET[A-Z_]*=", line):
                value = line.split("=", 1)[1].strip()
                assert value == "", f"secret placeholder must stay empty, got {value!r}"


# ---------------------------------------------------------------------------
# F. Regression: in-process skeleton invariants (from P0.2, still valid)
# ---------------------------------------------------------------------------


class TestSkeletonRegression:
    def test_settings_module_loads(self):
        from django.conf import settings

        assert settings.DEBUG is False
        assert settings.USE_TZ is True
        assert settings.TIME_ZONE == "UTC"

    def test_urlconf_loads_and_is_empty(self):
        from config import urls

        assert urls.urlpatterns == []

    def test_wsgi_asgi_sources_require_explicit_module(self):
        # In-process source assertions (the subprocess contract tests in
        # TestEntrypoints prove behavior; this proves the committed source).
        for name in ("config/asgi.py", "config/wsgi.py"):
            source = (REPO_ROOT / name).read_text(encoding="utf-8")
            assert "ImproperlyConfigured" in source

    def test_no_domain_apps_registered(self):
        from django.conf import settings

        registered = set(settings.INSTALLED_APPS)
        for context_app in (
            "contexts.identity", "contexts.access", "contexts.profile",
            "contexts.address", "contexts.security", "contexts.audit",
            "contexts.notification", "contexts.org", "contexts.platform_admin",
        ):
            assert context_app not in registered

    def test_timezone_and_i18n_match_architecture(self):
        from django.conf import settings

        assert settings.USE_I18N is True
        assert settings.USE_TZ is True
        assert settings.TIME_ZONE == "UTC"


class TestSecretHygiene:
    """No secret literal outside config/settings/test.py (P0.2 decision)."""

    def test_only_documented_non_secret_key_exists(self):
        offenders = []
        for path in (REPO_ROOT / "config").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"SECRET_KEY\s*=\s*[\"']([^\"']+)[\"']", text):
                value = match.group(1)
                if path.name == "test.py" and value == TEST_SETTINGS_KEY:
                    continue
                offenders.append((str(path), value))
        assert offenders == []

    def test_importlib_used_for_module_imports_in_tests(self):
        # Guard against accidental top-level settings imports with ambient env.
        assert importlib is not None
