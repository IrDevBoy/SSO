"""P0.4 unit tests — database settings contract (no real DB required).

These tests exercise ``config.settings.base`` in subprocesses so each run
starts with a controlled environment (the P0.3 pattern). They prove:

  - the engine is django.db.backends.postgresql (psycopg 3) and there is NO
    SQLite anywhere (§51.1),
  - the UIAP_DB_* environment contract (names + sslmode) is honored,
  - staging/prod are fail-closed on missing/empty required DB configuration
    (§41.4 posture applied to the DB endpoint),
  - dev/test tolerate unset DB variables (checks/unit tier boots without a
    server) without ever selecting another backend,
  - no credentials are hardcoded anywhere in the settings tree,
  - no domain/database configuration exists beyond the single default alias.

Settings contracts run in subprocesses so every settings module is imported
exactly once under fully controlled environment variables.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Non-secret dummy used only where a *value* must exist to reach a code path;
# never a real credential.
DUMMY_SECRET = "ci-verification-dummy-not-a-real-secret"
DUMMY_PASSWORD = "ci-verification-dummy-password"


def run_py(code: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run python in a controlled environment (repo root on sys.path)."""
    full_env = dict(os.environ)
    full_env.pop("DJANGO_SETTINGS_MODULE", None)  # isolate from pytest env
    for name in (
        "UIAP_DB_HOST", "UIAP_DB_PORT", "UIAP_DB_NAME", "UIAP_DB_USER",
        "UIAP_DB_PASSWORD", "UIAP_DB_SSLMODE",
    ):
        full_env.pop(name, None)
    full_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def dump_databases(module: str, extra_env: dict[str, str]) -> subprocess.CompletedProcess:
    """Import a settings module and print its DATABASES configuration as JSON."""
    return run_py(
        "import importlib, json, os\n"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE', '')  # neutral, unused\n"
        f"os.environ['DJANGO_SETTINGS_MODULE']='{module}'\n"
        f"s = importlib.import_module('{module}')\n"
        "d = dict(s.DATABASES['default'])\n"
        "d.pop('PASSWORD', None)\n"  # never print credential material
        "print(json.dumps(d, default=repr))\n",
        extra_env,
    )


class TestDatabaseBackendContract:
    """Engine contract: PostgreSQL via psycopg, SQLite forbidden (§51.1)."""

    def test_backend_is_postgresql(self):
        r = dump_databases("config.settings.test", {"UIAP_DB_PASSWORD": DUMMY_PASSWORD})
        assert r.returncode == 0, r.stderr
        assert '"ENGINE": "django.db.backends.postgresql"' in r.stdout

    def test_no_sqlite_engine_anywhere_in_settings(self):
        # Grep-level guard: no SQLite engine string and no sqlite3 usage may
        # appear anywhere in the settings tree (prose mentions of the ban are
        # fine; engine configuration is not).
        for path in (REPO_ROOT / "config").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "django.db.backends.sqlite" not in text, f"SQLite engine in {path}"
            assert "import sqlite3" not in text, f"sqlite3 usage in {path}"
            assert "sqlite3.connect" not in text, f"sqlite3 usage in {path}"

    def test_dev_test_boot_without_any_db_env(self):
        # dev/test keep booting with zero DB variables set (no server needed
        # for checks / unit tier); backend is still PostgreSQL.
        for module in ("config.settings.dev", "config.settings.test"):
            r = dump_databases(module, {})
            assert r.returncode == 0, r.stderr
            assert '"ENGINE": "django.db.backends.postgresql"' in r.stdout

    def test_database_settings_importable_for_all_modules(self):
        r = run_py(
            "import importlib\n"
            "for m in ('config.settings.base', 'config.settings.dev',\n"
            "          'config.settings.test'):\n"
            "    importlib.import_module(m)\n"
            "print('ok')\n",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD},
        )
        assert r.returncode == 0, r.stderr
        assert "ok" in r.stdout


class TestEnvContractReaders:
    """The UIAP_DB_* variables flow from environment into DATABASES."""

    def test_db_parameters_are_read_from_environment(self):
        env = {
            "UIAP_DB_HOST": "db.example.internal",
            "UIAP_DB_PORT": "6543",
            "UIAP_DB_NAME": "uiap_shard7",
            "UIAP_DB_USER": "uiap_app",
            "UIAP_DB_PASSWORD": DUMMY_PASSWORD,
            "UIAP_DB_SSLMODE": "require",
        }
        r = dump_databases("config.settings.dev", env)
        assert r.returncode == 0, r.stderr
        assert '"NAME": "uiap_shard7"' in r.stdout
        assert '"USER": "uiap_app"' in r.stdout
        assert '"HOST": "db.example.internal"' in r.stdout
        assert '"PORT": "6543"' in r.stdout
        assert '"sslmode": "require"' in r.stdout

    def test_sslmode_contract_unset_defaults_to_prefer(self):
        r = dump_databases("config.settings.dev", {"UIAP_DB_PASSWORD": DUMMY_PASSWORD})
        assert r.returncode == 0, r.stderr
        assert '"sslmode": "prefer"' in r.stdout

    def test_sslmode_verify_full_is_honored(self):
        r = dump_databases(
            "config.settings.dev",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD, "UIAP_DB_SSLMODE": "verify-full"},
        )
        assert r.returncode == 0, r.stderr
        assert '"sslmode": "verify-full"' in r.stdout

    def test_migration_search_path_pinned_to_uiap_migration(self):
        # A-1/A-3: the connection's search_path targets the infrastructure
        # schema so django_migrations is created there.
        r = dump_databases("config.settings.test", {"UIAP_DB_PASSWORD": DUMMY_PASSWORD})
        assert r.returncode == 0, r.stderr
        assert "search_path=uiap_migration" in r.stdout


class TestFailClosedEnvironments:
    """staging/prod refuse to boot on missing/empty required DB config."""

    def _staging_env(self, **overrides) -> dict[str, str]:
        # Real staging/prod boot paths REQUIRE an explicit DJANGO_SETTINGS_MODULE
        # (P0.3 G-3); the fail-closed gate keys on that selector (and, as
        # defense in depth, on the UIAP_ENV identity).
        env = {
            "DJANGO_SETTINGS_MODULE": "config.settings.staging",
            "UIAP_SECRET_KEY": DUMMY_SECRET,
            "UIAP_DB_HOST": "db.staging.internal",
            "UIAP_DB_PORT": "5432",
            "UIAP_DB_NAME": "uiap",
            "UIAP_DB_USER": "uiap_app",
            "UIAP_DB_PASSWORD": DUMMY_PASSWORD,
        }
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return env

    def test_staging_boots_with_full_db_config(self):
        r = run_py(
            "import importlib\ns = importlib.import_module('config.settings.staging')\n"
            "print(s.DATABASES['default']['ENGINE'])\n",
            self._staging_env(),
        )
        assert r.returncode == 0, r.stderr
        assert "django.db.backends.postgresql" in r.stdout

    def test_staging_missing_password_fails(self):
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.staging')\n",
            self._staging_env(UIAP_DB_PASSWORD=None),
        )
        assert r.returncode != 0
        assert "UIAP_DB_PASSWORD" in r.stderr

    def test_staging_empty_user_fails(self):
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.staging')\n",
            self._staging_env(UIAP_DB_USER=""),
        )
        assert r.returncode != 0
        assert "UIAP_DB_USER" in r.stderr

    def test_staging_missing_host_fails(self):
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.staging')\n",
            self._staging_env(UIAP_DB_HOST=None),
        )
        assert r.returncode != 0
        assert "UIAP_DB_HOST" in r.stderr

    def test_staging_empty_name_fails(self):
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.staging')\n",
            self._staging_env(UIAP_DB_NAME=""),
        )
        assert r.returncode != 0
        assert "UIAP_DB_NAME" in r.stderr

    def test_staging_missing_port_fails(self):
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.staging')\n",
            self._staging_env(UIAP_DB_PORT=None),
        )
        assert r.returncode != 0
        assert "UIAP_DB_PORT" in r.stderr

    def test_prod_missing_password_fails(self):
        env = self._staging_env(UIAP_DB_PASSWORD=None)
        env["DJANGO_SETTINGS_MODULE"] = "config.settings.prod"
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.prod')\n",
            env,
        )
        assert r.returncode != 0
        assert "UIAP_DB_PASSWORD" in r.stderr

    def test_prod_boots_with_full_db_config(self):
        env = self._staging_env()
        env["DJANGO_SETTINGS_MODULE"] = "config.settings.prod"
        r = run_py(
            "import importlib\ns = importlib.import_module('config.settings.prod')\n"
            "print(s.DATABASES['default']['ENGINE'])\n",
            env,
        )
        assert r.returncode == 0, r.stderr
        assert "django.db.backends.postgresql" in r.stdout

    def test_uiap_env_identity_alone_triggers_fail_closed(self):
        # Defense in depth: even without the settings-module selector, the
        # UIAP_ENV=prod identity refuses to boot without DB configuration.
        env = self._staging_env(UIAP_DB_PASSWORD=None)
        env.pop("DJANGO_SETTINGS_MODULE", None)
        env["UIAP_ENV"] = "prod"
        r = run_py(
            "import importlib\nimportlib.import_module('config.settings.prod')\n",
            env,
        )
        assert r.returncode != 0
        assert "UIAP_DB_PASSWORD" in r.stderr


class TestNoHardcodedCredentials:
    """No secret/credential literals in the settings tree (§41.4)."""

    def test_no_password_literals_in_settings(self):
        offenders = []
        for path in (REPO_ROOT / "config").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"(PASSWORD\s*=\s*[\"'])[A-Za-z0-9!@#$%^&*]{8,}", text):
                offenders.append(str(path))
        assert offenders == []

    def test_env_template_has_no_real_credentials(self):
        text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.match(r"^UIAP_DB_PASSWORD=", line):
                assert line.split("=", 1)[1].strip() == ""

    def test_single_default_alias_only(self):
        r = run_py(
            "import importlib\ns = importlib.import_module('config.settings.test')\n"
            "print(sorted(s.DATABASES))\n",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD},
        )
        assert r.returncode == 0, r.stderr
        assert "['default']" in r.stdout


class TestNoDomainDatabaseConfiguration:
    """P0 carries exactly one table's worth of DB surface: the outbox."""

    def test_registered_context_apps_are_exactly_identity(self):
        # P0.6.1: the FIRST bounded context (§9.1 identity) is registered.
        # P0.7.2 (ADR-0006): audit joins as the second context — its storage
        # foundation (§28) has landed. The registered context set is exactly
        # these two — no other context may register before its foundation.
        r = run_py(
            "import importlib\ns = importlib.import_module('config.settings.test')\n"
            "print(sorted(a for a in s.INSTALLED_APPS if a.startswith('contexts')))\n",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD},
        )
        assert r.returncode == 0, r.stderr
        assert (
            "['contexts.audit.apps.AuditConfig', "
            "'contexts.identity.apps.IdentityConfig']" in r.stdout
        )

    def test_outbox_infrastructure_app_registered(self):
        r = run_py(
            "import importlib\ns = importlib.import_module('config.settings.test')\n"
            "print('core.outbox.apps.OutboxConfig' in s.INSTALLED_APPS)\n",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD},
        )
        assert r.returncode == 0, r.stderr
        assert "True" in r.stdout

    def test_model_targets_uiap_access_outbox_events(self):
        r = run_py(
            "import os\n"
            "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')\n"
            "import django\ndjango.setup()\n"
            "from django.apps import apps\n"
            "m = apps.get_model('outbox', 'OutboxEvent')\n"
            "print(m._meta.db_table)\n",
            {"UIAP_DB_PASSWORD": DUMMY_PASSWORD},
        )
        assert r.returncode == 0, r.stderr
        assert 'uiap_access"."outbox_events' in r.stdout
