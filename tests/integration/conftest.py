"""P0.4 integration fixtures — a real PostgreSQL 17 via testcontainers.

Per §51.1 the integration tier runs against a REAL PostgreSQL (never SQLite,
never a developer database, never production). The fixture:

  1. boots a throwaway PostgreSQL 17 container (Docker required; if Docker is
     unavailable the whole tier SKIPS transparently — a local-environment
     limitation, never a fake failure),
  2. executes the repository's real CI-owned bootstrap SQL
     (deploy/db/bootstrap/001_schemas_roles.sql) exactly as CI would,
  3. points DJANGO_SETTINGS_MODULE at config.settings.dev with UIAP_DB_* set
     to the container, then runs ONLY the targeted ``migrate outbox``
     (RULE 9: generic `migrate` is forbidden — it would touch auth/
     contenttypes, which must never materialize),
  4. hands tests a psycopg connection (as the uiap_migration principal) for
     inventory/privilege assertions.

The settings modules are imported fresh inside the session fixture (the
pytest process itself never configures Django for the unit tier — keep these
integration modules importable without Django side effects at collection).
"""

import subprocess
import sys
from pathlib import Path

import pytest

# The whole tier is opt-in via the `integration` marker (pyproject: excluded
# from the default run). pytest reads `pytestmark` only from TEST modules —
# it cannot be applied transitively from conftest.py — so each test module
# under tests/integration declares the marker itself (P0.5.2 marker fix).
# The previous `pytestmark = pytest.mark.integration` here was inert: conftest
# is not a test module, so it never marked anything (behavior unchanged).

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SQL = REPO_ROOT / "deploy" / "db" / "bootstrap" / "001_schemas_roles.sql"

PG_IMAGE = "postgres:17"
PG_USER = "postgres"
PG_PASSWORD = "uiap-it-bootstrap"  # throwaway container-only credential
PG_DB = "uiap_it"


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


@pytest.fixture(scope="session")
def postgres_container():
    """A real PostgreSQL 17; skip the tier transparently without Docker."""
    if not _docker_available():
        pytest.skip(
            "Docker is not available in this environment — integration tier "
            "skipped (local-environment limitation, not a test failure)."
        )
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer(image=PG_IMAGE, username=PG_USER, password=PG_PASSWORD, dbname=PG_DB) as pg:
        yield {
            "host": pg.get_container_host_ip(),
            "port": pg.get_exposed_port(5432),
            "user": PG_USER,
            "password": PG_PASSWORD,
            "dbname": PG_DB,
        }


def _psycopg_connect(env: dict[str, str], dbname: str, user: str, password: str):
    """Raw psycopg connection for bootstrap execution / inventory probes."""
    import psycopg

    return psycopg.connect(
        host=env["host"],
        port=env["port"],
        dbname=dbname,
        user=user,
        password=password,
        autocommit=True,
    )


@pytest.fixture(scope="session")
def bootstrapped_db(postgres_container):
    """Container + the repository's real bootstrap SQL applied exactly once.

    Mirrors CI: the bootstrap principal (throwaway superuser) applies the
    repository's SQL, then provisions the uiap_migration role's credential
    OUTSIDE version control (the bootstrap file itself carries no secrets),
    so the migration subprocess can run as the actual CI DDL role (A-5).
    """
    env = postgres_container
    with _psycopg_connect(env, env["dbname"], env["user"], env["password"]) as conn:
        sql = BOOTSTRAP_SQL.read_text(encoding="utf-8")
        with conn.cursor() as cur:
            cur.execute(sql)
            # CI-injected credential for the DDL role (throwaway container;
            # never committed, never reused outside this harness).
            cur.execute(
                "ALTER ROLE uiap_migration WITH LOGIN "
                "PASSWORD 'uiap-it-migrate-throwaway'"
            )
        yield env


@pytest.fixture(scope="session")
def migrated_db(bootstrapped_db):
    """Bootstrap + the targeted `migrate outbox` run (RULE 9)."""
    import os

    env = bootstrapped_db
    run_env = dict(os.environ)
    run_env.update(
        {
            "DJANGO_SETTINGS_MODULE": "config.settings.dev",
            "UIAP_DB_HOST": env["host"],
            "UIAP_DB_PORT": str(env["port"]),
            "UIAP_DB_NAME": env["dbname"],
            # Migrations run AS the uiap_migration role (A-5: it owns the
            # uiap_* objects; §34.7: DDL via CI only). The credential was
            # provisioned by the bootstrap fixture above.
            "UIAP_DB_USER": "uiap_migration",
            "UIAP_DB_PASSWORD": "uiap-it-migrate-throwaway",
            "UIAP_DB_SSLMODE": "disable",
            "UIAP_ENV": "dev",
        }
    )
    run_env.pop("PYTEST_CURRENT_TEST", None)

    def _manage(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "manage.py"), *args],
            cwd=REPO_ROOT,
            env=run_env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    r = _manage("migrate", "outbox", "--noinput")
    assert r.returncode == 0, f"migrate outbox failed:\n{r.stdout}\n{r.stderr}"
    yield {**env, "manage": _manage, "manage_env": run_env, "repo_root": REPO_ROOT}


@pytest.fixture()
def db_conn(migrated_db):
    """Per-test psycopg connection to the migrated database (fresh schema query surface)."""
    env = migrated_db
    conn = _psycopg_connect(env, env["dbname"], env["user"], env["password"])
    try:
        yield conn
    finally:
        conn.close()
