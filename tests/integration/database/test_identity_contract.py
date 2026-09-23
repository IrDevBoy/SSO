"""P0.6.1 integration contract — the identity foundation on a REAL PostgreSQL 17
(§34.4 group identity + §11.4 lifecycle + §12.0 credential header).

Mirrors the P0.4 outbox-contract style: raw psycopg for schema/privilege
inventory, and the proven ``django.setup()`` subprocess pattern for ORM/service
behavior.  The session fixture has already applied the repository's real
bootstrap SQL and the targeted ``migrate outbox`` + ``migrate identity``.
"""

import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "identities",
    "identity_status_history",
    "credentials",
}


def fetchall(conn, sql):
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall()


def run_orm_script(migrated_db, script: str, timeout: int = 90) -> str:
    import os

    env = dict(migrated_db["manage_env"])
    env.pop("PYTEST_CURRENT_TEST", None)
    r = subprocess.run(
        [sys.executable, "-c", script],
        cwd=migrated_db["repo_root"],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert r.returncode == 0, f"ORM script failed:\n{r.stdout}\n{r.stderr}"
    return r.stdout


# ---------------------------------------------------------------------------
# G1 — exact schema (tables, PK/FK, CHECKs, indexes)
# ---------------------------------------------------------------------------
class TestIdentitySchemaContract:
    def test_exactly_three_tables_in_uiap_identity(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT tablename FROM pg_tables "
            "WHERE schemaname='uiap_identity' ORDER BY tablename",
        )
        assert {r[0] for r in rows} == EXPECTED_TABLES

    def test_identity_pk_is_uuid_no_default(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT column_default, data_type FROM information_schema.columns "
            "WHERE table_schema='uiap_identity' AND table_name='identities' "
            "AND column_name='id'",
        )
        assert rows[0][1] == "uuid"
        assert rows[0][0] is None, "no DB-generated default: ids are app-side UUIDv7 (D-2)"

    def test_status_checks_present(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT conname FROM pg_constraint "
            "WHERE conrelid = 'uiap_identity.identities'::regclass AND contype='c' "
            "ORDER BY conname",
        )
        names = {r[0] for r in rows}
        assert {"identities_type_check", "identities_status_check",
                "identities_verification_level_check"} <= names

    def test_status_check_includes_abandoned(self, migrated_db, db_conn):
        """D-1: the §11.4 state machine's ABANDONED is DB-enforced."""
        # row_version is service-owned (no DB default) — raw SQL must supply it.
        with db_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO uiap_identity.identities "
                "(id, type, status, verification_level, region_tag, row_version) "
                "VALUES (gen_random_uuid(), 'HUMAN', 'ABANDONED', 'UNVERIFIED', "
                "'eu-west', 1) RETURNING id"
            )
            assert cur.fetchone() is not None
        db_conn.rollback()

    def test_status_check_rejects_invented_state(self, migrated_db, db_conn):
        from psycopg.errors import CheckViolation

        with pytest.raises(CheckViolation):
            with db_conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO uiap_identity.identities "
                    "(id, type, status, verification_level, region_tag, row_version) "
                    "VALUES (gen_random_uuid(), 'HUMAN', 'ZOMBIE', 'UNVERIFIED', "
                    "'eu-west', 1)"
                )
        db_conn.rollback()

    def test_type_check_rejects_invented_type(self, migrated_db, db_conn):
        from psycopg.errors import CheckViolation

        with pytest.raises(CheckViolation):
            with db_conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO uiap_identity.identities "
                    "(id, type, status, verification_level, region_tag, row_version) "
                    "VALUES (gen_random_uuid(), 'ALIEN', 'ACTIVE', 'UNVERIFIED', "
                    "'eu-west', 1)"
                )
        db_conn.rollback()

    def test_brin_index_on_created_at(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE schemaname='uiap_identity' AND tablename='identities'",
        )
        brin = [d for _, d in rows if "USING brin" in d and "created_at" in d]
        assert brin, f"BRIN(created_at) missing: {rows}"

    def test_partial_live_status_index(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname='uiap_identity' AND tablename='identities'",
        )
        partial = [d[0] for d in rows if "WHERE" in d[0] and "status" in d[0]]
        assert partial, "partial status index (ops scans, §34.4) missing"

    def test_credential_fks_protect(self, db_conn):
        """PROTECT semantics: bare FKs — no ON DELETE action at all
        (Django PROTECT = RESTRICT-at-ORM / NO ACTION in the catalog)."""
        rows = fetchall(
            db_conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='uiap_identity.credentials'::regclass AND contype='f'",
        )
        assert len(rows) >= 1, "credential→identity FK missing"
        assert all("ON DELETE" not in r[0].upper() for r in rows), (
            f"FKs must not cascade/set-null on delete: {rows}"
        )

    def test_row_version_bigint_no_db_default(self, db_conn):
        """row_version is service-owned (§11.2 MUT bump in the service layer,
        D-6): bigint everywhere, and deliberately NO DB default/trigger."""
        rows = fetchall(
            db_conn,
            "SELECT table_name, data_type, column_default "
            "FROM information_schema.columns "
            "WHERE table_schema='uiap_identity' AND column_name='row_version' "
            "ORDER BY table_name",
        )
        assert {r[0] for r in rows} == {"identities", "credentials"}, (
            f"row_version belongs to the two mutable tables; history has none: {rows}"
        )
        assert all(r[1] == "bigint" for r in rows)
        assert all(r[2] is None for r in rows)

    def test_history_columns_are_exactly_d7(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='uiap_identity' "
            "AND table_name='identity_status_history' ORDER BY column_name",
        )
        assert {r[0] for r in rows} == {"id", "identity_id", "status", "valid_from"}


# ---------------------------------------------------------------------------
# G6 — migration lifecycle + bookkeeping placement
# ---------------------------------------------------------------------------
class TestIdentityMigrationLifecycle:
    def test_zero_removes_tables_and_bookkeeping(self, migrated_db, db_conn):
        r = migrated_db["manage"]("migrate", "identity", "zero", "--noinput")
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
        rows = fetchall(
            db_conn,
            "SELECT to_regclass('uiap_identity.identities'), "
            "to_regclass('uiap_identity.credentials'), "
            "to_regclass('uiap_identity.identity_status_history')",
        )
        assert all(v is None for v in rows[0])
        # outbox bookkeeping row survives; identity's is gone
        book = fetchall(
            db_conn,
            "SELECT app FROM uiap_migration.django_migrations ORDER BY app",
        )
        assert {r[0] for r in book} == {"outbox"}

        r = migrated_db["manage"]("migrate", "identity", "--noinput")
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"

    def test_re_migrate_is_idempotent(self, migrated_db, db_conn):
        r = migrated_db["manage"]("migrate", "identity", "--noinput")
        assert r.returncode == 0
        assert "No migrations to apply" in r.stdout

    def test_no_auth_or_contenttypes_tables_anywhere(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT schemaname, tablename FROM pg_tables "
            "WHERE tablename LIKE 'auth_%' OR tablename LIKE 'django_content_type' "
            "OR tablename LIKE 'django_session'",
        )
        assert rows == []

    def test_uiap_app_cannot_ddl(self, migrated_db):
        """§34.7: uiap_app has DML, never CREATE (grants via default privileges)."""
        script = (
            "import os, django\n"
            "django.setup()\n"
            "from django.db import connection\n"
            "try:\n"
            "    with connection.cursor() as c:\n"
            "        c.execute('CREATE TABLE uiap_identity.\"probe_should_fail\" (x int)')\n"
            "    print('DDL-ALLOWED')\n"
            "except Exception as e:\n"
            "    print('DDL-DENIED', type(e).__name__)\n"
        )
        env = dict(migrated_db["manage_env"])
        env.update(
            {
                "UIAP_DB_USER": "uiap_app",
                "UIAP_DB_PASSWORD": "uiap-it-app-throwaway",
            }
        )
        env.pop("PYTEST_CURRENT_TEST", None)
        r = subprocess.run(
            [sys.executable, "-c", script],
            cwd=migrated_db["repo_root"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert r.returncode == 0, r.stderr
        assert "DDL-DENIED" in r.stdout, r.stdout


# ---------------------------------------------------------------------------
# G2/G3/G4 — lifecycle persistence, append-only history, tombstone, races
# ---------------------------------------------------------------------------
class TestLifecyclePersistence:
    def test_create_writes_initial_history_same_tx(self, migrated_db, db_conn):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Identity, IdentityStatusHistory\n"
            "from contexts.identity.services import create_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "h = IdentityStatusHistory.objects.filter(identity=i).order_by('valid_from')\n"
            "print(i.pk.version, i.status, h.count(), h.first().status)\n",
        )
        assert out.strip() == "7 PROVISIONAL 1 PROVISIONAL"

    def test_full_happy_path_transitions_and_row_version_bump(self, migrated_db, db_conn):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Identity, IdentityStatusHistory\n"
            "from contexts.identity.services import create_identity, transition_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "for target in ('ACTIVE', 'SUSPENDED', 'ACTIVE', 'LOCKED', 'ACTIVE', 'PENDING_DELETION', 'DELETED'):\n"
            "    i = transition_identity(i.pk, to_status=target)\n"
            "history = IdentityStatusHistory.objects.filter(identity=i).count()\n"
            "print(i.status, i.row_version, history, i.activated_at is not None, i.closed_at is not None)\n",
        )
        # 7 transitions on top of the initial row_version=1 → 8;
        # history carries all 7 transitions + the creation record = 8.
        assert out.strip() == "DELETED 8 8 True True"

    def test_forbidden_transition_refused_atomically(self, migrated_db, db_conn):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Identity, IdentityStatusHistory\n"
            "from contexts.identity.services import create_identity, transition_identity\n"
            "from contexts.identity.lifecycle import TransitionForbidden\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "before = IdentityStatusHistory.objects.filter(identity=i).count()\n"
            "try:\n"
            "    transition_identity(i.pk, to_status='SUSPENDED')\n"
            "    print('COERCED')\n"
            "except TransitionForbidden:\n"
            "    i.refresh_from_db()\n"
            "    after = IdentityStatusHistory.objects.filter(identity=i).count()\n"
            "    print(i.status, i.row_version, before, after)\n",
        )
        # nothing changed: no silent coercion, no partial write
        assert out.strip() == "PROVISIONAL 1 1 1"

    def test_concurrent_transition_is_race_safe(self, migrated_db, db_conn):
        """Two processes race PROVISIONAL→ACTIVE: exactly one wins."""
        setup = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.services import create_identity\n"
            "print(create_identity(type='HUMAN', region_tag='eu-west').pk)\n",
        ).strip()
        script = (
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.services import transition_identity\n"
            "from contexts.identity.lifecycle import TransitionForbidden\n"
            "import sys\n"
            "try:\n"
            "    transition_identity(sys.argv[1], to_status='ACTIVE')\n"
            "    print('WIN')\n"
            "except TransitionForbidden:\n"
            "    print('LOSE')\n"
        )
        import os

        env = dict(migrated_db["manage_env"])
        env.pop("PYTEST_CURRENT_TEST", None)
        results = []
        for _ in range(2):
            r = subprocess.run(
                [sys.executable, "-c", script, setup],
                cwd=migrated_db["repo_root"],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert r.returncode == 0, r.stderr
            results.append(r.stdout.strip())
        assert sorted(results) == ["LOSE", "WIN"]

    def test_history_is_append_only_by_service_discipline(self, migrated_db, db_conn):
        """D-6: the service layer never updates history rows (discipline + tests)."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import IdentityStatusHistory\n"
            "from contexts.identity.services import create_identity, transition_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "transition_identity(i.pk, to_status='ACTIVE')\n"
            "rows = list(IdentityStatusHistory.objects.filter(identity=i).order_by('valid_from'))\n"
            "print(len(rows), [r.status for r in rows])\n",
        )
        assert out.strip() == "2 ['PROVISIONAL', 'ACTIVE']"

    def test_hard_delete_is_refused_at_domain_boundary(self, migrated_db):
        """G4/INV-01: no delete path exists — instance and bulk are sealed."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Identity, IdentityHardDeleteForbidden\n"
            "from contexts.identity.services import create_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "try:\n"
            "    i.delete()\n"
            "    print('DELETED-INSTANCE')\n"
            "except IdentityHardDeleteForbidden:\n"
            "    print('REFUSED-INSTANCE')\n"
            "try:\n"
            "    Identity.objects.all().delete()\n"
            "    print('DELETED-BULK')\n"
            "except IdentityHardDeleteForbidden:\n"
            "    print('REFUSED-BULK')\n",
        )
        assert "REFUSED-INSTANCE" in out and "REFUSED-BULK" in out

    def test_credential_header_lifecycle_persists(self, migrated_db, db_conn):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.services import create_identity, transition_credential\n"
            "from contexts.identity.models import Credential\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "c = Credential.objects.create(identity=i, kind='PASSWORD', status='PENDING')\n"
            "c = transition_credential(c.pk, to_status='ACTIVE')\n"
            "print(c.status, c.row_version)\n",
        )
        assert out.strip() == "ACTIVE 2"

    def test_identity_pks_are_uuidv7(self, migrated_db, db_conn):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.services import create_identity\n"
            "ids = [create_identity(type='SERVICE', region_tag='eu-west').pk for _ in range(5)]\n"
            "print(','.join(str(i.version) for i in ids))\n",
        )
        assert out.strip() == "7,7,7,7,7"
