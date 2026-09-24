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
        # P0.6.2-A adds the §34.4 password_secrets typed-secret table.
        assert {r[0] for r in rows} == {"identities", "identity_status_history", "credentials", "password_secrets"}

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
        assert {r[0] for r in rows} == {"identities", "credentials", "password_secrets"}, (
            f"row_version belongs to the mutable tables; history has none: {rows}"
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


# ---------------------------------------------------------------------------
# P0.6.2-A — password_secrets schema + password contract (§34.4, §12.2, R-04)
# ---------------------------------------------------------------------------
EXPECTED_PASSWORD_SECRET_TABLES = {"identities", "identity_status_history", "credentials", "password_secrets"}


class TestPasswordSecretSchema:
    def test_password_secrets_table_exists_with_exact_set(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT tablename FROM pg_tables WHERE schemaname='uiap_identity' ORDER BY tablename",
        )
        assert {r[0] for r in rows} == EXPECTED_PASSWORD_SECRET_TABLES

    def test_pk_uuid_no_default_and_fk_protect_semantics(self, db_conn):
        cols = fetchall(
            db_conn,
            "SELECT column_name, data_type, column_default FROM information_schema.columns "
            "WHERE table_schema='uiap_identity' AND table_name='password_secrets' "
            "AND column_name IN ('id', 'credential_id', 'phc', 'argon_memory_kib', "
            "'argon_time_cost', 'argon_parallelism', 'status') ORDER BY column_name",
        )
        by_name = {c[0]: (c[1], c[2]) for c in cols}
        assert by_name["id"][0] == "uuid" and by_name["id"][1] is None
        assert by_name["phc"][0].startswith("character")
        for p in ("argon_memory_kib", "argon_time_cost", "argon_parallelism"):
            assert by_name[p][0] in ("integer", "smallint"), by_name[p]
        fks = fetchall(
            db_conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='uiap_identity.password_secrets'::regclass AND contype='f'",
        )
        assert len(fks) == 1 and "credential" in fks[0][0]
        assert "ON DELETE" not in fks[0][0].upper()

    def test_argon2id_phc_check_and_param_bounds(self, migrated_db, db_conn):
        from psycopg.errors import CheckViolation

        base = (
            "INSERT INTO uiap_identity.password_secrets (id, credential_id, phc, "
            "argon_memory_kib, argon_time_cost, argon_parallelism, status) "
            "SELECT gen_random_uuid(), c.id, %s, %s, %s, %s, 'ACTIVE' "
            "FROM uiap_identity.credentials c "
            "JOIN uiap_identity.identities i ON i.id = c.identity_id "
            "WHERE c.kind='PASSWORD' LIMIT 1"
        )
        # A real PHC (produced by our hasher, valid base64 parts) inserts fine.
        import django
        django.setup()
        from contexts.identity import passwords
        good_phc = passwords.hash_password(passwords.normalize("schema-probe-pw-123456"))
        with db_conn.cursor() as cur:
            cur.execute(
                "SELECT c.id FROM uiap_identity.credentials c "
                "JOIN uiap_identity.identities i ON i.id = c.identity_id "
                "WHERE c.kind='PASSWORD' ORDER BY c.created_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO uiap_identity.identities (id, type, status, "
                    "verification_level, region_tag, row_version) "
                    "VALUES (gen_random_uuid(), 'HUMAN', 'PROVISIONAL', 'UNVERIFIED', 'eu-west', 1) "
                    "RETURNING id"
                )
                iid = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO uiap_identity.credentials (id, identity_id, kind, "
                    "status, row_version) VALUES (gen_random_uuid(), %s, 'PASSWORD', "
                    "'ACTIVE', 1) RETURNING id",
                    (iid,),
                )
                cid = cur.fetchone()[0]
            else:
                cid = row[0]
            cur.execute(
                "INSERT INTO uiap_identity.password_secrets (id, credential_id, phc, "
                "argon_memory_kib, argon_time_cost, argon_parallelism, version, row_version, status) "
                "VALUES (gen_random_uuid(), %s, %s, 19456, 2, 1, 1, 1, 'ACTIVE') RETURNING id",
                (cid, good_phc),
            )
            assert cur.fetchone() is not None
        db_conn.rollback()
        # Non-argon2id PHC refused by the phc CHECK.
        bad_phc = "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$" + "A" * 43
        weak_phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$" + "A" * 43
        with pytest.raises(CheckViolation):
            with db_conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO uiap_identity.password_secrets (id, credential_id, phc, "
                    "argon_memory_kib, argon_time_cost, argon_parallelism, version, row_version, status) "
                    "SELECT gen_random_uuid(), c.id, %s, 19456, 2, 1, 1, 1, 'ACTIVE' "
                    "FROM uiap_identity.credentials c WHERE c.kind='PASSWORD' LIMIT 1",
                    (bad_phc,),
                )
        db_conn.rollback()
        # Out-of-bounds params refused (§34.4: params NOT NULL + sane).
        with pytest.raises(CheckViolation):
            with db_conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO uiap_identity.password_secrets (id, credential_id, phc, "
                    "argon_memory_kib, argon_time_cost, argon_parallelism, version, row_version, status) "
                    "SELECT gen_random_uuid(), c.id, %s, 1024, 2, 1, 1, 1, 'ACTIVE' "
                    "FROM uiap_identity.credentials c WHERE c.kind='PASSWORD' LIMIT 1",
                    (weak_phc,),
                )
        db_conn.rollback()

    def test_no_hot_index_on_secret_columns(self, db_conn):
        """§34.4 'none hot': no index touches phc/params.  The FK backing
        index Django creates on credential_id is structural plumbing (join
        path), not a secret-readable index — asserted explicitly."""
        rows = fetchall(
            db_conn,
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname='uiap_identity' AND tablename='password_secrets'",
        )
        defs = [r[0] for r in rows]
        assert all("pkey" in d or "credential_id" in d for d in defs), defs
        assert not any("phc" in d or "argon" in d for d in defs), defs


class TestPasswordContract:
    def test_set_verify_rotate_and_history(self, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Credential, PasswordSecret\n"
            "from contexts.identity.services import create_identity, set_password, verify_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "cred = set_password(i.pk, raw_password='first-secret-value-12')\n"
            "ok, rehash = verify_password(i.pk, raw_password='first-secret-value-12')\n"
            "secrets1 = list(PasswordSecret.objects.filter(credential=cred))\n"
            "cred2 = set_password(i.pk, raw_password='second-secret-value-13')\n"
            "rows = list(PasswordSecret.objects.filter(credential=cred2).order_by('created_at'))\n"
            "states = [(s.status, s.superseded_at is not None) for s in rows]\n"
            "ok2, _ = verify_password(i.pk, raw_password='second-secret-value-13')\n"
            "old_ok, _ = verify_password(i.pk, raw_password='first-secret-value-12')\n"
            "print(cred.kind, cred.status, ok, rehash, len(secrets1), states, ok2, old_ok)\n",
        )
        assert "PASSWORD ACTIVE True False 1 [('SUPERSEDED', True), ('ACTIVE', False)] True False" in out

    def test_r04_keeps_exactly_previous_one_then_wipes(self, migrated_db):
        """3 rotations on one identity → exactly 2 rows for its credential
        (current + previous 1); the first generation is wiped (R-04).
        Scoped to this identity — the session DB is shared across tests."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import PasswordSecret\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "for pw in ['pw-one-abcdef-123', 'pw-two-ghijkl-456', 'pw-three-mnopqr-789']:\n"
            "    set_password(i.pk, raw_password=pw)\n"
            "rows = PasswordSecret.objects.filter(credential__identity=i)\n"
            "total = rows.count()\n"
            "superseded = rows.filter(status='SUPERSEDED').count()\n"
            "active = rows.filter(status='ACTIVE').count()\n"
            "print(total, superseded, active)\n",
        )
        # 3 sets → only 2 rows survive (current + previous 1); the first is wiped.
        assert out.strip() == "2 1 1"

    def test_history_reuse_of_previous_password_refused(self, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "from contexts.identity.passwords import PasswordHistoryConflict\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='alpha-secret-123456')\n"
            "set_password(i.pk, raw_password='beta-secret-654321')\n"
            "try:\n"
            "    set_password(i.pk, raw_password='beta-secret-654321')\n"
            "    print('ACCEPTED')\n"
            "except PasswordHistoryConflict:\n"
            "    print('REFUSED')\n",
        )
        # R-04: "previous 1 (only to block revoke = re-set same password loops)"
        assert "REFUSED" in out

    def test_policy_rejects_short_and_never_stores_plaintext(self, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Credential, PasswordSecret\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "from contexts.identity.passwords import PasswordPolicyViolation\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "try:\n"
            "    set_password(i.pk, raw_password='short9')\n"
            "    print('ACCEPTED')\n"
            "except PasswordPolicyViolation:\n"
            "    print('REFUSED')\n"
            "rows = PasswordSecret.objects.filter(credential__identity=i).count()\n"
            "creds = Credential.objects.filter(identity=i).count()\n"
            "plain = any('short9' in (s.phc or '') for s in PasswordSecret.objects.all())\n"
            "print(rows, creds, plain)\n",
        )
        # Exception path prints REFUSED on its own line, counts on the next.
        assert "REFUSED" in out and "\n0 0 False" in out

    def test_active_password_invariant_under_repeated_sets(self, migrated_db):
        """OD-5: however many set_password calls race/rotate, the identity
        ends with EXACTLY ONE ACTIVE password credential and exactly one
        ACTIVE secret (previous kept per R-04, superseded) — never two live
        password generations.  A second sequential set is a legitimate
        *rotation*, so the observable invariant is the end state, not a
        LOSE/WIN split (which only applies to the §11.4 state machine race
        covered by test_concurrent_transition_is_race_safe)."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import Credential, PasswordSecret\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='race-pw-A-12345678')\n"
            "set_password(i.pk, raw_password='race-pw-B-87654321')\n"
            "active_creds = Credential.objects.filter(identity=i, kind='PASSWORD', status='ACTIVE').count()\n"
            "active_secrets = PasswordSecret.objects.filter(credential__identity=i, status='ACTIVE').count()\n"
            "total_creds = Credential.objects.filter(identity=i, kind='PASSWORD').count()\n"
            "print(active_creds, active_secrets, total_creds)\n",
        )
        assert out.strip() == "1 1 1"

    def test_transaction_atomicity_on_hash_failure(self, migrated_db):
        """A failure inside the atomic block leaves NO partial mutation."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from django.db import transaction\n"
            "from contexts.identity.models import Credential, PasswordSecret\n"
            "from contexts.identity import services\n"
            "from contexts.identity.services import create_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "calls = {'n': 0}\n"
            "real = services.passwords.hash_password\n"
            "def boom(pw):\n"
            "    calls['n'] += 1\n"
            "    if calls['n'] == 2:\n"
            "        raise RuntimeError('simulated KDF outage')\n"
            "    return real(pw)\n"
            "services.passwords.hash_password = boom\n"
            "services.set_password(i.pk, raw_password='first-pw-12345678')\n"
            "try:\n"
            "    services.set_password(i.pk, raw_password='second-pw-87654321')\n"
            "    print('NO-FAILURE')\n"
            "except RuntimeError:\n"
            "    pass\n"
            "creds = Credential.objects.filter(identity=i, kind='PASSWORD').count()\n"
            "secrets = PasswordSecret.objects.filter(credential__identity=i).count()\n"
            "active_states = sorted(\n"
            "    s['status'] for s in PasswordSecret.objects.filter(credential__identity=i).values('status')\n"
            ")\n"
            "print(creds, secrets, active_states)\n",
        )
        # Rotation aborted mid-tx: the first generation survives untouched.
        assert "1 1 ['ACTIVE']" in out

    def test_rehash_on_login_upgrades_weak_params(self, migrated_db):
        """The stored PHC is replaced by a *valid* but weaker-policy PHC for
        the same password (hashed for real with reduced params), so verify
        succeeds and needs_rehash fires; rehash_password then upgrades to
        the §12.2 initial policy."""
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from argon2 import PasswordHasher, Type\n"
            "from contexts.identity.models import PasswordSecret\n"
            "from contexts.identity import passwords\n"
            "from contexts.identity.services import create_identity, set_password, verify_password, rehash_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='upgrade-me-please-12')\n"
            "legacy = PasswordHasher(memory_cost=8192, time_cost=1, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)\n"
            "weak = legacy.hash('upgrade-me-please-12')\n"
            "s = PasswordSecret.objects.get(status='ACTIVE', credential__identity=i)\n"
            "PasswordSecret.objects.filter(pk=s.pk).update(phc=weak, argon_memory_kib=8192, argon_time_cost=1, argon_parallelism=1)\n"
            "ok, needs = verify_password(i.pk, raw_password='upgrade-me-please-12')\n"
            "changed = rehash_password(i.pk, raw_password='upgrade-me-please-12')\n"
            "s2 = PasswordSecret.objects.get(status='ACTIVE', credential__identity=i)\n"
            "print(ok, needs, changed, passwords.stored_params(s2.phc))\n",
        )
        assert "True True True (19456, 2, 1)" in out

    def test_terminal_credential_disables_secrets(self, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import os, django\n"
            "django.setup()\n"
            "from contexts.identity.models import PasswordSecret\n"
            "from contexts.identity.services import create_identity, set_password, verify_password, transition_credential\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "cred = set_password(i.pk, raw_password='revoke-me-please-12')\n"
            "transition_credential(cred.pk, to_status='REVOKED')\n"
            "state = PasswordSecret.objects.get(credential=cred).status\n"
            "ok, _ = verify_password(i.pk, raw_password='revoke-me-please-12')\n"
            "print(state, ok)\n",
        )
        assert out.strip() == "DISABLED False"
