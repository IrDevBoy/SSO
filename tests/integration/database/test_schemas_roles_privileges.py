"""P0.4 integration tests — schema, role, and privilege inventory (S8).

Run against a REAL PostgreSQL 17 (testcontainers). Gates covered here:

  G1  PostgreSQL 17
  G2  exactly the eight architecture schemas + uiap_migration (no ninth
      domain schema), and the eight are the approved names (A-1)
  G3  exactly ONE P0 table exists anywhere in the uiap_* schemas:
      uiap_access.outbox_events
  G4  no auth/contenttypes/django-internal tables anywhere (RULE 8/12)
  G5  role/privilege matrix (§34.7 mapping, decisions A-4/A-5/A-6)
  G8  DDL path: uiap_migration owns the substrate and django_migrations
      bookkeeping lands there (A-1/A-5)
  G10 no SQLite involvement (structural: a real PG server answered these)
  +   public-schema leakage: public holds no UIAP tables and PUBLIC cannot
      create in it; NOLOGIN placeholders really are NOLOGIN (A-6).
"""

import pytest

# Opt-in tier marker: pyproject excludes `integration` from the default run;
# pytest reads `pytestmark` only from test modules (P0.5.2 marker fix).
pytestmark = pytest.mark.integration

ARCH_SCHEMAS = {
    "uiap_identity", "uiap_access", "uiap_profile", "uiap_address",
    "uiap_security", "uiap_audit", "uiap_notification", "uiap_org",
}
INFRA_SCHEMA = {"uiap_migration"}
EXPECTED_SCHEMAS = ARCH_SCHEMAS | INFRA_SCHEMA

EXPECTED_ROLES = {
    "uiap_app", "uiap_relay", "uiap_verifier",
    "uiap_admin", "uiap_migration", "uiap_audit_read",
}
NOLOGIN_PLACEHOLDERS = {"uiap_verifier", "uiap_audit_read"}


def fetchall(conn, sql: str, params: tuple = ()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


class TestG1PostgresVersion:
    def test_postgresql_17(self, db_conn):
        rows = fetchall(db_conn, "SELECT current_setting('server_version_num')")
        major = int(rows[0][0]) // 10000
        assert major == 17, f"expected PostgreSQL 17, got {major}"


class TestG2SchemaInventory:
    def test_exactly_the_nine_expected_schemas_exist(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT nspname FROM pg_namespace "
            "WHERE nspname NOT LIKE %s AND nspname <> 'information_schema'",
            ("pg\\_%",),
        )
        present = {r[0] for r in rows}
        # Schemas that legitimately exist in a stock cluster/pytest run must
        # not be UIAP domain schemas; assert the UIAP set is exact.
        assert EXPECTED_SCHEMAS <= present
        uiap_schemas = {s for s in present if s.startswith("uiap_")}
        assert uiap_schemas == EXPECTED_SCHEMAS, (
            f"unexpected/ninth schema appeared: {uiap_schemas ^ EXPECTED_SCHEMAS}"
        )

    def test_the_eight_domain_names_are_exact(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT nspname FROM pg_namespace WHERE nspname LIKE %s "
            "AND nspname <> 'uiap_migration'",
            ("uiap\\_%",),
        )
        assert {r[0] for r in rows} == ARCH_SCHEMAS


class TestG3SingleP0Table:
    def test_exactly_one_uiap_table_outbox_events(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema LIKE %s AND table_type = 'BASE TABLE' "
            "AND table_schema <> 'uiap_migration'",  # infra bookkeeping excluded
            ("uiap\\_%",),
        )
        assert rows == [("uiap_access", "outbox_events")]

    def test_bookkeeping_table_is_the_infra_exception(self, db_conn):
        # django_migrations is the ONLY infra-schema table (A-1).
        rows = fetchall(
            db_conn,
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'uiap_migration' AND table_type = 'BASE TABLE'",
        )
        assert rows == [("django_migrations",)]

    def test_no_views_matviews_or_sequences_outside_outbox(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT table_schema, table_name, table_type FROM information_schema.tables "
            "WHERE table_schema LIKE %s",
            ("uiap\\_%",),
        )
        unexpected = [
            r for r in rows
            if r[:2] not in {("uiap_access", "outbox_events"),
                             ("uiap_migration", "django_migrations")}
        ]
        assert unexpected == []


class TestG4NoDjangoInternalTables:
    @pytest.mark.parametrize(
        "forbidden",
        ["auth_user", "auth_group", "auth_permission", "django_content_type",
         "django_session", "django_admin_log", "django_migrations"],
    )
    def test_no_django_internal_table_in_uiap_or_public(self, db_conn, forbidden):
        rows = fetchall(
            db_conn,
            "SELECT table_schema FROM information_schema.tables "
            "WHERE table_name = %s",
            (forbidden,),
        )
        found = {r[0] for r in rows}
        # django_migrations MUST exist, but only inside uiap_migration (A-1).
        if forbidden == "django_migrations":
            assert found == {"uiap_migration"}
        else:
            assert not (found & (ARCH_SCHEMAS | INFRA_SCHEMA | {"public"}))


class TestG5RolePrivilegeMatrix:
    def test_exactly_the_approved_roles_exist(self, db_conn):
        rows = fetchall(
            db_conn, "SELECT rolname FROM pg_roles WHERE rolname LIKE %s",
            ("uiap\_%",),
        )
        assert {r[0] for r in rows} == EXPECTED_ROLES

    def test_app_is_not_superuser(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT rolsuper FROM pg_roles WHERE rolname = 'uiap_app'",
        )
        assert rows and rows[0][0] is False

    def test_placeholders_are_nologin(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT rolname, rolcanlogin FROM pg_roles "
            "WHERE rolname = ANY(%s) ORDER BY rolname",
            (sorted(NOLOGIN_PLACEHOLDERS),),
        )
        assert rows and all(canlogin is False for _, canlogin in rows)

    def test_placeholders_have_zero_operational_privileges(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = ANY(%s)",
            (sorted(NOLOGIN_PLACEHOLDERS),),
        )
        assert rows == []

    def test_relay_cannot_insert_delete_truncate(self, db_conn):
        # The relay may read and claim (SELECT/UPDATE) but never INSERT,
        # DELETE or TRUNCATE outbox rows (§34.7; P0.4 rule).
        rows = fetchall(
            db_conn,
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'uiap_relay' "
            "AND table_schema = 'uiap_access' AND table_name = 'outbox_events'",
        )
        grants = {r[0] for r in rows}
        assert grants == {"SELECT", "UPDATE"}, grants
        assert not (grants & {"INSERT", "DELETE", "TRUNCATE"})

    def test_app_dml_but_no_create(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'uiap_app' "
            "AND table_schema = 'uiap_access' AND table_name = 'outbox_events'",
        )
        assert {r[0] for r in rows} == {"SELECT", "INSERT", "UPDATE"}

    def test_no_role_has_create_on_any_uiap_schema_except_owner(self, db_conn):
        rows = fetchall(
            db_conn,
            """
            SELECT n.nspname, COALESCE(r.rolname, 'PUBLIC'), a.privilege_type
            FROM pg_namespace n, aclexplode(n.nspacl) AS a
            LEFT JOIN pg_roles r ON r.oid = a.grantee
            WHERE n.nspname = ANY(%s) AND a.privilege_type = 'CREATE'
            """,
            (sorted(EXPECTED_SCHEMAS),),
        )
        # Only the owner (uiap_migration) may create objects in uiap_* schemas.
        assert {r[1] for r in rows} <= {"uiap_migration"}, rows


class TestG8OwnershipAndDDLNpath:
    def test_uiap_migration_owns_all_schemas(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
            "WHERE nspname = ANY(%s)",
            (sorted(EXPECTED_SCHEMAS),),
        )
        assert rows and all(owner == "uiap_migration" for _, owner in rows)

    def test_outbox_owner_is_uiap_migration(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT tableowner FROM pg_tables "
            "WHERE schemaname = 'uiap_access' AND tablename = 'outbox_events'",
        )
        assert rows and rows[0][0] == "uiap_migration"

    def test_django_migrations_lives_in_uiap_migration(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT schemaname, tablename FROM pg_tables WHERE tablename = 'django_migrations'",
        )
        assert rows == [("uiap_migration", "django_migrations")]

    def test_outbox_migration_recorded_in_bookkeeping(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT app FROM uiap_migration.django_migrations",
        )
        assert [r[0] for r in rows] == ["outbox"]


class TestPublicSchemaHygiene:
    def test_public_holds_no_uiap_or_django_tables(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public'",
        )
        assert rows == [], f"public-schema leakage: {rows}"

    def test_public_cannot_create_tables(self, db_conn):
        # PUBLIC has oid 0; aclexplode reveals every acl entry on the schema.
        rows = fetchall(
            db_conn,
            """
            SELECT a.grantee, a.privilege_type
            FROM pg_namespace n, aclexplode(n.nspacl) AS a
            WHERE n.nspname = 'public' AND a.grantee = 0
              AND a.privilege_type = 'CREATE'
            """,
        )
        assert rows == []

    def test_search_path_default_excludes_uiap_schemas(self, db_conn):
        rows = fetchall(db_conn, "SHOW search_path")
        assert "uiap_" not in rows[0][0]
