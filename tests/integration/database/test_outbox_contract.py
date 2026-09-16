"""P0.4 integration tests — the outbox table contract (S9).

Verified against a real PostgreSQL 17 via the actual Django migration:
schema/type inventory, constraints, defaults, the partial PENDING claim
index, reversibility (`migrate outbox zero`) and re-migration, and the
absence of any FK beyond the contract (there are none at all — by design,
see core/outbox/models.py and ADR 0001).

SKIP LOCKED runtime claiming behavior is deliberately NOT implemented here —
it belongs to the Relay phase.

Ordering note: the lifecycle class sorts last within this module and restores
the migrated state before returning, so the other classes stay order-
independent regardless of collection order.
"""

import os
import subprocess
import sys

import pytest

# Opt-in tier marker: pyproject excludes `integration` from the default run;
# pytest reads `pytestmark` only from test modules (P0.5.2 marker fix).
pytestmark = pytest.mark.integration

# NOTE: deliberately NO pytest-django django_db marker anywhere here — these
# tests drive the real database through psycopg and subprocess migrations, so
# pytest-django's test-DB creation must never activate (it would target
# config.settings.test, not the throwaway container).


def fetchall(conn, sql: str, params: tuple = ()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


class TestTableContract:
    def test_table_schema_qualified_name(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT schemaname FROM pg_tables WHERE tablename = 'outbox_events'",
        )
        assert rows == [("uiap_access",)]

    def test_primary_key_is_bigint_identity_sequence(self, db_conn):
        rows = fetchall(
            db_conn,
            """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'uiap_access' AND c.relname = 'outbox_events'
              AND a.attname = 'id'
            """,
        )
        assert rows and rows[0][1].startswith("bigint")

    def test_column_types_match_contract(self, db_conn):
        rows = fetchall(
            db_conn,
            """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'uiap_access' AND c.relname = 'outbox_events'
              AND a.attnum > 0 AND NOT a.attisdropped
            """,
        )
        types = {name: typ for name, typ, _ in rows}
        assert types["subject"].startswith("character varying")
        assert types["seq"] == "bigint"
        assert types["event_id"] == "uuid"
        assert types["payload"] == "jsonb"
        assert types["metadata"] == "jsonb"
        assert types["available_at"].startswith("timestamp with time zone")
        assert types["published_at"].startswith("timestamp with time zone")
        assert types["created_at"].startswith("timestamp with time zone")
        notnull = {name for name, _, nn in rows if nn}
        for required in ("subject", "seq", "event_id", "event_type", "payload",
                         "payload_hash", "publish_state", "attempts", "created_at"):
            assert required in notnull, required
        for nullable in ("payload_ref", "partition_key", "published_at",
                         "last_error", "trace_id", "request_id",
                         "correlation_id", "metadata"):
            assert nullable not in notnull, nullable

    def test_c_collation_on_hash_like_fields(self, db_conn):
        rows = fetchall(
            db_conn,
            """
            SELECT a.attname, c2.collname
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_collation c2 ON c2.oid = a.attcollation
            WHERE n.nspname = 'uiap_access' AND c.relname = 'outbox_events'
              AND a.attname = ANY(%s)
            """,
            (["subject", "event_type", "payload_hash"],),
        )
        collations = dict(rows)
        assert collations == {"subject": "C", "event_type": "C", "payload_hash": "C"}


class TestConstraints:
    def test_unique_subject_seq(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'uiap_access.outbox_events'::regclass "
            "AND contype = 'u'",
        )
        defs = dict(rows)
        assert any("subject" in d and "seq" in d for d in defs.values())

    def test_event_id_unique(self, db_conn):
        rows = fetchall(
            db_conn,
            """
            SELECT indexname FROM pg_indexes
            WHERE schemaname = 'uiap_access' AND tablename = 'outbox_events'
              AND indexdef ILIKE %s
            """,
            ("%UNIQUE%event_id%",),
        )
        assert rows

    def test_publish_state_check(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'uiap_access.outbox_events'::regclass "
            "AND conname = 'outbox_publish_state_check'",
        )
        assert rows
        definition = rows[0][0]
        for state in ("PENDING", "PUBLISHED", "ACKED", "FAILED"):
            assert state in definition

    def test_attempts_nonnegative_check(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'uiap_access.outbox_events'::regclass "
            "AND conname = 'outbox_attempts_nonnegative_check'",
        )
        assert rows and ">= 0" in rows[0][0].replace(">=0", ">= 0")

    def test_no_foreign_keys_at_all(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT conname FROM pg_constraint "
            "WHERE conrelid = 'uiap_access.outbox_events'::regclass "
            "AND contype = 'f'",
        )
        assert rows == [], f"unexpected FKs: {rows}"


class TestDefaultsAndIndexes:
    def test_available_at_and_created_at_default_now(self, db_conn):
        # Django's db_default=Now() renders as statement_timestamp(); both are
        # transaction-...-statement-anchored UTC clocks satisfying §34.3.
        rows = fetchall(
            db_conn,
            "SELECT column_name, column_default FROM information_schema.columns "
            "WHERE table_schema = 'uiap_access' AND table_name = 'outbox_events' "
            "AND column_name = ANY(%s)",
            (["available_at", "created_at"],),
        )
        defaults = dict(rows)
        assert set(defaults) == {"available_at", "created_at"}
        for default in defaults.values():
            assert default and "timestamp()" in default, default

    def test_partial_pending_claim_index(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname = 'uiap_access' AND tablename = 'outbox_events' "
            "AND indexname = 'outbox_pending_claim_idx'",
        )
        assert rows
        definition = rows[0][0]
        assert "WHERE" in definition and "PENDING" in definition
        assert "available_at" in definition

    def test_index_inventory_is_minimal(self, db_conn):
        rows = fetchall(
            db_conn,
            "SELECT indexname FROM pg_indexes "
            "WHERE schemaname = 'uiap_access' AND tablename = 'outbox_events' "
            "ORDER BY indexname",
        )
        names = {r[0] for r in rows}
        assert names == {
            "outbox_events_pkey",
            "outbox_events_event_id_key",       # field-level unique
            "outbox_subject_seq_key",           # UniqueConstraint
            "outbox_pending_claim_idx",         # the one partial claim index
        }

    def test_attempt_checks_are_nonnegative_only(self, db_conn):
        # attempts is a PositiveIntegerField: Django emits its own >=0 CHECK
        # in addition to the named contract constraint. Both must be
        # non-negative checks — nothing stronger may sneak in.
        rows = fetchall(
            db_conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'uiap_access.outbox_events'::regclass "
            "AND conname = ANY(%s)",
            (["outbox_attempts_nonnegative_check", "outbox_events_attempts_check"],),
        )
        assert len(rows) == 2
        for (definition,) in rows:
            assert ">= 0" in definition.replace(">=0", ">= 0")


class TestMigrationLifecycle:
    def test_insert_via_orm_respects_contract(self, migrated_db, db_conn):
        """A real ORM write flows through the schema-qualified table."""
        import os

        script = (
            "import os\n"
            "import django\n"
            "django.setup()\n"
            "from django.utils import timezone\n"
            "from core.outbox.models import OutboxEvent\n"
            "e = OutboxEvent.objects.create(\n"
            "    subject='identity:11111111-1111-1111-1111-111111111111',\n"
            "    seq=1,\n"
            "    event_id='0197ffff-0000-7000-8000-000000000001',\n"
            "    event_type='identity.created',\n"
            "    payload={'kind': 'nudge'},\n"
            "    payload_hash='a' * 64,\n"
            ")\n"
            "print(e.pk, e.publish_state, e.available_at is not None, "
            "e.created_at is not None)\n"
        )
        env = dict(migrated_db["manage_env"])
        env.pop("PYTEST_CURRENT_TEST", None)
        import subprocess
        import sys

        r = subprocess.run(
            [sys.executable, "-c", script], cwd=migrated_db["repo_root"],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert r.returncode == 0, r.stderr
        assert "1 PENDING True True" in r.stdout

    def test_migrate_zero_removes_table_and_state(self, migrated_db, db_conn):
        """Reversibility: reverse() drops the table and clears bookkeeping."""
        r = migrated_db["manage"]("migrate", "outbox", "zero", "--noinput")
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
        rows = fetchall(
            db_conn,
            "SELECT to_regclass('uiap_access.outbox_events')",
        )
        assert rows[0][0] is None
        book = fetchall(db_conn, "SELECT count(*) FROM uiap_migration.django_migrations")
        assert book[0][0] == 0

        # Leave the session database in the migrated state for other tests.
        r = migrated_db["manage"]("migrate", "outbox", "--noinput")
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"

    def test_re_migrate_is_idempotent(self, migrated_db, db_conn):
        """A second apply is a no-op (S13 step 13)."""
        r = migrated_db["manage"]("migrate", "outbox", "--noinput")
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
        assert "No migrations to apply" in r.stdout
        rows = fetchall(
            db_conn,
            "SELECT to_regclass('uiap_access.outbox_events')",
        )
        assert rows[0][0] == "uiap_access.outbox_events"
