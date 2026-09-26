"""P0.7.2 integration tier — audit contracts on REAL PostgreSQL 17 (§28, §51.1).

Scenarios (mandated by the phase): same-transaction cascade (INV-08/§34.5)
in all four mutation families, the three rollback directions, concurrent
chain validity, adversarial tamper detection, privilege separation, and the
migration/schema contract.
"""

from __future__ import annotations

import json
import uuid

import pytest

pytestmark = pytest.mark.integration

from tests.integration.database.test_identity_contract import run_orm_script
from tests.integration.valkey_conftest import valkey_url  # noqa: F401 (fixture import)


AUDIT_RESET_SQL = (
    "DROP TABLE IF EXISTS uiap_audit.audit_roots; "
    "DROP TABLE IF EXISTS uiap_audit.audit_events; "
    "DELETE FROM uiap_migration.django_migrations WHERE app='audit'; "
)


def reset_tables(migrated_db):
    """Reset audit + identity + outbox to freshly-migrated state."""
    migrated_db["manage"]("migrate", "outbox", "zero", "--noinput")
    migrated_db["manage"]("migrate", "identity", "zero", "--noinput")
    migrated_db["manage"]("migrate", "audit", "zero", "--noinput")
    migrated_db["manage"]("migrate", "outbox", "--noinput")
    migrated_db["manage"]("migrate", "identity", "--noinput")
    migrated_db["manage"]("migrate", "audit", "--noinput")


def orm(migrated_db, script):
    return run_orm_script(migrated_db, script).strip()


def audit_rows(migrated_db):
    script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.audit.models import AuditEvent
print(json.dumps([
    [str(r.audit_uuid), r.action, r.stream, r.seq_in_stream, r.outcome]
    for r in AuditEvent.objects.all().order_by("seq_in_stream")
]))
"""
    return json.loads(orm(migrated_db, script))


def outbox_rows(migrated_db):
    script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from core.outbox.models import OutboxEvent
print(json.dumps([[r.event_type, r.seq] for r in OutboxEvent.objects.all().order_by("id")]))
"""
    return json.loads(orm(migrated_db, script))


CREATE_IDENTITY = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.identity.services import create_identity
ident = create_identity(type="HUMAN", region_tag="ir-teh")
print(json.dumps({"pk": str(ident.pk), "status": ident.status}))
"""

TRANSITION = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.identity.services import transition_identity
from contexts.identity.models import Identity
ident = Identity.objects.first()
ident = transition_identity(ident.pk, to_status="ACTIVE")
print(json.dumps({"pk": str(ident.pk), "status": ident.status}))
"""

SET_PASSWORD = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.identity.services import set_password
from contexts.identity.models import Identity
ident = Identity.objects.first()
cred = set_password(ident.pk, raw_password="CorrectHorse9Battery")
print(json.dumps({"credential": str(cred.pk), "status": cred.status}))
"""


class TestSameTransactionCascade:
    def test_create_identity_audit_and_outbox(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        out = json.loads(orm(migrated_db, CREATE_IDENTITY))
        audits = audit_rows(migrated_db)
        assert [a[1] for a in audits] == ["identity.created"]
        assert audits[0][2] == "IDN"  # §28.5 stream mapping
        assert audits[0][4] == "SUCCESS"
        assert outbox_rows(migrated_db) == [["identity.created", 1]]

    def test_lifecycle_transition_audited(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        orm(migrated_db, CREATE_IDENTITY)
        orm(migrated_db, TRANSITION)
        actions = [a[1] for a in audit_rows(migrated_db)]
        assert actions == ["identity.created", "identity.activated"]
        assert [o[0] for o in outbox_rows(migrated_db)] == [
            "identity.created", "identity.activated",
        ]

    def test_credential_revoke_audited(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        orm(migrated_db, CREATE_IDENTITY)
        orm(migrated_db, SET_PASSWORD)
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.identity.services import transition_credential
from contexts.identity.models import Credential
cred = Credential.objects.first()
transition_credential(cred.pk, to_status="REVOKED")
print("revoked")
"""
        orm(migrated_db, script)
        actions = [a[1] for a in audit_rows(migrated_db)]
        # create + transition(PROVISIONAL→ACTIVE has no event... actually identity.created
        # + credential.added + credential.verified + password.changed + credential.revoked)
        assert actions.count("credential.revoked") == 1
        assert "password.changed" in actions

    def test_password_mutation_audited(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        orm(migrated_db, CREATE_IDENTITY)
        orm(migrated_db, SET_PASSWORD)
        actions = [a[1] for a in audit_rows(migrated_db)]
        assert "password.changed" in actions
        assert "credential.added" in actions
        assert "credential.verified" in actions
        # No secret material in any audit row (§28.6):
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.audit.models import AuditEvent
raw = json.dumps([r.context for r in AuditEvent.objects.all()])
print(json.dumps({"leak": ("phc" in raw or "$argon2id$" in raw)}))
"""
        out = json.loads(orm(migrated_db, script))
        assert out["leak"] is False


class TestRollbackDirections:
    def test_business_rollback_leaves_no_audit_no_outbox(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        # A create whose outbox emission fails must roll back identity AND audit.
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import transaction
from contexts.identity import services, events
from unittest import mock
try:
    with transaction.atomic():
        with mock.patch.object(services, "emit_outbox_event", side_effect=RuntimeError("boom")):
            services.create_identity(type="HUMAN", region_tag="ir-teh")
except RuntimeError:
    pass
print("done")
"""
        orm(migrated_db, script)
        assert audit_rows(migrated_db) == []
        assert outbox_rows(migrated_db) == []

    def test_audit_failure_rolls_back_business_and_outbox(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        # Audit append fails (taxonomy violation via mock) → everything rolls back.
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import transaction
from contexts.identity import services
from contexts.audit.services import append_audit_event
from unittest import mock
try:
    with transaction.atomic():
        with mock.patch.object(
            services, "append_audit_event",
            side_effect=services.AuditAppendError("audit unavailable"),
        ):
            services.create_identity(type="HUMAN", region_tag="ir-teh")
except services.AuditAppendError:
    pass
print("done")
"""
        orm(migrated_db, script)
        script_count = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.identity.models import Identity
print(json.dumps({"identities": Identity.objects.count()}))
"""
        out = json.loads(orm(migrated_db, script_count))
        assert out["identities"] == 0
        assert audit_rows(migrated_db) == []
        assert outbox_rows(migrated_db) == []


class TestChainIntegrity:
    def test_outbox_failure_rolls_back_audit(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        # Outbox emission fails → business mutation AND audit roll back
        # (§34.5: the whole cascade is one atomic boundary).
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import transaction
from contexts.identity import services
from unittest import mock
try:
    with transaction.atomic():
        # Make the *first* outbox emission fail (inside create_identity).
        with mock.patch.object(
            services, "emit_outbox_event", side_effect=RuntimeError("outbox down")
        ):
            services.create_identity(type="HUMAN", region_tag="ir-teh")
except RuntimeError:
    pass
print("done")
"""
        orm(migrated_db, script)
        assert audit_rows(migrated_db) == []
        assert outbox_rows(migrated_db) == []

    def test_audit_rows_cannot_be_appended_onto_after_chain_check(self, migrated_db, valkey_url):
        """§28.4 layer 3 discipline: an append-after-read violation (seq reuse)
        is refused — the unique (stream, partition, seq) check plus the
        advisory lock make duplicate seqs impossible. Prove the CHECK/unique
        backstop by bypassing the service and violating seq directly."""
        reset_tables(migrated_db)
        orm(migrated_db, CREATE_IDENTITY)
        # Force a row with a duplicate seq via raw SQL (adversarial path):
        # fresh uuid (defeating the uuid unique), duplicate seq_in_stream.
        script = """
import django, os, json, uuid
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import connection, transaction, IntegrityError
with connection.cursor() as cur:
    cur.execute(
        "SELECT actor_kind, action, subject_kind, subject_id, outcome, "
        "stream, seq_in_stream, prev_hash, row_hash "
        "FROM uiap_audit.audit_events LIMIT 1"
    )
    row = list(cur.fetchone())
dupe = False
try:
    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute(
                "INSERT INTO uiap_audit.audit_events (audit_uuid, actor_kind, "
                "action, subject_kind, subject_id, outcome, stream, "
                "seq_in_stream, prev_hash, row_hash) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [str(uuid.uuid4())] + row,
            )
except IntegrityError:
    dupe = True
print(json.dumps({"duplicate_seq_refused": dupe}))
"""
        out = json.loads(orm(migrated_db, script))
        assert out["duplicate_seq_refused"] is True
    def test_concurrent_appends_keep_chain_valid(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        script = """
import django, os, json, threading
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.audit.services import AuditAppendRequest, append_audit_event
errors = []
def worker(n):
    try:
        for i in range(5):
            append_audit_event(AuditAppendRequest(
                action="identity.created",
                subject_kind="identity",
                subject_id=f"subj-{n}-{i}",
            ))
    except Exception as exc:  # pragma: no cover
        errors.append(str(exc))
threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
for t in threads: t.start()
for t in threads: t.join()
print(json.dumps({"errors": errors}))
"""
        out = json.loads(orm(migrated_db, script))
        assert out["errors"] == []
        # Verify the chain across all appends (§28.4 verification).
        verify = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.utils import timezone
from contexts.audit.services import verify_stream_partition
from contexts.audit.models import AuditEvent
rows = AuditEvent.objects.all()
report = verify_stream_partition("IDN", timezone.now().strftime("%Y-%m"))
print(json.dumps(report))
"""
        report = json.loads(orm(migrated_db, verify))
        if not report["ok"]:
            # Debug surface: dump chain mismatch details before failing.
            detail = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from contexts.audit.models import AuditEvent
from contexts.audit.chain import compute_row_hash
from contexts.audit.services import _partition_filter
from django.utils import timezone
p = timezone.now().strftime("%Y-%m")
rows = list(AuditEvent.objects.filter(**_partition_filter("IDN", p)).order_by("seq_in_stream"))
expected_prev = "0" * 64
out = []
for r in rows:
    recomputed = compute_row_hash(r, expected_prev)
    ok = (r.prev_hash == expected_prev and r.row_hash == recomputed)
    out.append([r.seq_in_stream, r.prev_hash[:8], expected_prev[:8], r.row_hash[:8], recomputed[:8], ok])
    expected_prev = r.row_hash
print(json.dumps(out))
"""
            print("CHAIN DETAIL:", orm(migrated_db, detail))
        assert report["rows"] == 20
        assert report["ok"] is True
        assert report["first_broken_seq"] is None

    def test_adversarial_tamper_detected(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        for i in range(3):
            orm(migrated_db, CREATE_IDENTITY)
        # Adversary edits a row directly via raw SQL (superuser path, §28.4
        # threat table) — then reverts it. Verifier must detect while edited.
        tamper = """
import django, os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import connection
with connection.cursor() as cur:
    cur.execute(
        "UPDATE uiap_audit.audit_events SET action='identity.activated' "
        "WHERE seq_in_stream=2"
    )
print("tampered")
"""
        orm(migrated_db, tamper)
        verify = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.utils import timezone
from contexts.audit.services import verify_stream_partition
report = verify_stream_partition("IDN", timezone.now().strftime("%Y-%m"))
print(json.dumps(report))
"""
        report = json.loads(orm(migrated_db, verify))
        assert report["ok"] is False
        assert report["first_broken_seq"] == 2

    def test_row_deletion_detected(self, migrated_db, valkey_url):
        reset_tables(migrated_db)
        for _ in range(3):
            orm(migrated_db, CREATE_IDENTITY)
        delete = """
import django, os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import connection
with connection.cursor() as cur:
    cur.execute("DELETE FROM uiap_audit.audit_events WHERE seq_in_stream=2")
print("deleted")
"""
        orm(migrated_db, delete)
        verify = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.utils import timezone
from contexts.audit.services import verify_stream_partition
report = verify_stream_partition("IDN", timezone.now().strftime("%Y-%m"))
print(json.dumps(report))
"""
        report = json.loads(orm(migrated_db, verify))
        assert report["ok"] is False


class TestPrivilegeSeparation:
    def test_audit_read_role_has_no_write_privileges(self, migrated_db, valkey_url):
        """§28.4 layer 3 / ADR-0001 A-6: uiap_audit_read must hold zero
        operational privileges (it is a placeholder until the read phase)."""
        script = """
import json
import psycopg
privs = json.loads('''{ "__placeholder__": 0 }''')
print(json.dumps({"placeholder": True}))
"""
        # Probed via the harness superuser connection (information_schema).
        conn = migrated_db  # manage env has psycopg available in subprocess
        script2 = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import connection
with connection.cursor() as cur:
    cur.execute(
        "SELECT privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee='uiap_audit_read' AND table_schema='uiap_audit'"
    )
    privs = [r[0] for r in cur.fetchall()]
    cur.execute(
        "SELECT rolcanlogin FROM pg_roles WHERE rolname='uiap_audit_read'"
    )
    can_login = cur.fetchone()[0]
print(json.dumps({"privs": privs, "can_login": can_login}))
"""
        out = json.loads(orm(migrated_db, script2))
        # A-6: placeholder roles have zero grants and are NOLOGIN.
        assert out["privs"] == []
        assert out["can_login"] is False

    def test_migration_contract_audit_tables(self, migrated_db, valkey_url):
        script = """
import django, os, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()
from django.db import connection
with connection.cursor() as cur:
    cur.execute(
        "SELECT tablename FROM pg_tables "
        "WHERE schemaname='uiap_audit' ORDER BY tablename"
    )
    tables = [[r[0]] for r in cur.fetchall()]
    cur.execute(
        "SELECT conname FROM pg_constraint "
        "WHERE conrelid = 'uiap_audit.audit_events'::regclass "
        "AND contype='c' ORDER BY conname"
    )
    checks = [r[0] for r in cur.fetchall()]
print(json.dumps({"tables": tables, "checks": checks}))
"""
        out = json.loads(orm(migrated_db, script))
        assert [t[0] for t in out["tables"]] == ["audit_events", "audit_roots"]
        assert "audit_events_action_taxonomy_check" in out["checks"]
        assert "audit_events_stream_check" in out["checks"]
        assert "audit_events_outcome_check" in out["checks"]
