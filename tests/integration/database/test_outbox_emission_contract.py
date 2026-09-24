"""P0.6.2-B integration contract — §29.3/§29.4/§29.5 event plane on a REAL
PostgreSQL 17 (ADR-0004, BD-1..9).

Same harness as the identity contract file: raw psycopg against the session
database for outbox-row inventory plus the proven ``django.setup()``
subprocess pattern (session-fixture DB) for ORM/service behavior.  Outbox
rows are scoped per test identity via subject so the shared session DB can
never make assertions ambiguous (mission concurrency-detail rule).
"""

from __future__ import annotations

import json
import re

import pytest
from django.db import connection

from tests.integration.database.test_identity_contract import run_orm_script

pytestmark = pytest.mark.integration


def fetchall(conn, sql: str, params: tuple = ()) -> list[tuple]:
    """Raw cursor fetch (same pattern as test_outbox_contract.fetchall)."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


SHA64 = re.compile(r"^[0-9a-f]{64}$")


def outbox_rows(db_conn, identity_uuid: str) -> list[tuple]:
    return fetchall(
        db_conn,
        "SELECT event_type, seq, subject, payload, payload_hash, "
        "publish_state, dataversion, partition_key, trace_id, request_id, "
        "correlation_id, metadata "
        "FROM uiap_access.outbox_events WHERE subject = %s ORDER BY seq",
        (f"identity:{identity_uuid}",),
    )


def seqs(rows):
    return [r[1] for r in rows]


def types(rows):
    return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# create_identity / lifecycle
# ---------------------------------------------------------------------------


class TestIdentityLifecycleEmission:
    def test_create_emits_identity_created_seq1_pending(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert len(rows) == 1
        t, s, subj, payload, h, state, dv, pk_, tp, rq, co, md = rows[0]
        assert t == "identity.created"
        assert s == 1
        assert subj == f"identity:{out.strip()}"
        assert set(payload) == {"identity_id", "ts"}
        assert payload["identity_id"] == out.strip()
        assert SHA64.match(h)
        assert state == "PENDING" and dv == 1
        assert pk_ == subj                              # BD-2 partition key
        assert (tp, rq, co) == (None, None, None)       # BD-6 defaults
        assert md == {"region": "eu-west"}

    @pytest.mark.parametrize(
        "path,expected",
        [
            (["ACTIVE", "SUSPENDED"], ["identity.activated", "identity.suspended"]),
            (["ACTIVE", "LOCKED"], ["identity.activated", "identity.locked"]),
            (["ACTIVE", "LOCKED", "ACTIVE"], ["identity.activated", "identity.locked", "identity.unlocked"]),
            (["ACTIVE", "SUSPENDED", "ACTIVE"], ["identity.activated", "identity.suspended", "identity.reinstated"]),
            (
                ["ACTIVE", "PENDING_DELETION"],
                ["identity.activated", "identity.deletion_requested"],
            ),
            (["ACTIVE", "SUSPENDED", "PENDING_DELETION", "DELETED"],
             ["identity.activated", "identity.suspended", "identity.deletion_requested", "identity.deleted"]),
        ],
    )
    def test_each_supported_edge_emits_its_catalog_event(
        self, db_conn, migrated_db, path, expected
    ):
        script = "import django; django.setup()\n"
        script += "from contexts.identity.services import create_identity, transition_identity\n"
        script += "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
        for to in path:
            script += f"transition_identity(i.pk, to_status='{to}')\n"
        script += "print(i.pk)\n"
        out = run_orm_script(migrated_db, script)
        rows = outbox_rows(db_conn, out.strip())
        assert types(rows) == ["identity.created", *expected]
        assert seqs(rows) == list(range(1, len(expected) + 2))  # contiguous

    def test_invalid_transition_emits_nothing(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, transition_identity\n"
            "from contexts.identity.lifecycle import TransitionForbidden\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "try:\n"
            "    transition_identity(i.pk, to_status='DELETED')\n"  # PROVISIONAL→DELETED: forbidden
            "except TransitionForbidden:\n"
            "    pass\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert types(rows) == ["identity.created"]      # only the birth event

    def test_merge_and_abandon_edges_emit_nothing(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, transition_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "transition_identity(i.pk, to_status='ABANDONED')\n"  # PROVISIONAL→ABANDONED: no catalog event
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert types(rows) == ["identity.created"]


# ---------------------------------------------------------------------------
# credential / password
# ---------------------------------------------------------------------------


class TestCredentialPasswordEmission:
    def test_first_set_full_event_set(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "c = set_password(i.pk, raw_password='password-initial-one')\n"
            "print(i.pk, c.pk)\n",
        )
        identity_pk, credential_pk = out.split()
        rows = outbox_rows(db_conn, identity_pk)
        # BD-5 semantics (P0.6.2-A reality): verified_at is only set by the
        # reused-credential branch, so a *first* set emits added+changed;
        # a rotation after PENDING→ACTIVE emits added/changed/verified.
        assert types(rows) == [
            "identity.created", "credential.added", "password.changed",
        ]
        assert seqs(rows) == [1, 2, 3]
        added = rows[1][3]
        assert set(added) == {"identity_id", "credential_id", "kind", "ts"}
        assert added["credential_id"] == credential_pk and added["kind"] == "PASSWORD"

    def test_rotation_set_password_changed_only(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='password-initial-one')\n"
            "c = set_password(i.pk, raw_password='password-second-two')\n"
            "print(i.pk, c.pk)\n",
        )
        identity_pk, _ = out.split()
        rows = outbox_rows(db_conn, identity_pk)
        assert types(rows) == [
            "identity.created", "credential.added", "password.changed",
            "credential.verified", "password.changed",
        ]  # first set: added+changed; rotation: verified-then-changed (mutation chronology)
        assert seqs(rows) == [1, 2, 3, 4, 5]

    def test_revoked_credential_emits_credential_revoked(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import transition_credential\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "c = set_password(i.pk, raw_password='password-initial-one')\n"
            "transition_credential(c.pk, to_status='REVOKED')\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert types(rows)[-1] == "credential.revoked"
        assert set(rows[-1][3]) == {"identity_id", "credential_id", "kind", "ts"}

    def test_rehash_emits_nothing(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, set_password, rehash_password\n"
            "from contexts.identity import passwords, services\n"
            "from contexts.identity.models import PasswordSecret\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='password-initial-one')\n"
            "# Rebuild the ACTIVE PHC under the pre-P0.6.2 policy (m=8MiB, t=1)\n"
            "# so check_needs_rehash reports an upgrade (§12.2 rehash-on-login).\n"
            "legacy_phc = passwords._hasher.__class__(memory_cost=8192, time_cost=1, parallelism=1, hash_len=32, salt_len=16).hash('password-initial-one')\n"
            "ps = PasswordSecret.objects.filter(credential__identity_id=i.pk, status='ACTIVE').first()\n"
            "ps.phc = legacy_phc\n"
            "ps.save(update_fields=['phc'])\n"
            "assert services.rehash_password(i.pk, raw_password='password-initial-one') is True\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert "password.rehashed" not in types(rows)
        assert types(rows).count("password.changed") == 1  # rehash adds nothing


# ---------------------------------------------------------------------------
# payload contract / hash
# ---------------------------------------------------------------------------


class TestPayloadContract:
    def test_no_pii_or_secret_material_in_any_payload(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import transition_credential\n"
            "from contexts.identity.services import create_identity, set_password, transition_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "transition_identity(i.pk, to_status='ACTIVE')\n"
            "c = set_password(i.pk, raw_password='password-initial-one')\n"
            "transition_identity(i.pk, to_status='LOCKED')\n"
            "transition_credential(c.pk, to_status='REVOKED')\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        allowed = {
            "identity.created": {"identity_id", "ts"},
            "identity.activated": {"identity_id", "from_status", "to_status", "ts"},
            "identity.locked": {"identity_id", "from_status", "to_status", "ts"},
            "identity.unlocked": {"identity_id", "from_status", "to_status", "ts"},
            "identity.suspended": {"identity_id", "from_status", "to_status", "ts"},
            "identity.reinstated": {"identity_id", "from_status", "to_status", "ts"},
            "identity.deletion_requested": {"identity_id", "from_status", "to_status", "ts"},
            "identity.deleted": {"identity_id", "from_status", "to_status", "ts"},
            "credential.added": {"identity_id", "credential_id", "kind", "ts"},
            "credential.verified": {"identity_id", "credential_id", "kind", "ts"},
            "credential.revoked": {"identity_id", "credential_id", "kind", "ts"},
            "password.changed": {"identity_id", "credential_id", "ts"},
        }
        for t, _, _, payload, *_ in rows:
            assert set(payload) == allowed[t], f"unexpected payload key-set for {t}"
            blob = json.dumps(payload).lower()
            # Scan payload *values* (not key names): "kind":"password" is the
            # source-backed credential-kind field, not secret material.
            values = " ".join(str(v) for v in payload.values()).lower()
            for forbidden in ("$argon2", "phc", "argon2id", "bearer ", "email@", "+1555", "secret", "breach"):
                assert forbidden not in values, f"{forbidden} leaked into {t} payload"

    def test_payload_hash_recomputable(self, db_conn, migrated_db):
        import hashlib

        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='password-initial-one')\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        for t, _, _, payload, h, *_ in rows:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            assert h == hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# mixed ordering / concurrency / rollback / backstop
# ---------------------------------------------------------------------------


class TestOrderingConcurrencyRollback:
    def test_mixed_ops_strictly_increasing_contiguous(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import transition_credential\n"
            "from contexts.identity.services import create_identity, set_password, transition_identity\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "transition_identity(i.pk, to_status='ACTIVE')\n"
            "c = set_password(i.pk, raw_password='password-initial-one')\n"
            "transition_identity(i.pk, to_status='LOCKED')\n"
            "set_password(i.pk, raw_password='password-second-two')\n"
            "transition_identity(i.pk, to_status='ACTIVE')\n"
            "transition_credential(c.pk, to_status='REVOKED')\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert seqs(rows) == list(range(1, len(rows) + 1))

    def test_concurrent_rotations_no_integrity_error_seq_exact(self, db_conn, migrated_db):
        """8 threads × 1 rotation on one identity — allocation is serialized by
        the identity-row lock; assert DB-observed seq values, not thread order."""
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from concurrent.futures import ThreadPoolExecutor\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='password-initial-one')\n"
            "def rotate(n):\n"
            "    set_password(i.pk, raw_password=f'password-rot-{n:02d}-a')\n"
            "    return n\n"
            "with ThreadPoolExecutor(max_workers=8) as ex:\n"
            "    list(ex.map(rotate, range(8)))\n"
            "from contexts.identity.models import Credential\n"
            "assert Credential.objects.filter(identity=i, kind='PASSWORD', status='ACTIVE').count() == 1\n"
            "print(i.pk)\n",
        )
        identity_pk = out.strip()
        rows = outbox_rows(db_conn, identity_pk)
        changed = [r for r in rows if r[0] == "password.changed"]
        # initial set (seq 4) + 8 rotations, all distinct and contiguous
        assert len(changed) == 9
        assert seqs(rows) == sorted(seqs(rows))
        assert len(set(seqs(rows))) == len(seqs(rows))
        assert seqs(rows) == list(range(1, len(rows) + 1))

    def test_rollback_leaves_no_material_gap(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from django.db import transaction\n"
            "from contexts.identity.services import create_identity, set_password, transition_identity\n"
            "from contexts.identity.lifecycle import TransitionForbidden\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "transition_identity(i.pk, to_status='ACTIVE')\n"
            "c = set_password(i.pk, raw_password='password-initial-one')\n"
            "try:\n"
            "    with transaction.atomic():\n"
            "        transition_identity(i.pk, to_status='SUSPENDED')\n"   # seq 5 allocated
            "        raise RuntimeError('simulated abort')\n"
            "except RuntimeError:\n"
            "    pass\n"
            "transition_identity(i.pk, to_status='SUSPENDED')\n"          # must reuse seq 5
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert types(rows)[-1] == "identity.suspended"
        assert seqs(rows) == list(range(1, len(rows) + 1))  # contiguous, no gap

    def test_unique_backstop_rejects_duplicate_seq(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from django.db import IntegrityError, transaction\n"
            "from contexts.identity.services import create_identity, set_password\n"
            "from core.outbox.models import OutboxEvent\n"
            "from core.outbox.emitter import payload_hash\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "set_password(i.pk, raw_password='password-initial-one')\n"
            "try:\n"
            "    with transaction.atomic():\n"
            "        OutboxEvent.objects.create(\n"
            "            subject=f'identity:{i.pk}', seq=1, event_id=__import__('uuid').uuid4(),\n"
            "            event_type='identity.created', payload={'x': 1},\n"
            "            payload_hash=payload_hash({'x': 1}),\n"
            "        )\n"
            "except IntegrityError:\n"
            "    print('BACKSTOP-OK')\n"
            "print(i.pk)\n",
        )
        assert "BACKSTOP-OK" in out


# ---------------------------------------------------------------------------
# trace / metadata
# ---------------------------------------------------------------------------


class TestTraceMetadata:
    def test_explicit_trace_coordinates_persist(self, db_conn, migrated_db):
        out = run_orm_script(
            migrated_db,
            "import django; django.setup()\n"
            "from contexts.identity.services import create_identity\n"
            "from contexts.identity.ids import uuid7\n"
            "from core.outbox.emitter import emit_outbox_event\n"
            "from contexts.identity import events\n"
            "i = create_identity(type='HUMAN', region_tag='eu-west')\n"
            "subject = f'identity:{i.pk}'\n"
            "emit_outbox_event(\n"
            "    event_type='identity.activated', allowed_event_types=events.EVENT_TYPES,\n"
            "    subject=subject, payload={'identity_id': str(i.pk), 'from_status': 'PROVISIONAL', 'to_status': 'ACTIVE', 'ts': 't'},\n"
            "    event_id=uuid7(), partition_key=subject,\n"
            "    traceparent='00-abc-def-01', request_id='req-42', correlation_id='corr-42',\n"
            "    metadata={'region': i.region_tag},\n"
            ")\n"
            "print(i.pk)\n",
        )
        rows = outbox_rows(db_conn, out.strip())
        assert rows[-1][8] == "00-abc-def-01"
        assert rows[-1][9] == "req-42"
        assert rows[-1][10] == "corr-42"
        assert rows[-1][11] == {"region": "eu-west"}
