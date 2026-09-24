"""P0.6.2-B unit tier — §29.3 catalog, emitter contract (ADR-0004, BD-1..9).

Pure unit proofs (no database): catalog names are verbatim §29.3, canonical
JSON/hash is deterministic (BD-4), and the emitter validates types, formats
the subject (BD-2), stamps PENDING/dataversion, and allocates seq by MAX+1
(BD-1) — the model layer is mocked so no PostgreSQL is required.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from unittest import mock

import pytest

from core.outbox import emitter
from core.outbox.emitter import canonical_payload_bytes, emit_outbox_event, payload_hash
from contexts.identity import events

CATALOG_MD_LINE = (
    "`identity.created | identity.activated | identity.provisional_expired | "
    "identity.suspended | identity.reinstated | identity.locked | "
    "identity.unlocked | identity.deletion_requested | identity.deleted"
)


class TestCatalogIsVerbatimArchitecture:
    def test_catalog_names_exact(self):
        assert events.EVENT_TYPES == frozenset(
            {
                "identity.created",
                "identity.activated",
                "identity.suspended",
                "identity.reinstated",
                "identity.locked",
                "identity.unlocked",
                "identity.deletion_requested",
                "identity.deleted",
                "credential.added",
                "credential.verified",
                "credential.revoked",
                "password.changed",
            }
        )

    def test_bd3_unreachable_events_absent(self):
        for forbidden in ("identity.provisional_expired", "password.imported"):
            assert forbidden not in events.EVENT_TYPES
            assert not any(k.startswith("PASSWORD_IMPORTED") or k.startswith("PROVISIONAL") for k in dir(events))

    def test_catalog_names_appear_verbatim_in_architecture_md(self):
        text = open("docs/ARCHITECTURE.md", encoding="utf-8").read()
        for name in events.EVENT_TYPES:
            assert name in text, f"{name} is not in the §29.3 catalog"

    def test_dataversion_is_one(self):
        assert events.DATAVERSION == 1


class TestCanonicalHashBD4:
    PAYLOAD = {"identity_id": "01900000-0000-7000-8000-000000000000",
               "ts": "2026-09-24T00:00:00+00:00"}

    def test_canonical_bytes_exact(self):
        assert canonical_payload_bytes(self.PAYLOAD) == (
            b'{"identity_id":"01900000-0000-7000-8000-000000000000",'
            b'"ts":"2026-09-24T00:00:00+00:00"}'
        )

    def test_key_order_and_whitespace_irrelevant(self):
        reordered = {"ts": self.PAYLOAD["ts"], "identity_id": self.PAYLOAD["identity_id"]}
        assert canonical_payload_bytes(reordered) == canonical_payload_bytes(self.PAYLOAD)

    def test_hash_is_sha256_hex64(self):
        h = payload_hash(self.PAYLOAD)
        assert h == hashlib.sha256(canonical_payload_bytes(self.PAYLOAD)).hexdigest()
        assert len(h) == 64 and h == h.lower() and all(c in "0123456789abcdef" for c in h)

    def test_hash_fixture_value(self):
        assert payload_hash(self.PAYLOAD) == (
            "47885d9967a2ba27c0d8159fb1b6dd0882d4f4b1fcd73a55ecd6aeff0a0e7827"
        )


class TestEmitterContract:
    OK = dict(
        event_type="identity.created",
        allowed_event_types=events.EVENT_TYPES,
        subject="identity:01900000-0000-7000-8000-000000000000",
        payload={"identity_id": "x", "ts": "t"},
        event_id=uuid.uuid4(),
    )

    def test_unsupported_event_type_rejected(self):
        with pytest.raises(ValueError, match="approved catalog"):
            emit_outbox_event(**{**self.OK, "event_type": "password.rehashed"})

    def test_unsupported_type_not_created(self):
        with mock.patch.object(emitter, "OutboxEvent") as fake:
            with pytest.raises(ValueError):
                emit_outbox_event(**{**self.OK, "event_type": "identity.anonymized"})
            fake.objects.create.assert_not_called()

    def test_row_fields(self):
        with mock.patch.object(emitter, "OutboxEvent") as fake:
            fake.objects.filter.return_value.aggregate.return_value = {"max_seq": 7}
            emit_outbox_event(**self.OK)
            kw = fake.objects.create.call_args.kwargs

        assert kw["seq"] == 8                      # BD-1: MAX+1
        assert kw["publish_state"] == "PENDING"    # §34.4
        assert kw["dataversion"] == 1              # §29.5
        assert kw["subject"].startswith("identity:")  # BD-2
        assert kw["event_id"] == self.OK["event_id"]
        assert kw["payload_hash"] == payload_hash(self.OK["payload"])
        assert len(kw["payload_hash"]) == 64       # BD-4
        assert kw["trace_id"] is None              # BD-6 defaults
        assert kw["request_id"] is None
        assert kw["correlation_id"] is None
        assert kw["metadata"] is None
        fake.objects.filter.assert_called_once_with(subject=self.OK["subject"])

    def test_metadata_and_trace_propagate(self):
        with mock.patch.object(emitter, "OutboxEvent") as fake:
            fake.objects.filter.return_value.aggregate.return_value = {"max_seq": None}
            emit_outbox_event(
                **self.OK,
                partition_key=self.OK["subject"],
                traceparent="00-trace-span-01",
                request_id="req-1",
                correlation_id="corr-1",
                metadata={"region": "eu-west"},
            )
            kw = fake.objects.create.call_args.kwargs

        assert kw["seq"] == 1                       # MAX(NULL)+1
        assert kw["partition_key"] == self.OK["subject"]
        assert kw["trace_id"] == "00-trace-span-01"
        assert kw["request_id"] == "req-1"
        assert kw["correlation_id"] == "corr-1"
        assert kw["metadata"] == {"region": "eu-west"}
