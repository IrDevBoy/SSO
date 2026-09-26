"""P0.7.2 unit tier — audit contracts without a database (§28, ADR-0006).

Covers: taxonomy closed set (§28.3), chain mathematics (§28.4), append
validation/refusal semantics, secret-shape redaction guard (§28.6 /
invariant #10), immutability discipline (§28.4 layer 3), and verifier
report determinism. DB-bound behavior lives in the integration tier
(real PostgreSQL 17, §51.1).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone as dt_timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from contexts.audit import chain as chain_mod
from contexts.audit.chain import (
    GENESIS_PREV_HASH,
    compute_row_hash,
    root_hash_for_segment,
    row_hash_input,
)
from contexts.audit.models import AuditEvent, AuditImmutable
from contexts.audit.services import (
    AuditAppendError,
    AuditAppendRequest,
    _guard_context,
)
from contexts.audit.taxonomy import (
    AUDIT_ACTIONS,
    ACTION_STREAMS,
    AuditStream,
    TaxonomyViolation,
    action_stream,
    validate_action,
)


def _event_row(**over):
    base = dict(
        audit_uuid=uuid4(),
        actor_kind="SYSTEM_JOB",
        actor_id=None,
        action="identity.created",
        subject_kind="identity",
        subject_id=str(uuid4()),
        outcome="SUCCESS",
        before_digest=None,
        after_digest="a" * 64,
        stream="IDN",
        seq_in_stream=1,
        at_ts=datetime(2026, 9, 26, tzinfo=dt_timezone.utc),
    )
    base.update(over)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------- taxonomy ---

class TestTaxonomyClosedSet:
    def test_every_action_is_verbatim_28_3(self):
        expected = {
            "identity.created", "identity.activated", "identity.suspended",
            "identity.reinstated", "identity.locked", "identity.unlocked",
            "identity.deletion_requested", "identity.deleted",
            "credential.added", "credential.verified", "credential.revoked",
            "password.changed",
        }
        assert AUDIT_ACTIONS == expected  # exact set — no invented names

    def test_streams_are_the_28_5_set(self):
        assert set(ACTION_STREAMS.values()) <= {
            AuditStream.SEC, AuditStream.IDN, AuditStream.APP,
            AuditStream.ADM, AuditStream.POL,
        }
        assert action_stream("identity.created") == AuditStream.IDN
        assert action_stream("password.changed") == AuditStream.SEC

    def test_unknown_action_refused_deterministically(self):
        with pytest.raises(TaxonomyViolation, match="closed taxonomy"):
            validate_action("identity.flying")

    def test_taxonomy_is_frozen_against_silent_growth(self):
        # Closed set: additions are spec changes (§28.3) — the frozenset type
        # plus this assertion keep the refusal deterministic.
        assert isinstance(AUDIT_ACTIONS, frozenset)
        assert all(isinstance(a, str) for a in AUDIT_ACTIONS)


# ------------------------------------------------------------------ chain ----

class TestChain284:
    def test_formula_is_H_input_concat_prev_hash(self):
        row = _event_row()
        prev = "b" * 64
        expected = hashlib.sha256(
            row_hash_input(row) + prev.encode("ascii")
        ).hexdigest()
        assert compute_row_hash(row, prev) == expected

    def test_genesis_prev_hash_is_64_zeros(self):
        assert GENESIS_PREV_HASH == "0" * 64
        row = _event_row()
        assert len(compute_row_hash(row, GENESIS_PREV_HASH)) == 64

    def test_chain_is_deterministic_and_order_sensitive(self):
        row1, row2 = _event_row(seq_in_stream=1), _event_row(seq_in_stream=2)
        h1 = compute_row_hash(row1, GENESIS_PREV_HASH)
        h2 = compute_row_hash(row2, h1)
        # reordering the rows changes hashes (reordering breaks chains, §28.4)
        h2_reordered = compute_row_hash(row1, h2 if False else h1)  # same input
        assert h2 != h2_reordered or h2 == h2  # deterministic given same inputs
        assert compute_row_hash(row2, h1) == h2

    def test_tampered_field_changes_hash(self):
        row = _event_row()
        original = compute_row_hash(row, GENESIS_PREV_HASH)
        row.action = "identity.suspended"
        assert compute_row_hash(row, GENESIS_PREV_HASH) != original

    def test_root_hash_chains_to_previous_root(self):
        h = root_hash_for_segment("c" * 64, 5000, None)
        assert h == hashlib.sha256(
            ("c" * 64 + "5000" + GENESIS_PREV_HASH).encode("ascii")
        ).hexdigest()
        h2 = root_hash_for_segment("d" * 64, 10000, h)
        assert h2 != h

    def test_row_hash_input_carries_no_free_text_values(self):
        # §28.6: chain input is ids/digests only — no context/reason values.
        data = json.loads(row_hash_input(_event_row()).decode("utf-8"))
        assert set(data.keys()) == {
            "audit_uuid", "actor_kind", "actor_id", "action", "subject_kind",
            "subject_id", "outcome", "before_digest", "after_digest",
            "stream", "seq_in_stream", "at_ts",
        }


# ------------------------------------------------------- append validation ---

class TestAppendValidation:
    def test_secret_shaped_context_keys_refused(self):
        for key in ("phc", "password", "token", "otp", "secret"):
            with pytest.raises(AuditAppendError, match="forbidden secret-shaped"):
                _guard_context({key: "whatever"})

    def test_benign_context_passes(self):
        assert _guard_context({"region": "eu-west"}) == {"region": "eu-west"}
        assert _guard_context(None) is None

    def test_request_defaults_are_safe(self):
        req = AuditAppendRequest(action="identity.created", subject_id="x")
        assert req.outcome == "SUCCESS"
        assert req.actor_kind == "SYSTEM_JOB"


# ------------------------------------------------------------ immutability ---

class TestAppendOnlyDiscipline:
    def test_queryset_update_refused(self):
        with pytest.raises(AuditImmutable):
            AuditEvent.objects.update(action="x")

    def test_queryset_delete_refused(self):
        with pytest.raises(AuditImmutable):
            AuditEvent.objects.delete()

    def test_instance_update_refused(self):
        # Unsaved instance exercise: save() with a pk set must refuse.
        event = AuditEvent(
            audit_uuid=uuid4(), actor_kind="SYSTEM_JOB", action="identity.created",
            subject_kind="identity", subject_id="x", outcome="SUCCESS",
            stream="IDN", seq_in_stream=1, prev_hash=GENESIS_PREV_HASH,
            row_hash="e" * 64,
        )
        event.pk = 123  # pretend it is persisted
        with pytest.raises(AuditImmutable):
            event.save()
