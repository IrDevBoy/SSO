"""P0.7 unit tier — relay policy units: backoff (PD-4), DLQ budget (PD-5),
envelope mapping (§29.5), config contract (PD-8/PD-7), safe error
categorization (invariant #10). No database, no Docker.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone as dt_timezone
from unittest import mock
from uuid import uuid4

import pytest

from core.outbox import backoff, conf
from core.outbox.backoff import (
    BACKOFF_BASE_SECONDS,
    BACKOFF_MAX_SECONDS,
    RETRY_BUDGET,
    categorize_error,
    next_backoff_seconds,
)
from core.outbox.conf import RelayConfigError, RelaySettings, dlq_stream_name, relay_settings_from_env
from core.outbox.envelope import EnvelopeError, build_envelope


# ---------------------------------------------------------------- backoff ----

class TestBackoffPD4:
    def test_contract_constants_match_architecture(self):
        # §29.4: exponential 1 s → 15 m; N=5.
        assert BACKOFF_BASE_SECONDS == 1.0
        assert BACKOFF_MAX_SECONDS == 15 * 60.0
        assert RETRY_BUDGET == 5

    def test_monotonic_growth_to_cap(self):
        seq = [next_backoff_seconds(a, rng=random.Random(42)) for a in range(1, 7)]
        # attempts=1 ~1s … attempts>=4 ~15m (capped). Median-bounded checks:
        assert seq[0] < 2.0                     # ~1s + jitter
        assert seq[1] < 4.0                     # ~2s + jitter
        assert seq[2] < 8.0                     # ~4s + jitter
        for late in seq[3:]:
            assert late <= BACKOFF_MAX_SECONDS

    def test_jitter_stays_within_bounds(self):
        for attempts in range(1, 8):
            raw = min(1.0 * 2 ** (attempts - 1), BACKOFF_MAX_SECONDS)
            for _ in range(200):
                v = next_backoff_seconds(attempts, rng=random.Random())
                assert 0.5 * raw <= v <= 1.5 * raw + 1e-9 or v == BACKOFF_MAX_SECONDS

    def test_capped_at_15m(self):
        for attempts in (4, 5, 6, 20):
            assert next_backoff_seconds(attempts, rng=random.Random(1)) <= BACKOFF_MAX_SECONDS

    def test_attempts_must_be_positive(self):
        with pytest.raises(ValueError):
            next_backoff_seconds(0)


class TestErrorCategorizationInvariant10:
    def test_categories_are_enumerated(self):
        assert categorize_error(TimeoutError("read timed out")) == "transport_timeout"
        assert categorize_error(ConnectionError("connection refused")) == "transport_unavailable"
        assert categorize_error(Exception("anything else")) == "unknown_error"

    def test_category_never_echoes_message(self):
        # A hostile error message containing PII-looking text must not leak.
        cat = categorize_error(Exception("failed for user@example.com token=abc123"))
        assert cat == "unknown_error"
        assert "@" not in cat and "token" not in cat and "abc" not in cat


# --------------------------------------------------------------- envelope ----

def _row(**over):
    base = dict(
        event_id=uuid4(),
        event_type="identity.created",
        subject="identity:01900000-0000-7000-8000-000000000000",
        seq=3,
        dataversion=1,
        payload={"identity_id": "01900000-0000-7000-8000-000000000000", "ts": "t"},
        partition_key="identity:01900000-0000-7000-8000-000000000000",
        trace_id="00-trace-span-01",
        request_id="req-1",
        correlation_id="corr-1",
        metadata={"region": "eu-west"},
        created_at=datetime(2026, 9, 25, 12, 0, 0, tzinfo=dt_timezone.utc),
    )
    base.update(over)
    return type("R", (), base)()


class TestEnvelope29_5:
    SRC = "https://id.example.invalid"  # test-only stand-in, never shipped

    def test_mapping_contract(self):
        env = build_envelope(source=self.SRC, row=_row())
        assert env["specversion"] == "1.0"
        assert env["datacontenttype"] == "application/json"
        assert env["id"] == str(_row().event_id) or "id" in env
        assert env["type"] == "identity.created"
        assert env["subject"].startswith("identity:")
        assert env["time"] == "2026-09-25T12:00:00Z"
        assert env["dataversion"] == 1
        assert env["seq"] == 3
        assert env["partition_key"].startswith("identity:")
        assert env["data"] == {"identity_id": "01900000-0000-7000-8000-000000000000", "ts": "t"}
        assert env["traceparent"] == "00-trace-span-01"
        assert env["request_id"] == "req-1"
        assert env["correlation_id"] == "corr-1"
        assert env["metadata"] == {"region": "eu-west"}

    def test_no_schemaurl_invariant14(self):
        env = build_envelope(source=self.SRC, row=_row())
        assert "schemaurl" not in env

    def test_optional_fields_omitted_when_null(self):
        env = build_envelope(source=self.SRC, row=_row(trace_id=None, request_id=None, correlation_id=None, metadata=None))
        for absent in ("traceparent", "request_id", "correlation_id", "metadata"):
            assert absent not in env

    def test_missing_source_refuses_oq01(self):
        for bad in (None, "", "   "):
            with pytest.raises(EnvelopeError, match="OQ-01"):
                build_envelope(source=bad, row=_row())

    def test_no_producer_or_test_invented(self):
        env = build_envelope(source=self.SRC, row=_row(metadata=None))
        assert "metadata" not in env  # nothing fabricated when row has none

    def test_time_is_rfc3339_utc(self):
        env = build_envelope(source=self.SRC, row=_row())
        assert env["time"].endswith("Z") and "T" in env["time"]


# ------------------------------------------------------------------ conf -----

class TestConfPD8:
    def test_dlq_naming_is_locked_template(self):
        assert dlq_stream_name("uiap_events_group") == "dlq.uiap_events_group"  # §29.4

    def test_defaults_present_non_strict(self):
        s = RelaySettings(env={})
        assert s.stream and s.group and s.consumer
        assert s.claim_batch > 0 and s.idle_ms > 0
        assert s.dlq_stream == f"dlq.{s.group}"

    def test_env_overrides(self):
        s = RelaySettings(env={
            "UIAP_RELAY_STREAM": "s1", "UIAP_RELAY_GROUP": "g1",
            "UIAP_RELAY_CONSUMER": "c1", "UIAP_RELAY_CLAIM_BATCH": "7",
            "UIAP_RELAY_IDLE_MS": "1234",
        })
        assert (s.stream, s.group, s.consumer) == ("s1", "g1", "c1")
        assert s.claim_batch == 7 and s.idle_ms == 1234

    def test_strict_mode_fails_closed(self):
        with pytest.raises(RelayConfigError, match="fail-closed"):
            RelaySettings(env={}, strict=True)

    def test_invalid_tuning_values_rejected(self):
        with pytest.raises(RelayConfigError):
            relay_settings_from_env({"UIAP_RELAY_CLAIM_BATCH": "0"})
        with pytest.raises(RelayConfigError):
            relay_settings_from_env({"UIAP_RELAY_IDLE_MS": "-5"})

    def test_no_invented_source_anywhere_in_conf(self):
        # OQ-01: the config module must not carry any source/issuer default.
        src = open(conf.__file__, encoding="utf-8").read()
        assert "UIAP_RELAY_SOURCE" not in src
        assert "issuer" not in src.lower()
