"""P0.6.1 unit tests — pure, Django-free proofs of the foundation pieces.

The UUIDv7 generator (:mod:`contexts.identity.ids`) and the lifecycle maps
(:mod:`contexts.identity.lifecycle`) are deliberately dependency-free, so
the whole matrix is provable without a database, without Docker and without
configuring Django — matching the unit tier's contract (§51.1).
"""

import threading
import uuid

import pytest

from contexts.identity import ids, lifecycle
from contexts.identity.lifecycle import (
    CREDENTIAL_TRANSITIONS,
    IDENTITY_TRANSITIONS,
    TransitionForbidden,
    validate_transition,
)
from contexts.identity.models import (
    IdentityHistoryImmutable,
    IdentityStatusHistory,
)

IDENTITY_STATUSES = [
    "PROVISIONAL",
    "ACTIVE",
    "SUSPENDED",
    "LOCKED",
    "PENDING_DELETION",
    "DELETED",
    "ABANDONED",
    "MERGED",
]

TERMINAL = ["DELETED", "ABANDONED", "MERGED"]


# ---------------------------------------------------------------------------
# G5 — UUIDv7 (RFC 9562, D-2 hand-rolled)
# ---------------------------------------------------------------------------
class TestUuid7:
    def test_version_and_variant_bits(self):
        for _ in range(500):
            u = ids.uuid7()
            assert u.version == 7
            assert u.variant is uuid.RFC_4122

    def test_timestamp_extraction_roundtrip(self):
        u = ids.uuid7()
        ts = u.int >> 80  # top 48 bits are unix_ts_ms
        assert ts == ids._last_ts_ms

    def test_batch_uniqueness(self):
        seen = {ids.uuid7() for _ in range(10_000)}
        assert len(seen) == 10_000

    def test_intraprocess_ordering_is_monotonic(self):
        values = [ids.uuid7().int for _ in range(1_000)]
        assert values == sorted(values), "uuid7 must be monotonic within a process"

    def test_concurrent_generation_unique_and_monotonic(self):
        """8 contended threads × 500 generations:

        * every value is unique, and
        * the *values* form a strict total order — sorted(values) is
          strictly increasing, which is exactly what consumers rely on
          (B-tree insert locality, §11.1) and what can hold regardless of
          scheduling: the module lock makes each (unix_ts_ms, counter)
          slot unique, and rand_b < 2^62 < 2^64 never disturbs the
          (ts, counter) comparison.

        The *collection* order of ``results`` is thread-scheduling noise
        (local lists overlap in time and are extended in arbitrary
        order), so it is deliberately NOT asserted.  Deterministic proof
        that the lock serializes counter *allocation* — generation order
        — lives in test_contended_counter_allocation_is_deterministic.
        """
        results: list[uuid.UUID] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            local = [ids.uuid7() for _ in range(500)]
            with lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(results)) == 8 * 500
        ordered = sorted(u.int for u in results)
        assert all(a < b for a, b in zip(ordered, ordered[1:])), (
            "distinct UUIDs must be strictly totally orderable "
            "((ts, counter) slots are unique; rand_b never outranks them)"
        )
        assert all(u.version == 7 and u.variant == uuid.RFC_4122 for u in results)

    def test_contended_counter_allocation_is_deterministic(self, monkeypatch):
        """Frozen clock + 8 contended threads × 256 generations (2048 total,
        well below the 4096/ms exhaustion bound): the module lock must
        allocate the counter exactly once per generation, so the extracted
        rand_a counters are exactly {0 .. 2047} under the single shared
        timestamp.  This asserts generation order (lock-acquisition order)
        deterministically — independent of thread scheduling and of the
        order results are collected in (§11.1: 'monotonic within a node').
        """
        monkeypatch.setattr(ids, "_time_ms", lambda: 1_700_000_000_000)
        monkeypatch.setattr(ids, "_last_ts_ms", 0)
        monkeypatch.setattr(ids, "_counter", 0)
        results: list[uuid.UUID] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            local = [ids.uuid7() for _ in range(256)]
            with lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total = 8 * 256
        assert len(set(results)) == total
        assert all((u.int >> 80) == 1_700_000_000_000 for u in results)
        counters = sorted((u.int >> 64) & 0xFFF for u in results)
        assert counters == list(range(total)), (
            "counter allocation must be serialized exactly once per "
            "generation by the module lock"
        )

    def test_clock_stall_never_regresses_and_counts(self, monkeypatch):
        monkeypatch.setattr(ids, "_last_ts_ms", 1_000)
        monkeypatch.setattr(ids, "_counter", 0)
        monkeypatch.setattr(ids, "_time_ms", lambda: 1_000)  # stalled clock
        u1, u2 = ids.uuid7(), ids.uuid7()
        assert (u1.int >> 80) == 1_000
        assert (u2.int >> 80) == 1_000
        # counter advanced: the two values differ deterministically
        assert u1.int != u2.int

    def test_clock_rollback_holds_last_timestamp(self, monkeypatch):
        monkeypatch.setattr(ids, "_last_ts_ms", 5_000)
        monkeypatch.setattr(ids, "_counter", 0)
        monkeypatch.setattr(ids, "_time_ms", lambda: 4_999)  # clock went backwards
        u = ids.uuid7()
        assert (u.int >> 80) == 5_000  # never regresses (RFC 9562 monotonicity)

    def test_counter_exhaustion_advances_timestamp(self, monkeypatch):
        monkeypatch.setattr(ids, "_last_ts_ms", 7_000)
        monkeypatch.setattr(ids, "_counter", 0xFFF)  # one value left in this ms
        monkeypatch.setattr(ids, "_time_ms", lambda: 7_000)
        u = ids.uuid7()
        assert (u.int >> 80) == 7_001  # rolled into the next millisecond


# ---------------------------------------------------------------------------
# G2 — lifecycle matrix (§11.4, exactly the diagram edges)
# ---------------------------------------------------------------------------
class TestLifecycleMatrix:
    def test_all_status_sets_are_complete(self):
        assert set(IDENTITY_TRANSITIONS) == set(IDENTITY_STATUSES)
        assert set(CREDENTIAL_TRANSITIONS) == {"PENDING", "ACTIVE", "STALE", "REVOKED", "EXPIRED"}

    def test_allowed_edges_match_the_architecture_diagram(self):
        assert IDENTITY_TRANSITIONS["PROVISIONAL"] == frozenset({"ACTIVE", "ABANDONED"})
        assert IDENTITY_TRANSITIONS["ACTIVE"] == frozenset(
            {"SUSPENDED", "LOCKED", "PENDING_DELETION", "MERGED"}
        )
        assert IDENTITY_TRANSITIONS["SUSPENDED"] == frozenset(
            {"ACTIVE", "PENDING_DELETION", "MERGED"}
        )
        assert IDENTITY_TRANSITIONS["LOCKED"] == frozenset({"ACTIVE", "PENDING_DELETION"})
        assert IDENTITY_TRANSITIONS["PENDING_DELETION"] == frozenset({"ACTIVE", "DELETED"})

    def test_terminal_states_have_no_outgoing_edges(self):
        for state in TERMINAL:
            assert IDENTITY_TRANSITIONS[state] == frozenset()

    def test_terminal_states_are_never_targets_of_forbidden_paths(self):
        # DELETED is reachable only from PENDING_DELETION; ABANDONED only from
        # PROVISIONAL; MERGED only from ACTIVE/SUSPENDED.
        reachable_to = {to for edges in IDENTITY_TRANSITIONS.values() for to in edges}
        assert reachable_to == {"ACTIVE", "ABANDONED", "SUSPENDED", "LOCKED",
                                "PENDING_DELETION", "DELETED", "MERGED"}

    def test_forbidden_transitions_raise_with_states_in_message(self):
        for current, to in [
            ("PROVISIONAL", "SUSPENDED"),
            ("LOCKED", "SUSPENDED"),
            ("ABANDONED", "ACTIVE"),
            ("DELETED", "ACTIVE"),
            ("MERGED", "ACTIVE"),
            ("ACTIVE", "DELETED"),  # hard path forbidden: must go via PENDING_DELETION
        ]:
            with pytest.raises(TransitionForbidden) as exc:
                validate_transition(IDENTITY_TRANSITIONS, current, to, kind="identity")
            assert current in str(exc.value) and to in str(exc.value)

    def test_credential_edges_match_120_chain(self):
        assert CREDENTIAL_TRANSITIONS["PENDING"] == frozenset({"ACTIVE"})
        assert CREDENTIAL_TRANSITIONS["ACTIVE"] == frozenset({"STALE", "REVOKED", "EXPIRED"})
        assert CREDENTIAL_TRANSITIONS["STALE"] == frozenset({"REVOKED"})
        for terminal in ("REVOKED", "EXPIRED"):
            assert CREDENTIAL_TRANSITIONS[terminal] == frozenset()
        with pytest.raises(TransitionForbidden):
            validate_transition(CREDENTIAL_TRANSITIONS, "PENDING", "REVOKED", kind="credential")


class TestAppendOnlyHistoryGuards:
    """§5.B / D-6: history UPDATE/DELETE refused in the application layer.
    (The DB tier of this contract is exercised in the integration suite.)"""

    def _row(self) -> IdentityStatusHistory:
        return IdentityStatusHistory(identity_id=uuid.uuid4(), status="ACTIVE")

    def test_update_of_existing_row_refused(self):
        row = self._row()
        row.pk = 123  # simulate an existing (persisted) history row
        with pytest.raises(IdentityHistoryImmutable):
            row.save()

    def test_instance_delete_refused(self):
        with pytest.raises(IdentityHistoryImmutable):
            self._row().delete()

    def test_queryset_delete_refused(self):
        with pytest.raises(IdentityHistoryImmutable):
            IdentityStatusHistory.objects.all().delete()
