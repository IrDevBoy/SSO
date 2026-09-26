# ADR-0005: P0.7 Event Relay Foundation

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.7.1; owner-approved PD-2..PD-8) |
| Date | 2026-09-25 |
| Phase | P0.7.1 — Outbox Relay Foundation |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§8.2, §29.4–29.7, §34.4, §34.5, §34.7, §45.4, §51.1, §51.2, §54.2, §59, §60.1, R-30), ADR-0001 (outbox table/roles), ADR-0004 (emission BD-1..9), ADR-0011 (eventing), ADR-0022, OQ-01 |

---

## 1. Status

Accepted for P0.7.1. The seven PD decisions below were **explicitly approved
by the project owner** before implementation began and are recorded exactly
as approved. Where this ADR describes owner-approved choices, the authority
is the owner approval, not an architecture-document claim; nothing here
amends `docs/ARCHITECTURE.md` (Frozen v1.0.1, byte-identical).

## 2. Context

P0.6.2-B (ADR-0004) left every emitted outbox row in `PENDING`: the relay
phase owns everything after the publish-intent. P0.7.1 delivers the relay
foundation: claim loop, PG → Valkey Streams XADD, `PUBLISHED` transition,
retry/backoff, poison parking to the DLQ, PEL reclaim, safe observability,
and real integration tests (PostgreSQL 17 + Valkey, §51.1). ADR-0004 BD-9
deferred `source`/`producer` envelope values to this phase; OQ-01 (§59)
remains OPEN and governs their resolution.

## 3. Source evidence

- §8.2 (`docs/ARCHITECTURE.md:477`): relay is a **separate process** (survives
  deploys, own backpressure/alerts).
- §29.4 (`:2319`): transport = transactional PG outbox → Redis Streams
  (consumer groups); at-least-once; per-aggregate ordering via stream key +
  `seq` for consumer gap detection; retry exponential 1 s→15 m + jitter, per
  consumer group; DLQ stream `dlq.<group>` alert > 0; poison N=5 then park
  (manual replay tool w/ dry-run + audit); replay `X-UIAP-Replay`; relay-lag
  backpressure; stream trim 7 d.
- §29.5 (`:2325`): CloudEvents 1.0-compatible envelope; the `"producer":
  "1.24.0"` string is a **doc example**, not a specification.
- §29.6 (`:2335`): consumers MUST dedupe on `event.id`; MUST NOT assume
  cross-subject ordering; SHOULD verify freshness on refetch.
- §29.7 (`:2339`): nudge-not-data payloads (PII-light).
- §34.4 (`:2563`): outbox claim = SKIP LOCKED, explicitly chosen; R-30 keys
  retention on **published** rows (90 d hot + 90 d cold → purge).
- §34.7 (`:2590`) + bootstrap `001_schemas_roles.sql:147-153`: relay role has
  SELECT/UPDATE only — never INSERT/DELETE/TRUNCATE.
- §45.4 (`:3022`): `/readyz` includes outbox-relay heartbeat.
- §54.2: single leader via lease, N replicas (lease = deployment concern,
  not implemented in P0.7.1).
- ADR-0001 OQ-E: the claim itself provides mutual exclusion; no row_version.
- ADR-0004 BD-1..BD-9: seq allocation, subject namespace, payload_hash,
  no invented `producer`/`test`/`source`.

## 4. PD-2 (A) — Claim state machine

**Approved:** `PENDING → SELECT … FOR UPDATE SKIP LOCKED → XADD → PUBLISHED`.
No intermediate state (`CLAIMED`/`IN_FLIGHT`); no migration.

**Implementation:** `core/outbox/relay.py::claim_batch` claims up to
`claim_batch` rows under one short transaction with the PD-4 predicate
(`publish_state='PENDING' AND available_at <= now()`), ordered by the claim
index (`available_at, id`), envelopes built inside the claim so a missing
`source` fails fast before any publish. **Transaction boundary:** the row
locks are released at claim-commit; the state flip to `PUBLISHED` happens in
a separate short transaction after the XADD. Locks are never held across the
Valkey round-trip. Consequence (deliberate, at-least-once): a crash after
XADD and before the flip leaves the row `PENDING` → it is published again →
**duplicate delivery, expected**, covered by consumer dedupe on `event.id`
(§29.6). A concurrent-relay flip race is detected via the conditional
`UPDATE … WHERE publish_state='PENDING'` rowcount and logged.

## 5. PD-3 (B) — Publication ordering

**Approved:** free publication; the relay MUST NOT wait for `seq=N-1` before
publishing `seq=N` and MUST NOT block per subject. Ordering guarantees stay
in the consumer contract: gap detection on the envelope `seq` + refetch
(§29.4/§29.6). Verified by integration test
(`TestPD3FreePublication`): a later-seq event of the same subject publishes
while the earlier seq is still pending (future `available_at`).

## 6. PD-4 (A) — available_at / backoff semantics

**Approved:** `available_at` = relay-side eligibility time; claim predicate
includes `available_at <= now()`; failure → `attempts += 1` and
`available_at = now() + backoff`.

**Implementation:** `core/outbox/backoff.py` — exponential 1 s → 15 m
(§29.4 constants), full-band jitter in `[0.5x, 1.5x)` (implementation-owned
bounds, tested), cap 15 m. `last_error` stores a **safe error category**
only. **Preserved tension (owner instruction, recorded verbatim):** §29.4
describes retry *per consumer group* while the outbox row carries a single
`available_at`. P0.7 creates **no** per-group backoff state, no table, no
column, and invents no reconciliation semantics; the tension stands until
resolved via the §57 ADR process.

## 7. PD-5 (A) — FAILED / DLQ contract

**Approved:** at the retry budget (`attempts` reaching 5, i.e. N=5 per
§29.4), the event is XADDed to the DLQ stream named `dlq.<group>` (the one
source-backed naming contract) and `publish_state=FAILED`. **No auto-purge
of FAILED exists** — FAILED retention is OPEN (R-30 covers published rows
only). If the DLQ XADD itself fails, the row stays `PENDING` with the retry
budget *not consumed* (park retried later) — at-least-once never degrades to
loss. `error_category` accompanies the DLQ envelope entry. Full replay
tooling (dry-run, admin API, token bucket) is **out of P0.7.1 scope** and
belongs to the §29.4 replay-tool deliverable.

## 8. PD-6 (V1) — PUBLISHED terminal, ACKED deferred

**Approved:** in V1 `PUBLISHED` is the terminal relay state. `ACKED` is
reserved/deferred: the enum value remains in the schema (no migration, no
removal), and **no transition to `ACKED` exists anywhere in P0.7 code**
(asserted by test). R-30 remains keyed on `PUBLISHED`. A future ack-registry
census mechanism (ADR-0022 context) may own the transition later — via a new
owner-approved decision, not silent drift.

## 9. PD-7 (A) — PEL reclaim via XAUTOCLAIM

**Approved:** reclaim idle PEL entries with `XAUTOCLAIM` and a min-idle-time
that is config-backed and tunable
(`UIAP_RELAY_IDLE_MS`, `core/outbox/conf.py`). This is an
**implementation mechanism, not an architectural invariant** — nothing in
the architecture document mandates XAUTOCLAIM. PG outbox state is untouched
by reclaim: the outbox remains the source of truth regardless of transport
state. Reclaim count is surfaced in relay counters.

## 10. PD-8 (A) — Naming and producer metadata

**Approved:** main stream, consumer group, and consumer names come
exclusively from settings/config (`UIAP_RELAY_STREAM`, `UIAP_RELAY_GROUP`,
`UIAP_RELAY_CONSUMER`; batch size and idle time likewise). **No invented
literals** in code; dev/test defaults exist only for local boot and are
documented as such. The DLQ name is *derived* (not configured) from the
group via the locked `dlq.<group>` template. `producer` metadata is read
only from a verified runtime/deployment source — the relay never fabricates
a version. `schemaurl` is not emitted (invariant #14). A source-scan test
asserts no invented `https://id.*` literal exists in relay code.

## 11. OQ-01 — issuer/source

**OPEN / DEFERRED.** No real issuer or `source` value is invented anywhere
in this phase. `UIAP_ISSUER` in `.env.example` remains RESERVED with no
reader. P0.7.1 introduces the deployment-input seam
`UIAP_RELAY_SOURCE` with a **refuse-to-publish** policy: `build_envelope`
hard-fails on a missing/empty source; the claim loop skips the row (row
stays `PENDING`, nothing is published, nothing invented) and logs the
refusal; the standalone relay process refuses to **boot** without a
verified source (fail-closed, §41.4 posture). The real value is set only
when OQ-01 resolves at the §60.1 gate (before first production client
onboarding). This behavior is an owner-approved policy, not an
architectural fact.

## 12. Relay process model

The relay runs as a separate process (`python -m relay`, §8.2) with its own
boot validation, heartbeat/start logging, and config contract. §54.2's
single-leader-via-lease with N replicas is a **deployment-plane concern**
not implemented in P0.7.1; the code is safe under N replicas because claim
mutual exclusion is SKIP LOCKED and the flip is a conditional update — but
the lease itself, k8s manifests, and deployment scaffolds are out of this
phase's boundary.

## 13. Claim/publish semantics

See §4 (PD-2). Summary of crash behavior (all integration-tested):

| Crash window | Result | Contract |
|---|---|---|
| before claim | row untouched, `PENDING` | nothing lost |
| during claim | SKIP LOCKED: disjoint claims | no double claim (tested) |
| after claim, before XADD | row `PENDING` again later | republished (at-least-once) |
| after XADD, before flip | duplicate delivery possible | expected; dedupe on `event.id` (tested) |
| after flip | `PUBLISHED` terminal | done |
| Valkey unavailable | row stays `PENDING`, backoff scheduled | nothing lost (tested) |

## 14. Retry/DLQ

See §6 (PD-4) and §7 (PD-5). N=5 budget consumed only on a *successful*
park; DLQ write failure leaves the row retryable.

## 15. PEL reclaim

See §9 (PD-7). Transport-side bookkeeping only; counted, config-tuned,
tested after the idle threshold.

## 16. CloudEvents mapping (§29.5)

`core/outbox/envelope.py` maps the outbox row to the envelope with nothing
invented: `id = event_id` (invariant #11), `type = event_type`,
`subject = subject`, `time = created_at` (RFC 3339 UTC `Z`),
`data = payload`, `specversion = "1.0"`, `datacontenttype =
"application/json"`, `dataversion`, `seq`, `partition_key`,
`traceparent` (from `trace_id`), `request_id`, `correlation_id`,
`metadata` (verbatim from the row — ADR-0004 BD-6 already guaranteed it is
source-backed; nothing is added). `source` = `UIAP_RELAY_SOURCE` only
(refuse without it). `schemaurl` absent. No fields beyond the contract.

**Clarification on `time` (documentation only; no behavioral change):**
`time = outbox_events.created_at` — the event creation/emit time recorded in
the outbox row (§34.3 DB-clock default). The relay places this stored value
into the envelope; it does **not** stamp a fresh wall-clock timestamp at
XADD time. ADR-0004 §6's phrase "envelope `time` will be relay-built" is
therefore realized here as *the relay builds the field into the envelope*
(from the row's `created_at`), not *the relay generates a new timestamp*.
No code behavior was changed by this clarification.

## 17. Security/logging

- Logs carry only: `event_id`, `subject`, `event_type`, `seq`, `attempts`,
  safe error category, counters. **Never** payload, PHC, OTP, token, email,
  phone, secrets, or PII (invariants #9/#10, §41.4/§42 T-22).
- `last_error` column stores enumerated safe categories only.
- No new dependency; `redis-py` (already pinned `redis>=5,<7`) speaks the
  Redis protocol to Valkey (App. A/OQ-12).
- Unit tests assert error categories never echo hostile message content.

## 18. Observability

`RelayCounters` (safe telemetry): heartbeat/start log, claimed, published,
retry-scheduled, parked/FAILED, reclaimed, transport-unavailable count,
error-category histogram, publish latency (total/avg). DLQ/main stream
lengths exposed via transport helpers. §45.4 `/readyz` heartbeat wiring is
the observability sub-phase's integration point — the counter surface is
designed for it.

## 19. Testing

Real PostgreSQL 17 + real Valkey via testcontainers (§51.1: no stand-ins,
no SQLite anywhere). 18 integration tests in
`tests/integration/relay/test_outbox_relay_contract.py` cover: claim
concurrency (threaded SKIP LOCKED, zero overlap), publish transition, no
intermediate state, future `available_at` not claimed, duplicate after
XADD+failed flip, Valkey-unavailable retry with safe category, backoff
progress (attempts 1→2), N=5 park to `dlq.<group>` + `FAILED` + attempts
preserved, no auto-purge of FAILED, no `ACKED` transition, free publication
(PD-3), XAUTOCLAIM after idle threshold, envelope contract + `id ==
event_id`, no invented source (refuse-to-publish) and no `https://id.*`
literals, payload_hash recomputation (invariant #12), config-backed names
(custom stream/group honored), no-PII log scan. Unit tier: backoff bounds,
envelope mapping, config fail-closed, DLQ naming.

## 20. Migration impact

**Zero migrations.** No schema change of any kind: claim state machine
(PD-2), backoff semantics (PD-4), DLQ parking (PD-5), and ACKED deferral
(PD-6) all operate on the existing P0.4 columns and CHECK. The relay role's
grants (SELECT/UPDATE, USAGE/SELECT sequences) already suffice; the
bootstrap SQL is unchanged.

## 21. Unresolved items

1. **FAILED retention — OPEN.** No contract exists (R-30 keys on
   `PUBLISHED`); FAILED rows accumulate unbounded until resolved. No purge
   was implemented (owner instruction). Resolution via owner decision.
2. **OQ-01 — OPEN.** Real `source`/issuer value, set via `UIAP_RELAY_SOURCE`
   at the §60.1 gate. Until then the relay either refuses to publish or runs
   with a deployment-verified value.
3. **§29.4 per-group retry vs single `available_at` tension — preserved
   verbatim**, un-reconciled by owner instruction.
4. **Replay tooling** (manual replay, dry-run + audit, token bucket,
   `X-UIAP-Replay`) — §29.4 deliverable, out of P0.7.1.
5. **Lease/leader election** (§54.2) — deployment-plane, out of P0.7.1.
6. **Jitter bounds `[0.5x, 1.5x)`** — implementation-owned, tunable, not
   architecture.

## 22. Exit gates

- [x] Owner approval recorded for PD-2..PD-8 (decision registration turn).
- [x] Baseline verified: HEAD `a1efcbd`, ARCHITECTURE SHA256
      `c9fa5264…3401` unchanged, `arch-v1.0.1` = `9ee7fafd`, tracked tree
      clean before implementation.
- [x] Zero migrations, zero new dependencies, zero `uv.lock` changes,
      zero CI changes, zero config changes beyond new relay env contract.
- [x] Unit suite green (150 tests), integration suite green on real
      PG17 + Valkey (117 tests, includes 18 relay tests).
- [x] Architecture document byte-identical after implementation.
- [ ] Security gates re-run recorded in the implementation report
      (bandit/semgrep/pip-audit/gitleaks).
- [ ] Commit only after full report; push only on explicit owner approval.
