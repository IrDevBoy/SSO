# ADR-0004: P0.6.2-B Transactional Identity Events (Outbox Emission)

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.6.2-B) |
| Date | 2026-09-24 |
| Phase | P0.6.2-B — Transactional Outbox + Identity Event Plane |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§29.2–29.7, §34.3–34.5, §55.7, §61.2 I-1..I-10, OQ-01), ADR-0001 (outbox table), ADR-0002, ADR-0003 |

---

## 1. Context

P0.6.1/P0.6.2-A built the identity storage, lifecycle, and password
contracts with the outbox emission deliberately deferred (D-8, OD-4). The
P0.4 outbox table (`uiap_access.outbox_events`, ADR-0001) already implements
the complete §34.4 contract — `(subject, seq)` unique, PENDING state
machine, PENDING partial claim index — so **no migration and no new
dependency are required**. P0.6.2-B wires the §29.3 identity/credential/
password events into the existing service transaction boundaries via a
generic emitter in `core/outbox` (cross-cutting infrastructure, §7.1/§55.7).

## 2. Approved decisions (BD-1 … BD-9)

- **BD-1 — seq allocation.** `MAX(seq)+1` for ALL events sharing subject
  `identity:<uuid>`, allocated while the identity row is locked
  (`select_for_update`). `identity.row_version` is **never** used as
  outbox seq — it remains exclusively the §34.3/§24.7 optimistic-concurrency
  / ETag version. Rows inserted earlier in the same transaction are visible
  to the `MAX` aggregate, so multi-event transactions get strictly
  increasing, contiguous sequences; a rolled-back transaction discards its
  rows entirely, so no committed gap can exist (the next transaction
  reuses the freed next seq). `unique(subject, seq)` (P0.4) remains the DB
  backstop. *Note: the earlier OD-6 hypothesis (`seq=row_version` for
  lifecycle events) is superseded — mixing two allocators on one subject
  namespace collides, and the §34.3 row_version semantics must not be
  overloaded.*
- **BD-2 — subject.** All identity/credential/password events use
  `subject = f"identity:{identity.uuid}"` (no `credential:<uuid>` subject).
  `partition_key = identity:<uuid>` — §29.4 pins the stream key to the
  identity-id hash; the exact envelope string is this same namespace
  (source-backed, one namespace, one allocator).
- **BD-3 — event scope.** Only currently reachable §29.3 events:
  `identity.created`, `identity.activated`, `identity.suspended`,
  `identity.reinstated`, `identity.locked`, `identity.unlocked`,
  `identity.deletion_requested`, `identity.deleted`, `credential.added`,
  `credential.verified`, `credential.revoked`, `password.changed`.
  `identity.provisional_expired` (no sweeper worker exists) and
  `password.imported` (no legacy-import service path exists) are NOT
  implemented. No type is invented; §11.4 edges without an approved catalog
  name (→ABANDONED, →MERGED) emit nothing. `rehash_password` emits nothing
  (no `password.rehashed` in §29.3).
- **BD-4 — payload_hash.** SHA-256 lowercase hex (exactly 64 chars) over
  the canonical JSON of the **payload only**:
  `json.dumps(payload, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False).encode("utf-8")`. Not the envelope.
- **BD-5 — payloads (minimum nudge sets, §29.7).**
  `identity.created`: `{identity_id, ts}`; lifecycle edges:
  `{identity_id, from_status, to_status, ts}`; credential events:
  `{identity_id, credential_id, kind, ts}`; `password.changed`:
  `{identity_id, credential_id, ts}`. No actor (no actor context exists in
  P0); never plaintext/hash/PHC/email/phone/tokens/secrets/Argon2
  parameters/breach data. `ts` = `timezone.now().isoformat()` — the
  established app timestamp semantics; DB `created_at` (db_default Now())
  remains the storage-side truth.
- **BD-6 — trace/metadata.** `traceparent`, `request_id`, `correlation_id`
  are explicit emitter arguments (NULL when unavailable; the model columns
  are named `trace_id` etc. from P0.4 — the §29.5 `traceparent` header
  value lands there; rename/DDL is out of scope). No middleware, no
  thread-locals, no observability infrastructure. `metadata` = only
  source-backed values: `{"region": identity.region_tag}`. `test` flag and
  `producer` version are deferred (no invented values).
- **BD-7 — governance.** Python constants in
  `contexts/identity/events.py` + unit tests asserting them verbatim
  against §29.3 (`docs/ARCHITECTURE.md:2302`). No `event-schemas/*.json`,
  no registry infrastructure this phase (§29.3 registry artifact is a later
  deliverable; schemaurl is not populated).
- **BD-8 — lock order.** `transition_credential` now acquires the identity
  row lock BEFORE the credential row lock (order everywhere:
  identity → credential), so seq allocation under the shared subject is
  serialized by the aggregate lock. No reverse order exists.
- **BD-9 — no source column.** OQ-01 (issuer domain) stays unresolved; the
  final CloudEvents `source` (and `specversion`/`time`/`schemaurl` fields
  not present as columns) is constructed at the future relay/publish stage.
  Rows in this phase are complete PENDING publish-intents.

## 3. Event ordering (password set)

Emission order inside `set_password` mirrors the mutation chronology:
`credential.added` (only when the credential row is newly created) →
`credential.verified` (only on the existing first-verification semantics:
the None→set transition of `verified_at`, the P0.6.2-A reused-credential
writer) → `password.changed` (every password mutation). The emitter
allocates seq sequentially inside the transaction, so outbox seq reflects
exactly this order.

## 4. Transaction semantics

Every emission is a plain insert inside the caller's existing
`transaction.atomic()` block (`create_identity`, `transition_identity`,
`transition_credential`, `set_password`). The emitter never opens a
transaction, publishes, or touches Redis/Valkey/Celery. Mutation + history
+ outbox commit or roll back atomically (§34.5). The P0.7 audit append
(OD-1) joins these same boundaries as an additional same-tx insert.

## 5. Dependency direction

`core.outbox` imports nothing from `contexts.*`; the identity context may
call `core.outbox` (§55.7 infrastructure). The emitter receives every value
explicitly, including the caller-generated `event_id` (the context's own
RFC 9562 UUIDv7 mechanism, ADR-0002 D-2) — this keeps the UUIDv7 generator
single-sourced without a forbidden reverse import.

## 6. Consequences

- Committed events are contiguous per subject and strictly ordered;
  consumers detect gaps per §29.4 (all gaps are committed-outbox semantics,
  never allocator artifacts).
- Event `ts` values are app-clock; envelope `time` will be relay-built.
- Outbox rows stay PENDING until the relay phase (Relay = separate
  sub-phase; no Redis/Valkey work in B).
- Scope exclusions: relay, Valkey/Redis Streams, DLQ/replay, event-schemas
  artifacts, audit tables (P0.7), authn/session/device/token/consent/
  email/phone/mfa events, sweeper, password import, middleware,
  observability, migrations, new dependencies, ARCHITECTURE.md changes.
