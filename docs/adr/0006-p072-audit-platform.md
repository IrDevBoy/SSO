# ADR-0006: P0.7.2 Audit Platform Foundation

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.7.2) |
| Date | 2026-09-26 |
| Phase | P0.7.2 — Audit Platform Foundation (INV-08 / §28 / §34.5 closure) |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§28, §34.5, §34.7, §51.1, §51.6, INV-08, FR-026, NFR-008, §61.1), ADR-0001 (schema/role/migration model), ADR-0002 (append-only pattern), ADR-0003 (OD-1 deferral — closed here), ADR-0004 (hash convention BD-4), ADR-0005 (relay) |

---

## 1. Status

Accepted for P0.7.2. All decisions below are implementation decisions within
the Frozen architecture's explicit grants (§61.2: implementation owns internal
module layout, ORM usage, migration tooling specifics). Nothing here amends
`docs/ARCHITECTURE.md` (byte-identical, hash `c9fa5264…3401` verified after
implementation).

## 2. Context

ADR-0003 (OD-1) deferred the audit cascade: "audit tables arrive in P0.7 …
this is a recorded deviation from the §34.5 strong-same-transaction cascade".
P0.7.1 delivered the relay but not audit, leaving OD-1 open — the only known
deviation from §34.5. P0.7.2 closes it: the `uiap_audit.audit_events` +
`audit_roots` tables, the same-transaction append service (INV-08), the
§28.4 hash-chain + checkpoint foundation, the verifier foundation, the
§28.3 closed taxonomy, and the identity/credential/password integration at
the four reserved mutation boundaries.

## 3. Architecture requirements (source of truth)

- **§28.1**: audit append participates in the domain transaction (INV-08) —
  an un-audited state change must roll back.
- **§28.2**: the full column contract (actor, action, subject, outcome,
  before/after *digests*, stream, chain fields).
- **§28.3**: closed action taxonomy, "versioned with the document".
- **§28.4**: per-stream/partition hash chain, checkpoint every 5,000 rows /
  15 min, PG-level immutability (UPDATE/DELETE revoked), verifier foundation,
  "gaps impossible: seq assigned pre-commit".
- **§28.5**: streams SEC|IDN|APP|ADM|POL; monthly logical partitions.
- **§28.6**: digests stored, not values; hot rows PII-light.
- **INV-08** (§10): identity status/credential changes MUST produce an audit
  event in the same transaction; breach = release blocker (§56 gate).
- **FR-026 / NFR-008**: tamper-evidence; checkpoint within 15 min / 5,000 rows.
- **§34.5**: rows + audit + outbox intent in one transaction.
- **§61.1**: "all verifications synchronous + audited" — audit precedes any
  authn/session phase.

## 4. Audit schema decisions

`contexts/audit/models.py` implements §28.2 with these concrete choices:

- **Table names**: `uiap_audit.audit_events`, `uiap_audit.audit_roots`
  (plural, Django convention — the §28.2 singular names `audit_event` /
  `audit_roots` are kept as `audit_roots`; the event table's pluralization is
  the established repository convention from `outbox_events` /
  `identity_status_history`).
- **PK**: `audit_id` BigAutoField (§28.2: "per-partition sequence … internal
  only, never exposed"); **external ref** = `audit_uuid` UUID4, unique
  (§28.2 + P-08). UUID4 (not UUIDv7): §28.2 does not mandate time-ordered
  public ids, and chain ordering is owned by `seq_in_stream`, not the uuid —
  no invented semantics.
- **`at_ts`**: app-clock `timezone.now()` set explicitly before hashing, then
  inserted as part of the row (see §7 of this ADR) — DB `Now()` default is
  retained for direct-SQL defense but the service always supplies the value.
- **`actor_id` / `session_sid` / `application_id` / `device_id`**: nullable —
  §28.2 marks session/app/device columns "nullable (system jobs)"; the actor
  producers for them (sessions, admin plane) do not exist yet, and inventing
  placeholder actors is forbidden (phase rule). The audit service accepts
  explicit `actor_kind`/`actor_id` arguments so the future producer wires in
  with zero schema change.
- **`before_digest` / `after_digest`**: SHA-256 over canonical JSON of the
  *redacted state summary* (ids/statuses only) — §28.2 "digests stored".
- **`payload_ref`**: column present, always NULL in P0.7.2 (no object storage
  exists; §28.2 cold tier is a later infrastructure phase).
- **`context`**: JSONB with a service-level refusal of secret-shaped keys +
  a DB CHECK as backstop.
- **CheckConstraints**: taxonomy closed-set check, stream check, outcome
  check, no-secret-keys check — DB-level backstops behind service validation.

## 5. Nullable/deferred session-dependent fields

Recorded per the phase mandate: `actor_id` (when `actor_kind=SYSTEM_JOB` or
`ANONYMOUS`), `application_id`, `device_id`, `session_sid`, `ip`,
`request_id`/`correlation_id`/`trace_id`, `reason_text`, `payload_ref` are
NULL in P0.7.2 rows. No fake values, no placeholder business data. The
producers (sessions §23, admin plane §44) arrive in later phases and will
pass these values explicitly; no migration will be needed.

## 6. Hash-chain algorithm

§28.4 formula implemented verbatim in `contexts/audit/chain.py`:

- `row_hash = H(row_hash_input || prev_hash)` with **H = SHA-256** (the
  repository's established hash convention — ADR-0004 BD-4 `payload_hash`;
  the architecture does not name a different algorithm).
- `row_hash_input` = canonical JSON (`sort_keys=True, separators=(",",":"),
  ensure_ascii=False` — the BD-4 convention) over exactly twelve
  redaction-safe §28.2 fields (`audit_uuid`, `actor_kind`, `actor_id`,
  `action`, `subject_kind`, `subject_id`, `outcome`, `before_digest`,
  `after_digest`, `stream`, `seq_in_stream`, `at_ts`). Values that could
  carry PII/secrets are excluded from hot rows by §28.6 construction, so the
  chain input never carries them.
- **Genesis**: `prev_hash = "0" * 64` for the first row of a chain (constant,
  documented, tested).
- **Chain scope**: `(stream, logical month-partition)` per §28.4 "within each
  (stream, month-partition) subpartition". Physical monthly RANGE partitions
  (§28.5 DDL job) are a later infrastructure deliverable; the logical
  partition key (at_ts month) scopes lock, seq, checkpoint, and verification
  identically today, so the DDL job can land later without re-hashing.
- **Checkpoint commitment** (`audit_roots`): `root_hash =
  H(last_row_hash || seq_to || prev_root_hash)`; row-count bound (5,000)
  enforced inline by the append service; the 15-min cadence belongs to the
  nightly/cron job (deferred, §17).

## 7. Concurrency strategy

The architecture names the mechanism: §28.4 layer 1 — "maintained with
**partition-local advisory locks**". Implementation:

- **`pg_advisory_xact_lock(key)`** with `key = hashtext('uiap_audit:' ||
  stream)` — transaction-scoped (auto-release at commit/rollback, no manual
  unlock, no lock rows in tables, no deadlock class: single lock per append,
  acquired in one fixed order after the domain locks, so the identity→
  credential lock order (BD-8, ADR-0004) is preserved and never inverted).
- The lock is acquired **inside** `transaction.atomic()`: under autocommit
  callers it opens the bounded transaction that keeps the lock alive for the
  whole seq-read → hash → INSERT section; under callers already inside a
  transaction it creates a savepoint — still atomic with the caller (an
  outer rollback discards the append). The append never commits
  independently of the caller's work.
- `seq_in_stream = MAX(seq_in_stream) + 1` **inside the lock** (pre-commit,
  per §28.4's "seq assigned pre-commit, gaps roll back the transaction") with
  a **DB UNIQUE backstop** `audit_events_stream_seq_uc (stream,
  seq_in_stream)` — belt-and-braces: even a bypass of the service cannot
  duplicate a sequence position.
- Per-stream locking (not per-partition): the lock key hashes the stream
  name; the month partition rarely rolls mid-flight, and stream-level
  serialization is strictly safer for chain integrity at V1 volumes
  (§28.4: "write contention = per-partition, tolerable at V1 volumes" —
  stream-level is a subset of that contention envelope).

Verified by the concurrent-append integration test (4 threads × 5 appends →
chain re-verifies OK, zero duplicate seqs).

## 8. Transaction boundary

`append_audit_event` NEVER opens an independent committing transaction (the
emitter's rule, ADR-0004 §4). All three artifacts — domain mutation, audit
row, outbox intent — commit or roll back as one unit (§34.5). Any failure
(taxonomy violation, secret-shaped context, transport-class failure in the
future, IntegrityError) raises inside the caller's transaction and rolls
back everything. Proven by the three rollback-direction integration tests.

## 9. Identity integration

`contexts/identity/services.py` audit points (INV-08 + §28.3 Identity /
Credentials bullets):

| Mutation | Audit action | Stream |
|---|---|---|
| `create_identity` | `identity.created` | IDN |
| `transition_identity` (each catalog-mapped edge) | the edge's §29.3 name (e.g. `identity.activated`) | IDN |
| `transition_credential` (every edge) | `credential.{added,verified,revoked}` | SEC |
| `set_password` (new credential) | `credential.added` | SEC |
| `set_password` (always) | `password.changed` | SEC |
| `rehash_password` (upgrade applied) | `password.changed` (context marks rehash) | SEC |

Notes:
- The outbox stays BD-3-scoped (P0.6.2-B emission set unchanged); audit
  coverage is per §28.3 and intentionally broader (e.g. credential edges
  that emit no event are still audited).
- Lock order: domain row locks (identity → credential, BD-8) are acquired
  BEFORE the audit advisory lock — the audit lock is the innermost, ordered
  last everywhere, so no deadlock cycle exists.
- Digests only: the secret itself, its PHC, and any credential material
  never enter an audit row (§28.6 + invariant #10; tested).

## 10. Taxonomy

`contexts/audit/taxonomy.py` — closed set of the twelve §28.3 actions whose
producer paths exist (identity lifecycle edges, credential edges,
password.changed), each mapped to its §28.5 stream. `validate_action`
refuses anything else with a deterministic error naming the §57 ADR process
for additions. The DB CHECK constraint mirrors the set. The rest of the
§28.3 catalog belongs to unimplemented contexts — no invention, no
placeholders.

## 11. Verifier

`verify_stream_partition(stream, partition)` — §28.4 layer 4 foundation:

- Recomputes the row chain for one `(stream, partition)` slice from stored
  rows and compares `prev_hash`/`row_hash` stepwise.
- Detects: edited field (hash mismatch), deleted row (prev-hash break),
  reordering (sequence/prev mismatch), any suppression tampering.
- Reports deterministically: `{stream, partition, rows, ok,
  first_broken_seq}`.
- **Read-only** — never mutates audit data.
- **Privilege boundary**: designed to run under the dedicated
  `uiap_verifier` NOLOGIN role (A-6/§34.7) when the nightly job phase wires
  it; the function itself needs only SELECT, which the role model grants
  separately (see §12).
- The adversarial-tamper and row-deletion integration tests prove detection
  (§51.6 adversarial posture, in-DB superuser edit).

## 12. Privileges

- **No change to `deploy/db/bootstrap/001_schemas_roles.sql`.** The ADR-0001
  default-privilege mechanism (OQ-D) grants on `uiap_audit` objects the
  moment `uiap_migration` creates them; the audit app requires **no**
  runtime-role writes through anything but the application module, and P0
  runtime roles already hold what §34.7 gives them.
- `uiap_audit_read` / `uiap_verifier` remain NOLOGIN placeholders with zero
  operational privileges (A-6) — verified by an integration test asserting
  zero grants and NOLOGIN. They receive SELECT only in the audit-read /
  nightly-verifier phase, per §34.7.
- §28.4 layer 3 ("UPDATE/DELETE revoked on audit tables via role grants")
  is **application-enforced + tested** in this phase (the
  `AuditImmutable` discipline + the queryset/instance refusals + the
  duplicate-seq adversarial test). The grant-level revocation for
  `uiap_app` is a bootstrap change and belongs to the same CI-owned file
  when the read/verifier phase activates the roles — recorded here so it is
  not silently dropped.

## 13. Migration strategy

Django-native only (`makemigrations audit`), following ADR-0001:

- `contexts/audit/migrations/0001_initial.py` — `audit_events` + `audit_roots`
  CreateModel ops, schema-qualified `db_table = 'uiap_audit"."…'` (A-3
  pattern), no auth/contenttypes dependency, targeted `migrate audit` only
  (RULE 9).
- `0002_auditevent_audit_events_stream_seq_uc.py` — the seq-unique backstop
  (§7 of this ADR).
- Fully reversible (`migrate audit zero`) — proven by the test harness
  reset path, which zeroes and re-migrates per test.
- No hand-DDL; no changes to existing P0 migrations.

## 14. Test strategy

- **Unit (16 new, DB-free)**: taxonomy closed set + stream mapping +
  refusal; chain formula/genesis/order-sensitivity/tamper-sensitivity;
  chain-input field inventory (no free-text carriers); secret-shaped context
  refusal; append-only discipline (queryset update/delete, instance save
  with pk).
- **Integration (13 new, real PG17 via testcontainers)**: the four
  same-transaction cascade scenarios (create / lifecycle / credential revoke
  / password mutation), no-secret-leak scan over stored rows, the three
  rollback directions (business-fail / audit-fail / outbox-fail → no
  residue), concurrent chain validity (4 threads × 5 appends → verifier OK),
  adversarial row-edit detection, row-deletion detection, duplicate-seq
  backstop, privilege separation (audit_read zero grants + NOLOGIN),
  migration/schema contract (tables, owner, CHECK constraints).
- All deterministic; no SQLite; no new fixtures beyond the existing harness.

## 15. Security / redaction

- Audit rows carry ids, taxonomy names, outcomes, digests — never secrets,
  PHC strings, OTPs, tokens, or PII values (§28.6, invariant #10). Enforced
  by: service-level `_guard_context` (secret-shaped key refusal), the
  `_digest` helper (only summaries are hashed), a DB CHECK, and an
  integration test scanning stored rows for `phc`/`$argon2id$` leakage.
- No secret-like literals in any new file (gitleaks-clean posture).

## 16. Explicit non-goals (P0.7.2)

- Physical monthly RANGE partitions + the partition-creation job (§28.5 DDL
  job) — logical partitioning is in place; DDL lands with the retention
  phase.
- Nightly verifier cron + alerting (§28.4 layer 4 operations) — the verifier
  function is the foundation; the job wiring is the observability phase.
- WORM/TSA external anchoring (V2/V3, §28.4) — explicitly out of V1 scope.
- Audit read API / admin search / SIEM mirror (§28.7) — read-side phases.
- Retention/pruning tombstoning (§28.4 threat table) — retention engine.
- Sampling policies, `audit.queried` self-audit (no admin plane yet).

## 17. Deferred items (with owner phase)

| Item | Owner phase |
|---|---|
| 15-min checkpoint cadence job | observability/cron phase |
| Physical partitions + creation job | retention phase |
| `uiap_audit_read`/`uiap_verifier` SELECT grants + nightly verifier job | audit-read phase |
| `uiap_app` UPDATE/DELETE revocation at grant level (bootstrap edit) | audit-read phase (CI-owned bootstrap change) |
| Audit read API + `audit.queried` self-auditing | admin/read phase |
| `payload_ref` cold tier + object storage | infrastructure phase |

## 18. Consequences

- **OD-1 is closed**: the §34.5 cascade (rows + audit + outbox in one
  transaction) is now implemented and tested for every identity/
  credential/password mutation. ADR-0003's recorded deviation is discharged.
- INV-08 is machine-checked (unit + integration + DB CHECK), satisfying the
  §56 gate requirement.
- The audit foundation required by §61.1 ("all verifications … audited")
  now precedes any authn/session phase — the prerequisite graph is unblocked.
- Identity services gained one import seam (`contexts.audit.services`) —
  context → context import; §9.1 forbids cross-context *table* access, and
  this is a service-level seam over the audit context's own tables
  (equivalent to the outbox infrastructure seam), recorded here per §61.2.
- Zero migrations outside `contexts/audit`; zero dependency changes; zero
  CI changes; ARCHITECTURE.md byte-identical.
