# ADR-0002: P0.6.1 Identity Storage + Lifecycle Decisions

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.6.1) |
| Date | 2026-09-23 |
| Phase | P0.6.1 — Identity Storage + Lifecycle Foundation |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§11.2, §11.3, §11.4, §11.6, §12.0, §34.2, §34.4, §34.5, §34.7), ADR-0001 (schema/role/migration model) |

---

## 1. Context

P0.6.1 delivers the first domain tables of the platform: the identity root
aggregate, its lifecycle state machine (§11.4), the point-in-time status
history, and the §12.0 credential lifecycle hub header — storage tier only.
Password hashing, email/phone value storage, KMS-dependent blind indexes, and
outbox emission are explicitly **out of scope** (the latter belongs to
P0.6.2).

Everything here was approved as the implementation scope with decisions
D-1 … D-7; this ADR records them, the one architecture discrepancy they
touch, and the recorded inferences. The implementation is Django 5.2 /
Python 3.13 / PostgreSQL 17 (testcontainers for the integration tier,
§51.1: no SQLite stand-ins), following the ADR-0001 substrate (schema-
qualified `db_table`, `uiap_migration` bookkeeping, targeted migrations
only).

## 2. Decision summary (approved D-1 … D-7)

- **D-1 — ABANDONED is in the DB status CHECK.** §11.4's state machine
  defines `PROVISIONAL → ABANDONED`, so the status CHECK constraint on
  `identities` includes `ABANDONED` even though the §11.2 status
  enumeration omits it. **The §11.2 / §11.4 discrepancy is recorded here
  verbatim and deliberately NOT "fixed":** `docs/ARCHITECTURE.md` remains
  byte-identical (Frozen v1.0.1, §61.2 protocol governs any reissue). The
  state machine (§11.4) is treated as authoritative for behavior.
- **D-2 — hand-rolled RFC 9562 UUIDv7, zero new dependencies.**
  `contexts/identity/ids.py` implements UUIDv7 application-side: 48-bit
  unix-ms timestamp, 12-bit `rand_a` per-millisecond counter, 62
  `os.urandom` bits. Monotonicity: within a process, ids are ordered by
  `(unix_ts_ms, counter)`; clock rollback/stall holds the last timestamp
  and keeps counting; counter exhaustion advances the timestamp by exactly
  1 ms. No DB default and no `gen_random_uuid()`-style default exists on
  `identities.id` (integration-test-enforced); the column is a plain
  `uuid`.
- **D-3 — `identity_merges` is NOT created in this phase.** `MERGED`
  exists only as a terminal lifecycle representation (status value,
  terminal edge, `closed_at`); no merge feature, table, or flow.
- **D-4 — `identity_{human,organization,service}_ext` tables are NOT
  created.** The §11.2 ext-table pattern is deferred; `identities` holds
  exactly the architecture's base columns.
- **D-5 — `activated_at` / `closed_at` are nullable**, set only by the
  lifecycle transition that owns them: `activated_at` at ACTIVE entry
  (first time; birth-ACTIVE identities get it at creation), `closed_at`
  at terminal entry (DELETED / ABANDONED / MERGED).
- **D-6 — append-only history and tombstone semantics are enforced at the
  application layer + tests, with NO new grant tightening this phase.**
  Concretely: `IdentityStatusHistory.save()` refuses updates of persisted
  rows; instance and queryset `delete()` raise
  `IdentityHistoryImmutable`; `Identity` instance and bulk delete raise
  `IdentityHardDeleteForbidden` (INV-01: a tombstone is never hard-
  deleted; deletion is a status transition to DELETED). History rows are
  appended in the same transaction as the identity mutation
  (`transition_identity` uses `select_for_update` + atomic block;
  integration tests prove the concurrent single-winner property).
- **D-7 — `identity_status_history` columns are exactly
  `{id, identity_id, status, valid_from}`.** No `reason`, no `actor`, no
  `valid_to` (integration-test-enforced column inventory).

D-8 (noted for P0.6.2): outbox emission does not exist in P0.6.1; the
`seq = row_version` correlation is a P0.6.2 decision and is not
implemented.

## 3. Recorded inferences (non-decisions, visible in code)

- `credentials.created_by` — §12.0 lists the column without a type; stored
  as an opaque `varchar(128)` principal reference (minimal non-inventive
  storage). When the actor model exists, this column can be reconsidered
  through the §61.2 protocol.
- `credentials.mfa_strength_rank` — §12.0 defines the *order* (passkey >
  security-key > TOTP > email ≈ SMS); the numeric encoding is policy-
  owned and the column only stores it.
- `credential kind` CHECK — the kind set
  `{PASSWORD, EMAIL, PHONE, TOTP, PASSKEY, RECOVERY_CODES}` is derived
  from the §12.1 method matrix / §34.4 typed-secret-table list.
- `identities` partial status index — §34.4 says "status partial (ops
  scans)"; the predicate chosen is the non-terminal ("live") slice,
  consistent with the hot-path scans the section describes.
- Django `PROTECT` on both FKs (`credentials.identity`,
  `identity_status_history.identity`) — no cascades anywhere, matching
  the tombstone doctrine.

## 4. Consequences

- The identity schema is now the first domain consumer of the ADR-0001
  substrate; `uiap_identity` moves from empty schema to the exact three
  §34.4 group-identity tables, and the integration contract tests assert
  the set exactly.
- The §11.2/§11.4 `ABANDONED` discrepancy stays open as recorded
  documentation drift; if a future ADR reissues the architecture, the
  §11.2 enumeration should absorb `ABANDONED` (or the machine should be
  revised) — not silently in code.
- OQ-3 (ADR numbering/index/reissue consistency, deferred since P0.5.4)
  remains untouched: this ADR reuses the repository's existing sequential
  numbering (0001, 0002) per the established convention.

## 5. Rejected alternatives

- *DB-level UUIDv7 default* — rejected: §11.1/D-2 make the id application-
  owned and immutable; a DB default would invite non-service writes.
- *DB triggers for `row_version` / history append-only* — rejected: §34.2
  reserves mutation discipline to the service layer; triggers would
  duplicate policy and complicate reverse migrations.
- *Grant tightening for append-only enforcement now* — rejected for this
  phase per D-6 (application layer + tests first; DB-role enforcement
  follows with the audit/actor work).
- *Typed credential tables (email/phone/password_secrets/…) in P0.6.1* —
  rejected: out of approved scope; they need KMS-dependent
  encryption/blind-index decisions (OQ-02) and P0.6.2.
