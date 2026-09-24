# ADR-0003: P0.6.2-A Password Secrets + Argon2id Decisions

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.6.2-A) |
| Date | 2026-09-24 |
| Phase | P0.6.2-A — Password Secrets Storage + Argon2id |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§10.2, §12.0, §12.2, §34.4, §34.5, §39 R-04, §40.2, §50.3, §59 OQ-03), ADR-0001, ADR-0002 |

---

## 1. Context

P0.6.2-A adds password authentication storage: the §34.4 typed secret table
`uiap_identity.password_secrets`, Argon2id hashing (§12.2), the password
policy (§12.2 / FR-004), the R-04 history contract (current + 1 prior, then
wipe), and the OD-3 breach-deny boundary. Outbox emission (events, seq) is
P0.6.2-B and is deliberately absent here. The audit cascade (§34.5 / INV-08)
cannot be completed yet because audit tables are P0.7 — this is decision
OD-1 below. `docs/ARCHITECTURE.md` remains byte-identical (Frozen v1.0.1).

## 2. Decision summary (approved OD-1 … OD-7)

- **OD-1 — Audit deferral.** Audit tables/models/migrations are NOT created
  in P0.6.2-A (they arrive in P0.7). This is a recorded **deviation from the
  §34.5 strong-same-transaction cascade**, which requires rows + audit +
  outbox intent in one transaction. Consequence: credential/password
  mutations are currently atomic for rows + history only. The service-layer
  transaction boundaries (`contexts/identity/services.py`) are designed as
  the single append points, so the P0.7 audit writer joins the same
  `transaction.atomic()` block without redesign. Rollback: none needed.
- **OD-2 — argon2-cffi dependency.** Added via uv (real PyPI resolver):
  `argon2-cffi==25.1.0`, hash-pinned in `uv.lock`. No other dependency.
- **OD-3 — Breach-deny interface only.** `BreachDenier` Protocol +
  `AllowAllBreachDenier` fail-open stub in `contexts/identity/passwords.py`.
  No corpus, no network, no HIBP. Fail-open default is documented at the
  boundary; wiring a real denier is a call-site change once OQ-03 ships the
  offline k-anon bloom corpus.
- **OD-4 — No outbox emitter.** Nothing in P0.6.2-A touches
  `core/outbox`. Service atomic blocks are the designated future join
  points for the P0.6.2-B emitter.
- **OD-5 — No new partial unique constraint.** Max-one-ACTIVE-password
  invariant is enforced in the service layer under the identity row lock
  (§34.5 strong same-tx pattern); integration tests prove serialized
  rotations end with exactly one ACTIVE secret. No schema constraint added.
- **OD-6 — Outbox seq not implemented.** Belongs to P0.6.2-B.
- **OD-7 — Column provenance.** `password_secrets` implements §10.2/§34.4
  source-backed columns plus the minimal REQUIRED classification recorded
  in section 3; no convenience columns were added.

## 3. Column provenance for `uiap_identity.password_secrets`

| Column | Classification | Source |
|---|---|---|
| `id uuid` PK (app-side UUIDv7) | SOURCE-BACKED | §34.4 "PK uuid"; §11.1 ids |
| `credential_id` FK → credentials | SOURCE-BACKED | §34.4 "FK credential"; §10.2 row |
| `phc` (hash, length-capped) | SOURCE-BACKED | §34.4 "password hash"; PHC = source of truth (§12.2) |
| `argon_memory_kib`, `argon_time_cost`, `argon_parallelism` NOT NULL | SOURCE-BACKED | §34.4 "argon params NOT NULL" |
| CHECK `phc LIKE '$argon2id$%'` | SOURCE-BACKED (enforcement of "password hash" + §12.2 type) | §34.4/§12.2 |
| Argon parameter bounds CHECKs | REQUIRED (bounds, not values — supports rehash-era params) | ADR inference, recorded |
| `version` NOT NULL | SOURCE-BACKED | §10.2 row 6 explicitly lists "version" |
| `status` ACTIVE/SUPERSEDED/DISABLED + CHECK | SOURCE-BACKED | §10.2: "ACTIVE→SUPERSEDED/DISABLED" |
| `breach_checked_at` nullable | SOURCE-BACKED | §10.2 row 6 lists "breached-corpus check timestamp" |
| `superseded_at` nullable | REQUIRED | R-04 retention needs the supersede moment; `status` alone cannot order current/previous rows |
| `created_at` (db_default Now) | REQUIRED | §34.4 timestamps convention (P0.4/P0.6.1 pattern) |
| `row_version` bigint | REQUIRED | P0.6.1 mutable-row convention; bump on supersede/disable |
| NO index on `phc` / secret columns | SOURCE-BACKED | §34.4 "none hot/readable" |
| NO identity-level FK | SOURCE-BACKED | credential owns its secret (§12.0) |

## 4. Policy constants (§12.2 / FR-004)

Argon2id initial `m=19456 KiB, t=2, p=1`; long-term target `m=65536 KiB,
t=3, p=4` (rehash compares stored PHC params against policy). Min 12 /
legacy floor 8 (explicit `legacy_import` boundary only) / max 256; NFC
normalization; no composition, no expiry, no hints; history = current + 1
prior (R-04: new set supersedes current → previous, then older rows are
wiped, hash-only at all times).

## 5. Consequences

- Plaintext never persists anywhere (§6.6-2, §40.2, INV-03); PHC-only
  storage is DB-CHECK-enforced.
- The audit cascade gap (OD-1) is the only known deviation; it is closed in
  P0.7 without schema change.
- OQ-03 (breach corpus) and OQ-1/OQ-2 remain open and untouched.
