# ADR-0001: P0.4 Database Foundation Decisions

| Field | Value |
|---|---|
| Status | Accepted (implementation-approved, P0.4) |
| Date | 2026-09-16 |
| Phase | P0.4 — Database Foundation |
| Supersedes | — |
| Related | ARCHITECTURE.md v1.0.1 (§29, §34, §34.7, §41.4, §51.1, §54.1), ADR-0005 (PG17), ADR-0011 (outbox→streams) |

---

## 1. Context

P0.4 lays the physical database substrate of UIAP: the schema-per-context
model (§34.2), the DB role model (§34.7), and the single P0 table
(`outbox_events`, §34.4) delivered through Django's migration framework.
Everything here was approved as the implementation plan P0.4 with decisions
A-1 … A-8; this ADR records them, the open questions they resolve, the
rejected alternatives, and the two approved scope deviations discovered
during implementation.

The implementation is Django 5.2 on Python 3.13, PostgreSQL 17 via
psycopg 3 (Django backend `django.db.backends.postgresql`), with
testcontainers (PG 17 real) for the integration tier (§51.1: no SQLite
stand-ins, ever).

## 2. Decision summary (approved A-1 … A-8)

- **A-1** — `django_migrations` bookkeeping lives in a dedicated
  *infrastructure* schema **`uiap_migration`**. The eight architecture
  schemas remain exactly: `uiap_identity`, `uiap_access`, `uiap_profile`,
  `uiap_address`, `uiap_security`, `uiap_audit`, `uiap_notification`,
  `uiap_org`.
- **A-2** — the Django infrastructure app is **`core/outbox`** (app label
  `outbox`), a cross-cutting infrastructure subsystem — not a context app.
- **A-3** — schema targeting via `db_table = 'uiap_access"."outbox_events'`
  (fully schema-qualified DDL), and the migration/runtime connection pins
  `search_path=uiap_migration`.
- **A-4** — roles/schemas/grants come from CI-owned bootstrap SQL
  (`deploy/db/bootstrap/001_schemas_roles.sql`), separate from migrations.
- **A-5** — `uiap_migration` owns all `uiap_*` objects; migrations execute
  as that role.
- **A-6** — `uiap_verifier` and `uiap_audit_read` are created as NOLOGIN
  placeholders with zero operational privileges in P0.
- **A-7** — this ADR exists and records the P0.4 decisions and deviations.
- **A-8** — the file scope of the phase is the approved 13-path list (see
  §12 for the two approved deviations).

## 3. Open-question resolutions

### OQ-A — Where does Django's `django_migrations` table live?
**Resolved (A-1/A-3):** in `uiap_migration`. Django creates bookkeeping
wherever the connection's `search_path` points; base.py pins
`OPTIONS["options"] = "-c search_path=uiap_migration -c application_name=uiap-django"`.
Verified empirically by the integration suite
(`uiap_migration.django_migrations` holds exactly `('outbox','0001_initial')`
after `migrate outbox`).

### OQ-B — How does a Django model live in a specific schema?
**Resolved (A-3):** Django (5.2) has no per-model schema routing, so the
outbox model uses a fully schema-qualified `db_table`
(`uiap_access"."outbox_events` — the leading double-quote is opened by
Django's `quote_name`). Every emitted statement therefore names the table
*inside* `uiap_access` regardless of `search_path`; there is no runtime
ambient-path dependency for DML, and the migration cannot leak the table
into `public`. Rejected: `postgresql-db-schema` third-party router (new
dependency, forbidden), search_path juggling for DML (fragile, violates
single-pool posture).

### OQ-C — Who owns the objects; what identity applies DDL?
**Resolved (A-5):** `uiap_migration` owns every `uiap_*` schema and object.
CI runs `migrate outbox` with `UIAP_DB_USER=uiap_migration` (after the
bootstrap provisions that role's credential outside version control). The
integration harness enacts exactly this path, and asserts
`tableowner = uiap_migration` and `nspowner = uiap_migration` for all nine
schemas. No role in the model is superuser.

### OQ-D — How do runtime roles get privileges on objects that do not exist yet?
**Resolved:** the bootstrap attaches table/sequence grants through
`ALTER DEFAULT PRIVILEGES FOR ROLE uiap_migration IN SCHEMA uiap_access` so
grants materialize at object-creation time. This keeps the bootstrap
executable *before* the migration (no grants against a nonexistent table —
a real failure mode hit and fixed during implementation), while the role
matrix stays declarative in one CI-owned file. Outbox grants:
`uiap_app`: SELECT/INSERT/UPDATE (+sequence usage);
`uiap_relay`: SELECT/UPDATE — **never INSERT/DELETE/TRUNCATE**;
`uiap_admin`: SELECT/INSERT/UPDATE/DELETE; no CREATE for anyone but the
owner; `uiap_verifier`/`uiap_audit_read`: none (A-6).

### OQ-E — Does the outbox need `row_version` optimistic locking?
**Resolved:** **No** — documented per the P0.5 storage rule ("record the
reason in the ADR if not applicable"). Outbox rows are append-mostly;
lifecycle transitions (`PENDING→PUBLISHED→ACKED/FAILED`, attempts bump) are
claimed by the relay under the §34.4 SKIP LOCKED pattern, where the claim
itself provides mutual exclusion. A `row_version` counter would add a
second, weaker serialization mechanism that the claim already subsumes and
would widen the update surface of hot rows. The Relay phase owns the exact
claim predicate.

### OQ-F — Where do dev/test get a database from?
**Resolved:** dev/test keep the neutral, previously-existing laptop posture:
unset `UIAP_DB_HOST/PORT/NAME` fall back to `localhost/5432/uiap` purely so
`manage.py check` and the unit tier boot without a server (no scope creep);
the backend is always PostgreSQL and there is no SQLite anywhere. Real
local databases come from the env contract; CI/local integration uses the
testcontainers harness. staging/prod are **fail-closed**: any missing/empty
required `UIAP_DB_*` parameter is a boot error (§41.4 posture applied to
the DB endpoint), triggered by three independent signals — the `UIAP_ENV`
identity, the `DJANGO_SETTINGS_MODULE` selector (G-3), or a staging/prod
module being star-imported on top of base.

## 4. Schema model

Nine schemas, exactly (A-1): the eight domain schemas of §34.2 plus the
infrastructure schema `uiap_migration`. The integration suite asserts the
exact `uiap_*` namespace set (no ninth domain schema can appear silently)
and that only `uiap_migration.django_migrations` + `uiap_access.outbox_events`
exist as tables in P0.

## 5. Role model

Exactly the six §34.7 roles (no invented roles): `uiap_app`, `uiap_relay`,
`uiap_verifier`, `uiap_admin`, `uiap_migration`, `uiap_audit_read`.
`uiap_app` is emphatically not superuser; the two placeholders are NOLOGIN
with zero grants (A-6). Credentials never appear in the bootstrap file;
CI injects them (`ALTER ROLE … PASSWORD`) outside version control.

## 6. `uiap_migration` rationale

Migration bookkeeping is *infrastructure of the tooling*, not a domain
concept; keeping it out of the eight domain schemas preserves the §34.2
boundary list verbatim ("no ninth domain schema"), avoids polluting any
context's namespace with Django framework artifacts, and gives the DDL
principal (A-5) a natural home schema. `django_migrations` placement here
is fully reversible with the table it tracks.

## 7. django_migrations placement

`search_path=uiap_migration` is pinned on the single `default` connection
(P0 keeps one pool — split pools are a later, measured decision). DML is
unaffected because the outbox table name is schema-qualified; the pin
exists for bookkeeping creation/lookup and is proven by integration tests.

## 8. Outbox ownership & the cross-context exception

The outbox is the shared event plane of the monolith (§29): every context
writes publish-intents in its own transaction and the relay consumes them.
Its *table*, however, must have exactly one physical home; P0.4 places it
in `uiap_access` (A-3) while the owning code lives in the infrastructure
app `core/outbox` (A-2). This is the **only** approved cross-context
placement exception; contexts themselves still never touch foreign tables
(§9.1 rules intact). Rationale: the access schema already hosts the
authn/event pipeline's hot tables, and P0 keeps the exception count at one.

## 9. Migration policy

- Django-native migrations only (`makemigrations outbox` → audited
  `0001_initial.py`); reversible (`migrate outbox zero` restores the
  pre-migration state — verified against real PG17).
- **Targeted migration only**: `python manage.py migrate outbox`. The
  generic `migrate` is forbidden in P0 (would attempt
  auth/contenttypes). No dependency on `auth`/`contenttypes`/`admin` exists
  in the migration.
- No auth/contenttypes tables are created; `django_migrations` is the only
  framework artifact that materializes.
- Bootstrap SQL (roles/schemas/grants) is deliberately separate from
  migrations (A-4): roles and schemas are cluster-level facts with
  credentials managed outside Django; migrations are versioned schema
  *changes*. Mixing them would put secret-provisioning concerns into the
  ORM path and break the §34.7 "DDL via CI only" boundary.

## 10. Security boundaries

- Least privilege per role (matrix above); no superusers; CREATE nowhere
  except the owner.
- `public` schema: `REVOKE ALL ON SCHEMA public FROM PUBLIC` — no
  accidental table-creation path; integration tests assert PUBLIC holds no
  CREATE on `public` and no UIAP object exists there.
- No secret material in any committed file; the `.env.example` DB password
  stays empty by rule; staging/prod refuse to boot on missing/empty DB
  configuration (§41.4).
- `application_name=uiap-django` makes server-side triage unambiguous.

## 11. Rejected alternatives

- **SQLite for unit/local tiers** — forbidden by §51.1 and by the phase
  rules; no fallback exists anywhere in the settings tree (tested).
- **Search-path-based table placement** (keep `db_table='outbox_events'`
  and rely on search_path) — rejected: DML correctness would depend on an
  ambient session state; any other connection (PgBouncer pool, ad-hoc psql)
  silently lands in `public`.
- **Django app-per-context schema routing libraries** (`django-db-schema`,
  tenants) — new dependency forbidden (RULE 1); also unnecessary for one
  table.
- **Grants inside migrations** (`RunSQL(GRANT …)` per migration) — couples
  every migration to the role model and diverges from the CI-owned
  single-source bootstrap (A-4). Default privileges (OQ-D) achieve the same
  effect declaratively.
- **`row_version` on outbox rows** — see OQ-E.
- **Bootstrap that grants on the not-yet-existing table** — real failure
  found in implementation; replaced by default privileges (OQ-D).

## 12. Consequences & recorded deviations

Positive: exact schema/role inventory is machine-checked; migration
lifecycle (apply → reverse → re-apply) verified on real PG17; dev/test
laptop flow unchanged; the staging/prod fail-closed posture now also covers
the database endpoint.

**Approved deviation 1 (env contract):** `tests/unit/
test_environment_contract.py` (P0.3) asserted that `UIAP_DB_*` remain
RESERVED-with-no-reader and that `.env.example` declares exactly the old
variable set. S2/A-8 inherently contradict both. Per the user's explicit
approval, the two assertions were updated minimally: the five `UIAP_DB_*`
variables moved to ACTIVE with reader `config/settings/base.py`, and
`UIAP_DB_SSLMODE` was added to the declared contract. No other change to
that file.

**Approved deviation 2 (test helper credentials):** the P0.2/P0.3
staging/prod subprocess helpers (`test_skeleton.py` and
`TestProductionSafety`) import hardened settings without DB env vars; the
new fail-closed gate made them unable to reach the code paths they exist to
test. Their helpers now seed dummy (non-secret) `UIAP_DB_*` values so the
secret/DEBUG assertions under test remain decisive. ADR records this as
inherent to making staging/prod fail-closed, not a contract change.

## 13. Rollback implications

- `migrate outbox zero` drops the table and clears
  `uiap_migration.django_migrations` (verified). Re-apply is idempotent
  ("No migrations to apply" on a second run; re-creating after zero).
- Bootstrap SQL is idempotent (guarded role creation, `IF NOT EXISTS`
  schemas, repeated `ALTER DEFAULT PRIVILEGES` converge); re-running never
  downgrades privileges.
- Because the migration file is dependency-free and the table has no FKs,
  rollback touches nothing else; auth/contenttypes absence means there is
  no framework table cleanup to consider.
- Settings rollback is reverting `base.py`'s DATABASES block; no other
  settings module needs a compensating change (RULE 4 held — zero changes
  to dev/test/staging/prod).

## 14. Local provisioning is out of scope

Local developer provisioning (real PG instance, role credentials,
`.env` values) is deliberately NOT automated in P0.4: the integration
harness covers the CI path end-to-end, the `.env.example` contract tells
developers what to set, and provisioning automation belongs to a later
infrastructure sub-phase (§34.7/§54.1 ownership).
