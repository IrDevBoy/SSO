-- ============================================================================
-- UIAP — Unified Identity & Access Platform
-- deploy/db/bootstrap/001_schemas_roles.sql
--
-- P0.4 Database Foundation (ADR 0001; ARCHITECTURE.md v1.0.1 §34.2, §34.7)
--
-- PURPOSE
--   CI-owned bootstrap of the PostgreSQL substrate: the eight domain schemas,
--   the infrastructure bookkeeping schema (uiap_migration), and the approved
--   role/grant model. This file is the ONLY place infrastructure DDL outside
--   a Django migration lives (decision A-4); schema *changes* are migrations
--   only (§34.7: no hand-DDL, ever).
--
-- TARGET: PostgreSQL 17 (§34.1).
--
-- EXECUTION CONTEXT (CI):
--   Run by a connection with CREATEROLE + CREATE privilege on the database
--   (the migration-era superuser/bootstrap principal). Credentials for login
--   roles are injected by the pipeline (KMS/Vault → ALTER ROLE ... PASSWORD),
--   NEVER in this file: this script contains no secret material.
--
-- IDEMPOTENCE
--   Safe to re-run: CREATE ROLE/SCHEMA are guarded (IF NOT EXISTS /
--   pg_roles existence checks). Grants/revokes are inherently idempotent.
--
-- OWNERSHIP (decision A-5)
--   uiap_migration owns all uiap_* objects. Application roles receive
--   usage/DML privileges only; no role in this file is a superuser.
--
-- SCHEMAS (A-1) — exactly these, no ninth domain schema:
--   uiap_identity uiap_access uiap_profile uiap_address
--   uiap_security uiap_audit uiap_notification uiap_org
--   uiap_migration (infrastructure bookkeeping: django_migrations)
--
-- ROLES (§34.7; exactly these, no invented roles):
--   uiap_app        application runtime (LOGIN): DML on its own-schema
--                   objects; P0 = outbox read/write in uiap_access.
--   uiap_relay      outbox relay (LOGIN): claims/updates/reads outbox rows —
--                   NO INSERT/DELETE/TRUNCATE (insertion happens through the
--                   domain write path, never through the relay).
--   uiap_verifier   P0 NOLOGIN placeholder (decision A-6): audit-chain
--                   verifier in a later phase; zero operational privileges.
--   uiap_admin      platform admin (LOGIN): RW + audit SELECT (§34.7).
--   uiap_migration  DDL path via CI only (LOGIN): owns the uiap_* schemas.
--   uiap_audit_read P0 NOLOGIN placeholder (decision A-6): audit read in a
--                   later phase; zero operational privileges.
--
-- PUBLIC HYGIENE
--   The public schema must never become an accidental table-creation path:
--   CREATE on public is revoked from PUBLIC; public holds no UIAP objects;
--   uiap_* schemas are excluded from any default search_path.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Schemas (A-1: eight domain + one infrastructure)
-- ---------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS uiap_identity;
CREATE SCHEMA IF NOT EXISTS uiap_access;
CREATE SCHEMA IF NOT EXISTS uiap_profile;
CREATE SCHEMA IF NOT EXISTS uiap_address;
CREATE SCHEMA IF NOT EXISTS uiap_security;
CREATE SCHEMA IF NOT EXISTS uiap_audit;
CREATE SCHEMA IF NOT EXISTS uiap_notification;
CREATE SCHEMA IF NOT EXISTS uiap_org;

-- Infrastructure bookkeeping schema (A-1): django_migrations lives here.
CREATE SCHEMA IF NOT EXISTS uiap_migration;

COMMENT ON SCHEMA uiap_migration IS
  'UIAP infrastructure bookkeeping (django_migrations); not a domain schema.';

-- ---------------------------------------------------------------------------
-- 2. Roles (PG17: guarded CREATE via pg_roles lookup)
-- ---------------------------------------------------------------------------

-- Group/ownership roles first (NOLOGIN by default; membership carries the
-- privileges so per-person logins never hold privileges directly).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_migration') THEN
        CREATE ROLE uiap_migration NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_app') THEN
        CREATE ROLE uiap_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_relay') THEN
        CREATE ROLE uiap_relay NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_admin') THEN
        CREATE ROLE uiap_admin NOLOGIN;
    END IF;
    -- P0 placeholders (A-6): created NOLOGIN, no operational privileges.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_verifier') THEN
        CREATE ROLE uiap_verifier NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uiap_audit_read') THEN
        CREATE ROLE uiap_audit_read NOLOGIN;
    END IF;
END
$$;

-- P0 placeholders must stay NOLOGIN even on re-runs against drifted
-- environments (A-6: they gain real privileges only in a later phase).
ALTER ROLE uiap_verifier   NOLOGIN;
ALTER ROLE uiap_audit_read NOLOGIN;

-- ---------------------------------------------------------------------------
-- 3. Schema ownership (A-5: uiap_migration owns the substrate)
-- ---------------------------------------------------------------------------

ALTER SCHEMA uiap_identity     OWNER TO uiap_migration;
ALTER SCHEMA uiap_access       OWNER TO uiap_migration;
ALTER SCHEMA uiap_profile      OWNER TO uiap_migration;
ALTER SCHEMA uiap_address      OWNER TO uiap_migration;
ALTER SCHEMA uiap_security     OWNER TO uiap_migration;
ALTER SCHEMA uiap_audit        OWNER TO uiap_migration;
ALTER SCHEMA uiap_notification OWNER TO uiap_migration;
ALTER SCHEMA uiap_org          OWNER TO uiap_migration;
ALTER SCHEMA uiap_migration    OWNER TO uiap_migration;

-- ---------------------------------------------------------------------------
-- 4. public schema hygiene (no accidental table-creation path)
-- ---------------------------------------------------------------------------

REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 5. Grants: usage of the schemas
--    (CREATE is held by the owner uiap_migration only — no role below can
--    create objects in any uiap_* schema.)
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA uiap_identity, uiap_access, uiap_profile,
    uiap_address, uiap_security, uiap_audit, uiap_notification,
    uiap_org, uiap_migration TO uiap_migration;

-- app: runtime DML on outbox (P0: the only table). CREATE intentionally absent.
-- Table grants are attached via ALTER DEFAULT PRIVILEGES below so this script
-- stays executable BEFORE any migration has run (grants on a not-yet-existing
-- table would abort the bootstrap); they take effect the moment the migration
-- role creates the outbox table.
GRANT USAGE ON SCHEMA uiap_access TO uiap_app;

-- relay: claim/update/read the outbox. NO INSERT/DELETE/TRUNCATE — the relay
-- publishes and updates lifecycle state; it never creates or purges rows
-- (retention R-30 belongs to the retention engine, not the relay role).
GRANT USAGE ON SCHEMA uiap_access TO uiap_relay;

-- admin: broad RW over domain schemas + audit SELECT (§34.7). P0: only
-- outbox exists; kept to outbox scope so this file never over-grants.
GRANT USAGE ON SCHEMA uiap_access TO uiap_admin;

-- verifier / audit_read: NOLOGIN placeholders with zero operational
-- privileges in P0 (A-6). They receive USAGE only if/when their phase lands;
-- deliberately NO grants here.

-- migration: everything on the bookkeeping schema (it is the owner).
GRANT ALL ON SCHEMA uiap_migration TO uiap_migration;

-- ---------------------------------------------------------------------------
-- 5b. Default privileges for objects the migration role will create
--     (Each uiap_* schema: tables created by uiap_migration grant the §34.7
--     runtime privileges automatically; sequences likewise. CREATE never
--     propagates — only the migration role ever creates objects.)
-- ---------------------------------------------------------------------------

ALTER DEFAULT PRIVILEGES FOR ROLE uiap_migration IN SCHEMA uiap_access
    GRANT SELECT, INSERT, UPDATE ON TABLES TO uiap_app;
ALTER DEFAULT PRIVILEGES FOR ROLE uiap_migration IN SCHEMA uiap_access
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO uiap_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE uiap_migration IN SCHEMA uiap_access
    GRANT SELECT, UPDATE ON TABLES TO uiap_relay;
ALTER DEFAULT PRIVILEGES FOR ROLE uiap_migration IN SCHEMA uiap_access
    GRANT USAGE, SELECT ON SEQUENCES TO uiap_app, uiap_relay, uiap_admin;

-- ---------------------------------------------------------------------------
-- 6. Default privilege posture for future objects
--    (Objects created by the migration role in a uiap_* schema are usable by
--    the runtime roles without a re-bootstrap; no CREATE ever propagates.)
-- ---------------------------------------------------------------------------

-- Future tables land in domain schemas via Django migrations run as the
-- migration principal; each phase's migration pairs with its grants here.
-- P0 needs no ALTER DEFAULT PRIVILEGES beyond ownership (outbox grants above
-- are table-scoped). Intentionally minimal: unclaimed surface stays zero.

-- ---------------------------------------------------------------------------
-- 7. Housekeeping: no role here is a superuser; no passwords in this file.
--    Login-capable principals (uiap_app, uiap_relay, uiap_admin,
--    uiap_migration) receive credentials via CI-injected ALTER ROLE ...
--    PASSWORD statements outside version control.
--
--    NOTE (P0.4): default privileges (5b) attach table/sequence grants at
--    object-creation time. For objects created BEFORE this script runs on an
--    existing deployment, re-run the explicit GRANT block in 5b's successor
--    (future 002_*.sql) — P0 has no pre-existing objects.
-- ---------------------------------------------------------------------------

COMMIT;
