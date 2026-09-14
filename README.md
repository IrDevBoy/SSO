# UIAP — Unified Identity & Access Platform

The central Identity Provider (IdP) for the product portfolio: identity, credentials,
authentication, authorization, profiles, devices & sessions, step-up security, risk,
recovery, notifications, tamper-evident audit, consent, organizations, and service
identities — built as a **modular monolith** per the frozen architecture specification.

## Source of Truth

| Item | Value |
|---|---|
| Architecture document | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Architecture baseline | **v1.0.1** (final, consolidated) |
| Architecture status | **Approved — Frozen** (changes only via the §57 ADR process / §61.2 change protocol) |
| Repository baseline tag | `arch-v1.0.1` |

## Current Phase

**Phase 0 — walking skeleton.**

Phase 0 delivers infrastructure and mechanism foundations only — project bootstrap,
configuration, database schemas/roles, module-boundary enforcement, health/readiness,
outbox mechanism, CI gates, conformance harness wiring, container/manifests — and
contains **zero domain features** (no authentication, tokens, sessions, consent, or any
identity-domain behavior).

## Status: Architecture vs. Implementation

This repository is at the **repository baseline** stage (tag `arch-v1.0.1`). The
distinction between what the architecture requires and what exists here today:

| Area | Architecture requirement (ARCHITECTURE.md) | Repository status |
|---|---|---|
| Architecture document | Single source of truth, v1.0.1, frozen | **Present** (`ARCHITECTURE.md`) |
| Module skeleton (contexts/, core/, workers/, relay/, verifier/, tests/, deploy/) | Bounded contexts per §9.1, supporting processes per §8.2 | **Present as empty placeholders** (no code) |
| Django project bootstrap (App. A: Django 5.2 LTS, DRF, Python 3.13) | Required | **Not implemented** |
| PostgreSQL 17 schemas + roles (§34.2/§34.7) | Required | **Not implemented** |
| Outbox + relay + verifier mechanisms (§29.4, §28.4) | Required | **Not implemented** |
| Health/readiness endpoints (§45.6) | Required | **Not implemented** |
| CI gates, conformance harness (§51.2, §51.4, §60.1) | Required, wired from Phase 0 | **Not implemented** |
| Container / Kubernetes manifests (§54) | Required | **Not implemented** |
| Domain features (identity, credentials, OAuth/OIDC, …) | Phase 1+ per §60 | **Not started** (by design) |

Nothing in this README claims implementation that does not yet exist. Phase 0 progress
is tracked against its exit-gate criteria; no roadmap beyond the current baseline is
maintained here.

## Documents

- `ARCHITECTURE.md` — the architecture specification (normative; appendices A–I include
  the ADR record §57, review history, and finalization dispositions).
- `PROJECT_FLOWCHART.png` / `PROJECT_FLOWCHART.gv` — rendered architecture flowchart
  (source + image; regenerate with Graphviz: `dot -Tpng -Gdpi=150 PROJECT_FLOWCHART.gv -o PROJECT_FLOWCHART.png`).
- `.env.example` — **non-secret** configuration template. Copy to `.env` for local use;
  `.env` is git-ignored and never committed (§41.4 secrets hygiene).
