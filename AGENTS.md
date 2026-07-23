# AGENTS.md — bff (Backend-for-Frontend, aggregation only)

Depends on **governance** (`contracts/`) and **backend** (gRPC). Read `../governance/AGENTS.md`
and `../governance/docs/` first; obey invariants 1–25.

## Strict
- **No business logic** — aggregation/shaping/auth-context only (invariant 18).
- Calls `backend` over gRPC using `../governance/contracts/`; never imports backend internals.
- Serves the shaped API consumed by `webfrontend`. `webfrontend` never bypasses the BFF to reach backend.
- **TDD**; contract tests against `../governance/contracts/`; no direct DB access.
