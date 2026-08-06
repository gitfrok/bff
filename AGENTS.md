# AGENTS.md — bff (Backend-for-Frontend, aggregation only)

Depends on **governance** (`contracts/`) and **backend** (gRPC). Read `../governance/AGENTS.md`
and `../governance/docs/` first; obey invariants 1–25.

## Strict
- **No business logic** — aggregation/shaping/auth-context only (invariant 18).
- Calls `backend` over gRPC using `../governance/contracts/`; never imports backend internals.
- Serves the shaped API consumed by `webfrontend`. `webfrontend` never bypasses the BFF to reach backend.
- **TDD**; contract tests against `../governance/contracts/`; no direct DB access.
- **AuthZ**: ask `internal/pep`, never decide. There is no place in this repo where an inline
  permission check is correct — the `inline-permission-check` fitness function fails the build over
  one, with a `//arch:allow-inline-authz <reason>` waiver for the rare false positive (invariant 2,
  ADR-0006). Guard *before* the read, not after: see `internal/aggregate`. Decisions are cached and
  invalidated by policy revision; the TTL only bounds staleness of a subject's roles.
