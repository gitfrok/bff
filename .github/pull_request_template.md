# bff PR

SoT & governance checklists: `../governance/docs/process/definition-of-done.md`.

## BFF-specific gates
- [ ] **No business logic** — aggregation/shaping/auth-context only (invariant 18).
- [ ] Calls `backend` via `governance/contracts/`; no backend internals imported.
- [ ] Tests first: unit + contract tests against `governance/contracts/`.
- [ ] No direct DB access. Single submodule; governance-first for any contract change.
