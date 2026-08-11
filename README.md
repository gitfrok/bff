# bff

Go Backend-for-Frontend, aggregation only. Scaffolded by **T-0001**. See `AGENTS.md`.

## The session store

The browser session is an opaque identifier in a `__Host-` cookie, resolved server-side on every
request (ADR-0049). Two stores implement it, chosen by `GITFROK_SESSION_STORE`:

```
GITFROK_SESSION_STORE=memory                      # default; sessions die with the process
GITFROK_SESSION_STORE=valkey                      # shared, survives restarts and spans replicas
GITFROK_SESSION_VALKEY_ADDR=valkey:6379           # required with valkey
GITFROK_SESSION_VALKEY_PASSWORD=…                 # optional
```

**A configured store that cannot be reached is fatal at startup** (ADR-0052 decision 4). Falling back
to memory would leave the process looking healthy while logging every user out on the next rollout,
and nothing in a response would say why.

This is the **only** datastore the BFF may open. `internal/arch`'s `bff-direct-datastore` rule fails
the build on any other cache or database client, anywhere in the tree, and the exemption here needs
both the path (`internal/session/`) and the marker `//arch:allow-session-store <reason>` — ADR-0052.
A session is the BFF's own state; reading anything else through that client is the cross-context
access invariant 15 forbids.

The Valkey suite runs against a real server and skips without one, because a test that quietly passes
without its infrastructure is evidence of nothing:

```bash
podman run -d --rm -p 16379:6379 docker.io/valkey/valkey:9.1.1
GITFROK_TEST_VALKEY_ADDR=127.0.0.1:16379 go test ./internal/session/ -count=1
```

## Authorization

The BFF asks `internal/pep`; it never decides (invariant 2, ADR-0006). `internal/arch`'s
`inline-permission-check` rule fails the build on authorization logic here — waive a line with
`//arch:allow-inline-authz <reason>` only when it genuinely grants nothing.
