#!/usr/bin/env bash
# T-0021 AC2/AC3: build and assert the ADR-0035 posture for the BFF image.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
file="$root/Dockerfile"
[ -f "$file" ] || { echo "container-image: FAIL — missing Dockerfile" >&2; exit 1; }

runtime=${CONTAINER_RUNTIME:-}
if [ -z "$runtime" ]; then
  if command -v docker >/dev/null; then
    runtime=docker
  elif command -v podman >/dev/null; then
    runtime=podman
  else
    echo "container-image: neither docker nor podman is available" >&2
    exit 2
  fi
fi

image=localhost/gitfrok-bff:test
"$runtime" build --file "$file" --tag "$image" "$root"

user=$("$runtime" image inspect "$image" --format '{{.Config.User}}')
[ "$user" = "65532:65532" ] || { echo "container-image: FAIL — user is '$user'" >&2; exit 1; }

cmd=$("$runtime" image inspect "$image" --format '{{json .Config.Cmd}}')
[ "$cmd" = '["/bff"]' ] || { echo "container-image: FAIL — command is '$cmd'" >&2; exit 1; }

if "$runtime" run --rm "$image" /bin/sh >/dev/null 2>&1; then
  echo "container-image: FAIL — image unexpectedly contains /bin/sh" >&2
  exit 1
fi

# grpc.NewClient is non-blocking; the dummy addresses let the binary reach its normal startup path
# without a live dataplane or reader while proving its root filesystem need not be writable. The
# BFF requires all three since T-0015: without a PDP it cannot authorize, without RepositoryReader
# the browser has no data, and without a listen address it has nowhere to serve (invariant 13).
# The server runs until stopped, so the container runs detached and is stopped after it proves
# it came up.
name=bff-posture-test
"$runtime" rm -f "$name" >/dev/null 2>&1 || true
if ! "$runtime" run --detach --rm --read-only --name "$name" \
  -e GITFROK_PDP_ADDR=127.0.0.1:1 \
  -e GITFROK_REPOSITORY_READER_ADDR=127.0.0.1:1 \
  -e GITFROK_BFF_LISTEN_ADDR=127.0.0.1:18080 \
  "$image" >/dev/null; then
  echo "container-image: FAIL — BFF did not start with a read-only root filesystem" >&2
  exit 1
fi
# Give the server a moment to bind its listener, then confirm it is still running —
# a binary that exited non-zero after startup would fail here.
sleep 1
if ! "$runtime" inspect --format '{{.State.Running}}' "$name" | grep -q true; then
  echo "container-image: FAIL — BFF exited after startup" >&2
  "$runtime" rm -f "$name" >/dev/null 2>&1 || true
  exit 1
fi
"$runtime" stop "$name" >/dev/null 2>&1 || true
echo "container-image: OK"
