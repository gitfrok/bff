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

# grpc.NewClient is non-blocking; the dummy address lets the binary reach its normal startup path
# without a live dataplane while proving its root filesystem need not be writable.
"$runtime" run --rm --read-only -e GITFROK_PDP_ADDR=127.0.0.1:1 "$image" >/dev/null
echo "container-image: OK"
