#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
unset NODE_OPTIONS NODE_PATH NPM_CONFIG_USERCONFIG npm_config_userconfig

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
NODE="$ROOT/runtime/bin/node"
[ -x "$NODE" ] || { echo "Bundled Node runtime is missing: $NODE" >&2; exit 1; }
[ -f "$ROOT/bootstrap-runner.mjs" ] || { echo "Bootstrap runner is missing." >&2; exit 1; }
exec "$NODE" "$ROOT/bootstrap-runner.mjs" abandon
