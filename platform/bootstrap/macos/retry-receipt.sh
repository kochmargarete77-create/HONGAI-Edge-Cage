#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
unset NODE_OPTIONS NODE_PATH NPM_CONFIG_USERCONFIG npm_config_userconfig

[ "$#" -le 1 ] || { echo "Usage: retry-receipt.sh [absolute-pending-receipt]" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
NODE="$ROOT/runtime/bin/node"
[ -x "$NODE" ] || { echo "Bundled Node runtime is missing: $NODE" >&2; exit 1; }
[ -f "$ROOT/bootstrap-runner.mjs" ] || { echo "Bootstrap runner is missing." >&2; exit 1; }
if [ "$#" -eq 1 ]; then
  exec "$NODE" "$ROOT/bootstrap-runner.mjs" receipt "$1"
fi
exec "$NODE" "$ROOT/bootstrap-runner.mjs" receipt
