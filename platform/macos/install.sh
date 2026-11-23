#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This installer is for macOS only." >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CONFIG_PATH=${1:-"$PROJECT_ROOT/config/customer.macos.example.yaml"}
[ -f "$CONFIG_PATH" ] || { echo "Customer config does not exist: $CONFIG_PATH" >&2; exit 1; }
CONFIG_DIR=$(cd "$(dirname "$CONFIG_PATH")" && pwd -P)
CONFIG_PATH="$CONFIG_DIR/$(basename "$CONFIG_PATH")"

command -v node >/dev/null 2>&1 || { echo "Node.js 24 or newer is required." >&2; exit 1; }
NODE_MAJOR=$(node -p "Number(process.versions.node.split('.')[0])")
[ "$NODE_MAJOR" -ge 24 ] || { echo "Node.js 24 or newer is required." >&2; exit 1; }

export npm_config_cache="$PROJECT_ROOT/.npm-cache"
export TMPDIR="$PROJECT_ROOT/.tmp"
mkdir -p "$npm_config_cache" "$TMPDIR"

cd "$PROJECT_ROOT"
npm ci --fund=false --audit=false
npm run build
node dist/src/cli.js validate --config "$CONFIG_PATH"
node dist/src/cli.js doctor --config "$CONFIG_PATH"
echo "HONG AI Edge Cage installation and preflight completed."
