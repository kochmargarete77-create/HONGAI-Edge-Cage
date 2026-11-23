#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
umask 077

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This installer is for macOS only." >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"
PROJECT_ROOT=$(hongai_project_root "$0")
CONFIG_PATH=${1:-"$PROJECT_ROOT/config/customer.macos.example.yaml"}
CONFIG_PATH=$(hongai_absolute_file "$CONFIG_PATH")
ARCH=$(hongai_architecture)
hongai_require_customer_user
[ -w "$PROJECT_ROOT" ] || { hongai_fail "installation staging root is not writable: $PROJECT_ROOT"; exit 1; }
hongai_require_free_space "$PROJECT_ROOT" 1048576
NODE=$(hongai_require_offline_payload "$PROJECT_ROOT" "$ARCH")
VERSION=$(hongai_verify_versions "$PROJECT_ROOT" "$NODE")
hongai_prepend_runtime_path "$PROJECT_ROOT"

PROJECT_PARENT=$(dirname -- "$PROJECT_ROOT")
INSTALL_TMP=$(mktemp -d "$PROJECT_PARENT/.hongai-install-tmp.XXXXXX")
MARKER_TMP="$INSTALL_TMP/.hongai-install.json.tmp"
cleanup() {
  rm -rf -- "$INSTALL_TMP"
  rm -f -- "$MARKER_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "$INSTALL_TMP"

export TMPDIR="$INSTALL_TMP"
export XDG_CACHE_HOME="$INSTALL_TMP/cache"
export XDG_CONFIG_HOME="$INSTALL_TMP/config"
export XDG_DATA_HOME="$INSTALL_TMP/data"
mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"

"$NODE" "$PROJECT_ROOT/dist/src/cli.js" validate --config "$CONFIG_PATH"
"$NODE" "$PROJECT_ROOT/dist/src/cli.js" doctor --config "$CONFIG_PATH"

"$NODE" --input-type=commonjs - "$MARKER_TMP" "$VERSION" "$ARCH" "$CONFIG_PATH" <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const marker = {
  schemaVersion: 1,
  product: 'HONG AI Edge Cage',
  platform: 'macos',
  version: process.argv[3],
  architecture: process.argv[4],
  configSha256: crypto.createHash('sha256').update(fs.readFileSync(process.argv[5])).digest('hex'),
  verifiedAt: new Date().toISOString()
};
fs.writeFileSync(process.argv[2], `${JSON.stringify(marker, null, 2)}\n`, { mode: 0o600, flag: 'w' });
NODE
mv -f -- "$MARKER_TMP" "$PROJECT_ROOT/.hongai-install.json"
echo "HONG AI Edge Cage $VERSION offline payload and preflight completed for macOS $ARCH."
