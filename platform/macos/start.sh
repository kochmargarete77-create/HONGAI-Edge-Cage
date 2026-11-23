#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu

if [ "$#" -lt 1 ]; then
  echo "Usage: start.sh /absolute/path/customer.yaml [claude arguments...]" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"
PROJECT_ROOT=$(hongai_project_root "$0")
CONFIG_PATH=$(hongai_absolute_file "$1")
shift
ARCH=$(hongai_architecture)
NODE=$(hongai_require_offline_payload "$PROJECT_ROOT" "$ARCH")
hongai_verify_versions "$PROJECT_ROOT" "$NODE" >/dev/null
hongai_verify_install_marker "$PROJECT_ROOT" "$NODE"
hongai_verify_installed_config "$PROJECT_ROOT" "$NODE" "$CONFIG_PATH"
hongai_prepend_runtime_path "$PROJECT_ROOT"

exec "$NODE" "$PROJECT_ROOT/dist/src/cli.js" launch --config "$CONFIG_PATH" -- "$@"
