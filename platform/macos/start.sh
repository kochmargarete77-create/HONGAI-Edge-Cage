#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "Usage: start.sh /absolute/path/customer.yaml [claude arguments...]" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CONFIG_PATH=$1
shift

exec node "$PROJECT_ROOT/dist/src/cli.js" launch --config "$CONFIG_PATH" -- "$@"
