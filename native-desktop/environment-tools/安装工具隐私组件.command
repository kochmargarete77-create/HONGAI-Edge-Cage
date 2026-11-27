#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ ! -f request.json ]]; then
  printf '%s\n' 'Prepare the approved local request.json first. No changes were made.' >&2
  exit 2
fi
exec ./hongai-tools install --request "$PWD/request.json"
