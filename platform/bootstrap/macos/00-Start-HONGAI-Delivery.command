#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
"$ROOT/start-delivery.sh"
STATUS=$?

printf '\n'
if [ "$STATUS" -eq 0 ]; then
  printf '%s\n' '[HONG AI] Delivery command completed successfully.'
else
  printf '[HONG AI] Delivery stopped with exit code %s.\n' "$STATUS"
fi
printf '%s' 'Press Return to close this window: '
IFS= read -r _answer || true
exit "$STATUS"
