#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
printf '%s\n' '[HONG AI] This is a terminal action. Continue only after recovery has been deliberately abandoned.'
"$ROOT/abandon-delivery.sh"
STATUS=$?

printf '\n'
if [ "$STATUS" -eq 0 ]; then
  printf '%s\n' '[HONG AI] Explicit abandonment completed or was durably queued.'
else
  printf '[HONG AI] Nothing was abandoned; command stopped with exit code %s.\n' "$STATUS"
fi
printf '%s' 'Press Return to close this window: '
IFS= read -r _answer || true
exit "$STATUS"
