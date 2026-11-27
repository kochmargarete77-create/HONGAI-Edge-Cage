#!/bin/bash
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")" && pwd)"
exec /usr/bin/osascript -l JavaScript "$root/Check-Device-Mac.js" "$root" "${1:-NetworkAssessment}" "${2:-NotRequired}"
