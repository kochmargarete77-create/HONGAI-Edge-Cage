#!/bin/bash
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")" && pwd)"
exec /usr/bin/osascript -l JavaScript "$root/Start-Deployment-Mac.js" "$root" "${1:?Provide absolute deployment-request.json path}" "${2:-check}"
