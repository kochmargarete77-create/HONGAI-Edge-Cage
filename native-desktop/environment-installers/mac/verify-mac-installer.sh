#!/bin/bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
exec /usr/bin/env python3 "$script_dir/mac_installer.py" verify "$@"
