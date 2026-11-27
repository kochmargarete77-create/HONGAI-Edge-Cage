#!/bin/sh
set -eu
case "$0" in
  /*) hongai_entry=$0 ;;
  *) hongai_entry=$PWD/$0 ;;
esac
package_dir=$(CDPATH= cd -P "$(dirname "$hongai_entry")" && pwd -P)
runtime="$package_dir/hongai-environment"
if [ ! -f "$runtime" ]; then
  printf '%s\n' 'Package incomplete: hongai-environment is missing.' >&2
  printf '%s\n' 'Extract the complete package into a local folder before running this entry.' >&2
  exit 2
fi
if [ ! -x "$runtime" ]; then
  printf '%s\n' 'The archive did not retain the native executable permission.' >&2
  printf '%s\n' 'Use the original complete ZIP and extract it with Archive Utility. No permissions were changed.' >&2
  exit 2
fi
exec "$runtime" environment open "$@"
