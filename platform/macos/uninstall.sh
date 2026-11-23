#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"
PROJECT_ROOT=$(hongai_project_root "$0")
REMOVE_PROGRAM=0
CURRENT_LINK=''

while [ "$#" -gt 0 ]; do
  case "$1" in
    --remove-program) REMOVE_PROGRAM=1 ;;
    --current-link)
      [ "$#" -ge 2 ] || { echo "Missing value for --current-link" >&2; exit 2; }
      CURRENT_LINK=$2
      shift
      ;;
    *) echo "Usage: uninstall.sh [--current-link /absolute/current] [--remove-program]" >&2; exit 2 ;;
  esac
  shift
done

ARCH=$(hongai_architecture)
NODE=$(hongai_require_offline_payload "$PROJECT_ROOT" "$ARCH")
hongai_verify_versions "$PROJECT_ROOT" "$NODE" >/dev/null
hongai_verify_install_marker "$PROJECT_ROOT" "$NODE"

if [ -n "$CURRENT_LINK" ]; then
  case "$CURRENT_LINK" in /*) ;; *) hongai_fail "--current-link must be absolute"; exit 1 ;; esac
  if [ -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
    hongai_fail "refusing to alter a current path that is not a symbolic link: $CURRENT_LINK"
    exit 1
  fi
  if [ -L "$CURRENT_LINK" ]; then
    RESOLVED_TARGET=$(hongai_resolve_link_target "$CURRENT_LINK")
    if [ "$RESOLVED_TARGET" = "$PROJECT_ROOT" ]; then
      rm -f -- "$CURRENT_LINK"
    else
      hongai_fail "refusing to remove a current link that points to another installation: $RESOLVED_TARGET"
      exit 1
    fi
  fi
fi

echo "macOS uses per-process Seatbelt policies; no system sandbox account or WFP filter was installed."
echo "The HONG AI Edge Cage customer state is intentionally preserved for backup or later reinstallation."

if [ "$REMOVE_PROGRAM" -eq 1 ]; then
  case "$PROJECT_ROOT" in
    /|/Applications|/Users|/Users/Shared|/Library|/System|/System/Volumes|/private|/var|/usr|/usr/local|/opt|/tmp|"${HOME:-/nonexistent}")
      hongai_fail "refusing to remove unsafe installation root: $PROJECT_ROOT"
      exit 1
      ;;
  esac
  PARENT=$(dirname -- "$PROJECT_ROOT")
  BASE=$(basename -- "$PROJECT_ROOT")
  cd -- "$PARENT"
  rm -rf -- "./$BASE"
  echo "Program files removed from $PROJECT_ROOT; customer workspace and state roots were preserved."
else
  echo "Program files remain at $PROJECT_ROOT. Re-run with --remove-program to remove only this verified installation."
fi
