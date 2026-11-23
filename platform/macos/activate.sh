#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
umask 077

if [ "$#" -ne 2 ]; then
  echo "Usage: activate.sh /absolute/versioned-install-root /absolute/current-link" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
INSTALL_ROOT=$1
CURRENT_LINK=$2
case "$INSTALL_ROOT:$CURRENT_LINK" in /*:/*) ;; *) hongai_fail "install root and current link must be absolute"; exit 1 ;; esac
[ -d "$INSTALL_ROOT" ] || { hongai_fail "installation does not exist: $INSTALL_ROOT"; exit 1; }
INSTALL_ROOT=$(CDPATH= cd -- "$INSTALL_ROOT" && pwd -P)
CURRENT_PARENT=$(dirname -- "$CURRENT_LINK")
mkdir -p -- "$CURRENT_PARENT"
CURRENT_PARENT=$(CDPATH= cd -- "$CURRENT_PARENT" && pwd -P)
CURRENT_LINK="$CURRENT_PARENT/$(basename -- "$CURRENT_LINK")"
PREVIOUS_LINK="${CURRENT_LINK}.previous"

ARCH=$(hongai_architecture)
NODE=$(hongai_require_offline_payload "$INSTALL_ROOT" "$ARCH")
hongai_verify_versions "$INSTALL_ROOT" "$NODE" >/dev/null
hongai_verify_install_marker "$INSTALL_ROOT" "$NODE"

if { [ -e "$CURRENT_LINK" ] || [ -L "$CURRENT_LINK" ]; } && [ ! -L "$CURRENT_LINK" ]; then
  hongai_fail "current path exists and is not a symbolic link: $CURRENT_LINK"
  exit 1
fi
if { [ -e "$PREVIOUS_LINK" ] || [ -L "$PREVIOUS_LINK" ]; } && [ ! -L "$PREVIOUS_LINK" ]; then
  hongai_fail "previous path exists and is not a symbolic link: $PREVIOUS_LINK"
  exit 1
fi

PREVIOUS_TARGET=''
if [ -L "$CURRENT_LINK" ]; then
  PREVIOUS_TARGET=$(hongai_resolve_link_target "$CURRENT_LINK")
  if [ "$PREVIOUS_TARGET" = "$INSTALL_ROOT" ]; then
    echo "HONG AI Edge Cage is already active at $INSTALL_ROOT"
    exit 0
  fi
fi

CURRENT_TMP="${CURRENT_LINK}.tmp.$$"
PREVIOUS_TMP="${PREVIOUS_LINK}.tmp.$$"
if [ -e "$CURRENT_TMP" ] || [ -L "$CURRENT_TMP" ] || [ -e "$PREVIOUS_TMP" ] || [ -L "$PREVIOUS_TMP" ]; then
  hongai_fail "temporary activation path already exists; retry after inspecting $CURRENT_PARENT"
  exit 1
fi
cleanup() {
  rm -f -- "$CURRENT_TMP" "$PREVIOUS_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ln -s -- "$INSTALL_ROOT" "$CURRENT_TMP"
if [ -n "$PREVIOUS_TARGET" ]; then
  ln -s -- "$PREVIOUS_TARGET" "$PREVIOUS_TMP"
  mv -f -h -- "$PREVIOUS_TMP" "$PREVIOUS_LINK"
elif [ -L "$PREVIOUS_LINK" ]; then
  rm -f -- "$PREVIOUS_LINK"
fi
mv -f -h -- "$CURRENT_TMP" "$CURRENT_LINK"
trap - EXIT HUP INT TERM
echo "Activated $INSTALL_ROOT via $CURRENT_LINK"
