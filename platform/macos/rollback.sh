#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

set -eu
umask 077

if [ "$#" -ne 1 ]; then
  echo "Usage: rollback.sh /absolute/current-link" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
CURRENT_LINK=$1
case "$CURRENT_LINK" in /*) ;; *) hongai_fail "current link must be absolute"; exit 1 ;; esac
CURRENT_PARENT=$(dirname -- "$CURRENT_LINK")
[ -d "$CURRENT_PARENT" ] || { hongai_fail "current link parent is unavailable: $CURRENT_PARENT"; exit 1; }
CURRENT_PARENT=$(CDPATH= cd -- "$CURRENT_PARENT" && pwd -P)
CURRENT_LINK="$CURRENT_PARENT/$(basename -- "$CURRENT_LINK")"
PREVIOUS_LINK="${CURRENT_LINK}.previous"
JOURNAL_PATH="${CURRENT_LINK}.rollback-transaction.json"
[ -L "$CURRENT_LINK" ] || { hongai_fail "current link is missing: $CURRENT_LINK"; exit 1; }
[ -L "$PREVIOUS_LINK" ] || { hongai_fail "previous link is missing: $PREVIOUS_LINK"; exit 1; }

ARCH=$(hongai_architecture)
CURRENT_TARGET=$(hongai_resolve_link_target "$CURRENT_LINK")
CURRENT_NODE=$(hongai_require_offline_payload "$CURRENT_TARGET" "$ARCH")
hongai_verify_versions "$CURRENT_TARGET" "$CURRENT_NODE" >/dev/null
hongai_verify_install_marker "$CURRENT_TARGET" "$CURRENT_NODE"

# A two-link swap cannot be a single filesystem operation. This durable journal
# makes interruption before or after either rename idempotently recoverable.
rollback_transaction() {
  "$CURRENT_NODE" --input-type=commonjs - "$1" "$JOURNAL_PATH" "$CURRENT_LINK" "$PREVIOUS_LINK" "${2:-}" "${3:-}" <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const [action, journalPath, currentLink, previousLink, oldCurrentTarget, oldPreviousTarget] = process.argv.slice(2);
const product = 'HONG AI Edge Cage';

function fail(message) { throw new Error(message); }
function safeAbsolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value)) {
    fail(`${label} is unsafe`);
  }
  return path.resolve(value);
}
function syncParent(value) {
  const descriptor = fs.openSync(path.dirname(value), 'r');
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
function writeState(state) {
  const temporary = `${journalPath}.tmp-${crypto.randomUUID()}`;
  const descriptor = fs.openSync(temporary, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(state, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, journalPath);
  syncParent(journalPath);
}
function readState() {
  const state = JSON.parse(fs.readFileSync(journalPath, 'utf8'));
  if (
    state.schemaVersion !== 1
    || state.product !== product
    || safeAbsolute(state.currentLink, 'journal current link') !== path.resolve(currentLink)
    || safeAbsolute(state.previousLink, 'journal previous link') !== path.resolve(previousLink)
    || typeof state.transactionId !== 'string'
    || !/^[0-9a-f-]{36}$/.test(state.transactionId)
    || !['PREPARED', 'CURRENT_SWITCHED', 'LINKS_SWITCHED'].includes(state.phase)
  ) fail('rollback journal identity is invalid');
  state.oldCurrentTarget = safeAbsolute(state.oldCurrentTarget, 'journal current target');
  state.oldPreviousTarget = safeAbsolute(state.oldPreviousTarget, 'journal previous target');
  if (state.oldCurrentTarget === state.oldPreviousTarget) fail('rollback journal targets are identical');
  for (const [label, target] of [['current', state.oldCurrentTarget], ['previous', state.oldPreviousTarget]]) {
    const metadata = fs.statSync(target);
    if (!metadata.isDirectory()) fail(`rollback ${label} target is not a directory`);
  }
  return state;
}
function replaceLink(link, target, state, suffix) {
  const temporary = `${link}.rollback-${state.transactionId}.${suffix}`;
  try {
    const metadata = fs.lstatSync(temporary);
    if (!metadata.isSymbolicLink()) fail(`unsafe rollback temporary path exists: ${temporary}`);
    fs.unlinkSync(temporary);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  fs.symlinkSync(target, temporary);
  fs.renameSync(temporary, link);
  syncParent(link);
}

if (action === 'inspect') {
  const state = readState();
  process.stdout.write(`${state.oldCurrentTarget}\n${state.oldPreviousTarget}\n`);
  process.exit(0);
}

if (action === 'begin') {
  if (fs.existsSync(journalPath)) fail('rollback journal already exists; recover it before beginning another rollback');
  const currentTarget = safeAbsolute(oldCurrentTarget, 'current target');
  const previousTarget = safeAbsolute(oldPreviousTarget, 'previous target');
  if (currentTarget === previousTarget) fail('current and previous targets are identical');
  writeState({
    schemaVersion: 1,
    product,
    transactionId: crypto.randomUUID(),
    phase: 'PREPARED',
    currentLink: path.resolve(currentLink),
    previousLink: path.resolve(previousLink),
    oldCurrentTarget: currentTarget,
    oldPreviousTarget: previousTarget,
    updatedAt: new Date().toISOString()
  });
} else if (action !== 'apply') {
  fail('unsupported rollback transaction action');
}

const state = readState();
replaceLink(currentLink, state.oldPreviousTarget, state, 'current');
state.phase = 'CURRENT_SWITCHED';
state.updatedAt = new Date().toISOString();
writeState(state);
if (process.env.HONGAI_TEST_ROLLBACK_FAIL_AFTER_CURRENT === '1') {
  fail('injected rollback interruption after current-link switch');
}
replaceLink(previousLink, state.oldCurrentTarget, state, 'previous');
state.phase = 'LINKS_SWITCHED';
state.updatedAt = new Date().toISOString();
writeState(state);
fs.unlinkSync(journalPath);
syncParent(journalPath);
NODE
}

if [ -f "$JOURNAL_PATH" ]; then
  RECOVERY_TARGETS=$(rollback_transaction inspect)
  OLD_CURRENT_TARGET=$(printf '%s\n' "$RECOVERY_TARGETS" | sed -n '1p')
  OLD_PREVIOUS_TARGET=$(printf '%s\n' "$RECOVERY_TARGETS" | sed -n '2p')
  [ -n "$OLD_CURRENT_TARGET" ] && [ -n "$OLD_PREVIOUS_TARGET" ] || {
    hongai_fail "rollback journal did not contain two valid targets"
    exit 1
  }
else
  OLD_CURRENT_TARGET=$CURRENT_TARGET
  OLD_PREVIOUS_TARGET=$(hongai_resolve_link_target "$PREVIOUS_LINK")
  [ "$OLD_CURRENT_TARGET" != "$OLD_PREVIOUS_TARGET" ] || {
    hongai_fail "current and previous links resolve to the same installation"
    exit 1
  }
fi

OLD_CURRENT_NODE=$(hongai_require_offline_payload "$OLD_CURRENT_TARGET" "$ARCH")
hongai_verify_versions "$OLD_CURRENT_TARGET" "$OLD_CURRENT_NODE" >/dev/null
hongai_verify_install_marker "$OLD_CURRENT_TARGET" "$OLD_CURRENT_NODE"
OLD_PREVIOUS_NODE=$(hongai_require_offline_payload "$OLD_PREVIOUS_TARGET" "$ARCH")
hongai_verify_versions "$OLD_PREVIOUS_TARGET" "$OLD_PREVIOUS_NODE" >/dev/null
hongai_verify_install_marker "$OLD_PREVIOUS_TARGET" "$OLD_PREVIOUS_NODE"

if [ -f "$JOURNAL_PATH" ]; then
  rollback_transaction apply
  ACTION=Recovered
else
  rollback_transaction begin "$OLD_CURRENT_TARGET" "$OLD_PREVIOUS_TARGET"
  ACTION='Rolled back'
fi

NEW_CURRENT_TARGET=$(hongai_resolve_link_target "$CURRENT_LINK")
NEW_PREVIOUS_TARGET=$(hongai_resolve_link_target "$PREVIOUS_LINK")
[ "$NEW_CURRENT_TARGET" = "$OLD_PREVIOUS_TARGET" ] && [ "$NEW_PREVIOUS_TARGET" = "$OLD_CURRENT_TARGET" ] || {
  hongai_fail "rollback transaction completed with an unexpected link state"
  exit 1
}
echo "$ACTION $CURRENT_LINK to $OLD_PREVIOUS_TARGET"
