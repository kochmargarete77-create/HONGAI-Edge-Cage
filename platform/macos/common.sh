#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

# Shared, POSIX-sh-safe helpers for the macOS pilot package.
# Reject caller-controlled Node startup hooks and package-manager configuration.
# The portable runtime and customer configuration are supplied explicitly.
unset NODE_OPTIONS NODE_PATH NPM_CONFIG_USERCONFIG npm_config_userconfig

hongai_fail() {
  echo "HONG AI Edge Cage: $*" >&2
}

hongai_project_root() {
  HONGAI_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd -P) || return 1
  CDPATH= cd -- "$HONGAI_SCRIPT_DIR/../.." && pwd -P
}

hongai_architecture() {
  case "$(uname -m)" in
    arm64) printf '%s\n' arm64 ;;
    x86_64) printf '%s\n' x64 ;;
    *) hongai_fail "unsupported Mac architecture: $(uname -m)"; return 1 ;;
  esac
}

hongai_absolute_file() {
  HONGAI_INPUT_FILE=$1
  [ -f "$HONGAI_INPUT_FILE" ] || {
    hongai_fail "file does not exist: $HONGAI_INPUT_FILE"
    return 1
  }
  HONGAI_INPUT_DIR=$(CDPATH= cd -- "$(dirname -- "$HONGAI_INPUT_FILE")" && pwd -P) || return 1
  printf '%s/%s\n' "$HONGAI_INPUT_DIR" "$(basename -- "$HONGAI_INPUT_FILE")"
}

hongai_resolve_link_target() {
  HONGAI_LINK_TARGET=$(readlink "$1") || return 1
  case "$HONGAI_LINK_TARGET" in
    /*) ;;
    *) HONGAI_LINK_TARGET="$(dirname -- "$1")/$HONGAI_LINK_TARGET" ;;
  esac
  [ -d "$HONGAI_LINK_TARGET" ] || {
    hongai_fail "symbolic link target is unavailable: $HONGAI_LINK_TARGET"
    return 1
  }
  CDPATH= cd -- "$HONGAI_LINK_TARGET" && pwd -P
}

hongai_require_customer_user() {
  if [ "$(id -u)" -eq 0 ] && [ "${HONGAI_ALLOW_ROOT_INSTALL:-0}" != "1" ]; then
    hongai_fail "run as the customer account, not root; set HONGAI_ALLOW_ROOT_INSTALL=1 only for an isolated test image"
    return 1
  fi
}

hongai_runtime_node() {
  printf '%s/runtime/bin/node\n' "$1"
}

hongai_prepend_runtime_path() {
  HONGAI_RUNTIME_ROOT=$1
  PATH="$HONGAI_RUNTIME_ROOT/runtime/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  export PATH
}

hongai_require_offline_payload() {
  HONGAI_PAYLOAD_ROOT=$1
  HONGAI_EXPECTED_ARCH=$2
  HONGAI_PAYLOAD_NODE=$(hongai_runtime_node "$HONGAI_PAYLOAD_ROOT") || return 1
  HONGAI_PAYLOAD_RG="$HONGAI_PAYLOAD_ROOT/runtime/bin/rg"

  [ -x "$HONGAI_PAYLOAD_NODE" ] || {
    hongai_fail "matching bundled Node runtime is missing or not executable: $HONGAI_PAYLOAD_NODE"
    return 1
  }
  [ -x "$HONGAI_PAYLOAD_RG" ] || {
    hongai_fail "matching bundled ripgrep runtime is missing or not executable: $HONGAI_PAYLOAD_RG"
    return 1
  }
  "$HONGAI_PAYLOAD_RG" --version >/dev/null 2>&1 || {
    hongai_fail "bundled ripgrep cannot execute on this Mac: $HONGAI_PAYLOAD_RG"
    return 1
  }
  [ -f "$HONGAI_PAYLOAD_ROOT/dist/src/cli.js" ] || {
    hongai_fail "prebuilt application is missing dist/src/cli.js"
    return 1
  }
  [ -f "$HONGAI_PAYLOAD_ROOT/node_modules/@anthropic-ai/claude-code/package.json" ] || {
    hongai_fail "the pinned official Claude Code payload is missing"
    return 1
  }
  [ -x "$HONGAI_PAYLOAD_ROOT/node_modules/@anthropic-ai/claude-code/bin/claude" ] || {
    hongai_fail "the executable macOS Claude Code binary is missing"
    return 1
  }
  [ -f "$HONGAI_PAYLOAD_ROOT/node_modules/@anthropic-ai/sandbox-runtime/package.json" ] || {
    hongai_fail "the pinned Anthropic Sandbox Runtime payload is missing"
    return 1
  }
  [ -f "$HONGAI_PAYLOAD_ROOT/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js" ] || {
    hongai_fail "the compiled Sandbox Runtime CLI is missing"
    return 1
  }

  HONGAI_NODE_PLATFORM=$("$HONGAI_PAYLOAD_NODE" -p "process.platform") || return 1
  HONGAI_NODE_ARCH=$("$HONGAI_PAYLOAD_NODE" -p "process.arch") || return 1
  HONGAI_NODE_MAJOR=$("$HONGAI_PAYLOAD_NODE" -p "Number(process.versions.node.split('.')[0])") || return 1
  [ "$HONGAI_NODE_PLATFORM" = "darwin" ] || {
    hongai_fail "bundled runtime reports platform $HONGAI_NODE_PLATFORM instead of darwin"
    return 1
  }
  [ "$HONGAI_NODE_ARCH" = "$HONGAI_EXPECTED_ARCH" ] || {
    hongai_fail "bundled runtime targets $HONGAI_NODE_ARCH but this Mac requires $HONGAI_EXPECTED_ARCH"
    return 1
  }
  case "$HONGAI_NODE_MAJOR" in
    ''|*[!0-9]*) hongai_fail "bundled Node runtime reported an invalid version"; return 1 ;;
  esac
  [ "$HONGAI_NODE_MAJOR" -ge 24 ] || {
    hongai_fail "bundled Node.js 24 or newer is required"
    return 1
  }
  printf '%s\n' "$HONGAI_PAYLOAD_NODE"
}

hongai_require_free_space() {
  HONGAI_DISK_PATH=$1
  HONGAI_MINIMUM_KIB=${2:-1048576}
  HONGAI_AVAILABLE_KIB=$(df -Pk "$HONGAI_DISK_PATH" | awk 'NR == 2 { print $4 }')
  case "$HONGAI_AVAILABLE_KIB" in
    ''|*[!0-9]*) hongai_fail "unable to determine free disk space for $HONGAI_DISK_PATH"; return 1 ;;
  esac
  [ "$HONGAI_AVAILABLE_KIB" -ge "$HONGAI_MINIMUM_KIB" ] || {
    hongai_fail "at least ${HONGAI_MINIMUM_KIB} KiB of free disk space is required"
    return 1
  }
}

hongai_verify_versions() {
  HONGAI_VERSION_ROOT=$1
  HONGAI_VERSION_NODE=$2
  "$HONGAI_VERSION_NODE" --input-type=commonjs - "$HONGAI_VERSION_ROOT" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const delivery = JSON.parse(fs.readFileSync(path.join(root, 'HONGAI-DELIVERY.json'), 'utf8'));
const claudeCode = JSON.parse(fs.readFileSync(
  path.join(root, 'node_modules', '@anthropic-ai', 'claude-code', 'package.json'),
  'utf8'
));
const sandboxRuntime = JSON.parse(fs.readFileSync(
  path.join(root, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'package.json'),
  'utf8'
));
if (pkg.name !== '@hongai/edge-cage' || delivery.product !== 'HONG AI Edge Cage') {
  throw new Error('offline payload identity is invalid');
}
if (pkg.version !== delivery.version) {
  throw new Error('package and delivery versions do not match');
}
if (
  pkg.dependencies?.['@anthropic-ai/claude-code'] !== claudeCode.version
  || pkg.dependencies?.['@anthropic-ai/sandbox-runtime'] !== sandboxRuntime.version
) {
  throw new Error('installed Anthropic dependency versions do not match package.json');
}
if (delivery.schemaVersion === 1 && delivery.bundleType === 'source') {
  if (!Array.isArray(delivery.platforms) || !delivery.platforms.includes('macos')) {
    throw new Error('source delivery payload does not declare macOS support');
  }
} else if (delivery.schemaVersion === 2 && delivery.bundleType === 'portable') {
  if (delivery.platform !== 'macos' || delivery.architecture !== process.arch) {
    throw new Error('portable delivery target does not match this Mac');
  }
  if (
    delivery.runtime?.node !== process.version
    || delivery.runtime?.claudeCode !== claudeCode.version
    || delivery.runtime?.sandboxRuntime !== sandboxRuntime.version
    || delivery.payloadManifest !== 'HONGAI-PAYLOAD.json'
  ) {
    throw new Error('portable runtime versions do not match the delivery manifest');
  }
  const payload = JSON.parse(fs.readFileSync(path.join(root, delivery.payloadManifest), 'utf8'));
  if (
    payload.schemaVersion !== 1
    || payload.product !== 'HONG AI Edge Cage'
    || payload.commitSha !== delivery.commitSha
    || payload.treeSha !== delivery.treeSha
    || !Array.isArray(payload.files)
  ) {
    throw new Error('portable payload manifest does not match the delivery manifest');
  }
  const normalized = new Map();
  const rootPrefix = `${path.resolve(root)}${path.sep}`;
  function safeManifestPath(value) {
    if (
      typeof value !== 'string'
      || !value
      || value.includes('\\')
      || value.startsWith('/')
      || value.split('/').some((part) => !part || part === '.' || part === '..')
    ) throw new Error('portable payload contains an unsafe manifest path');
    const absolute = path.resolve(root, ...value.split('/'));
    if (!absolute.startsWith(rootPrefix)) throw new Error('portable payload manifest path escapes its root');
    return absolute;
  }
  function fileSha256(file) {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(file, 'r');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    try {
      let read;
      while ((read = fs.readSync(fd, chunk, 0, chunk.length, null)) > 0) {
        hash.update(chunk.subarray(0, read));
      }
    } finally {
      fs.closeSync(fd);
      chunk.fill(0);
    }
    return hash.digest('hex');
  }
  for (const entry of payload.files) {
    if (
      !entry
      || typeof entry.bytes !== 'number'
      || !Number.isSafeInteger(entry.bytes)
      || entry.bytes < 0
      || typeof entry.sha256 !== 'string'
      || !/^[a-f0-9]{64}$/.test(entry.sha256)
    ) throw new Error('portable payload manifest has invalid file metadata');
    const absolute = safeManifestPath(entry.path);
    const key = entry.path.toLowerCase();
    if (normalized.has(key)) throw new Error('portable payload manifest contains duplicate paths');
    normalized.set(key, entry.path);
    const metadata = fs.lstatSync(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`portable payload entry is not a regular file: ${entry.path}`);
    }
    if (metadata.size !== entry.bytes || fileSha256(absolute) !== entry.sha256) {
      throw new Error(`portable payload integrity check failed: ${entry.path}`);
    }
  }
  const allowedMutable = new Set(['HONGAI-PAYLOAD.json', '.hongai-install.json']);
  function inspect(directory) {
    for (const name of fs.readdirSync(directory)) {
      const absolute = path.join(directory, name);
      const metadata = fs.lstatSync(absolute);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (metadata.isSymbolicLink()) throw new Error(`portable payload contains a symbolic link: ${relative}`);
      if (metadata.isDirectory()) inspect(absolute);
      else if (!metadata.isFile()) throw new Error(`portable payload contains an unsupported entry: ${relative}`);
      else if (!normalized.has(relative.toLowerCase()) && !allowedMutable.has(relative)) {
        throw new Error(`portable payload contains an undeclared file: ${relative}`);
      }
    }
  }
  inspect(root);
} else {
  throw new Error('delivery manifest schema is unsupported');
}
process.stdout.write(pkg.version);
NODE
}

hongai_verify_install_marker() {
  HONGAI_MARKER_ROOT=$1
  HONGAI_MARKER_NODE=$2
  [ -f "$HONGAI_MARKER_ROOT/.hongai-install.json" ] || {
    hongai_fail "installation marker is missing from $HONGAI_MARKER_ROOT"
    return 1
  }
  "$HONGAI_MARKER_NODE" --input-type=commonjs - "$HONGAI_MARKER_ROOT/.hongai-install.json" "$HONGAI_MARKER_ROOT" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const marker = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (marker.schemaVersion !== 1 || marker.product !== 'HONG AI Edge Cage' || marker.platform !== 'macos') {
  throw new Error('installation marker is invalid');
}
if (typeof marker.configSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(marker.configSha256)) {
  throw new Error('installation marker is missing the bound customer configuration digest');
}
const pkg = JSON.parse(fs.readFileSync(path.join(process.argv[3], 'package.json'), 'utf8'));
if (marker.version !== pkg.version || marker.architecture !== process.arch) {
  throw new Error('installation marker version or architecture does not match this payload');
}
NODE
}

hongai_verify_installed_config() {
  HONGAI_CONFIG_ROOT=$1
  HONGAI_CONFIG_NODE=$2
  HONGAI_CONFIG_PATH=$3
  [ -f "$HONGAI_CONFIG_PATH" ] || {
    hongai_fail "customer configuration is unavailable: $HONGAI_CONFIG_PATH"
    return 1
  }
  "$HONGAI_CONFIG_NODE" --input-type=commonjs - "$HONGAI_CONFIG_ROOT/.hongai-install.json" "$HONGAI_CONFIG_PATH" <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const marker = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const digest = crypto.createHash('sha256').update(fs.readFileSync(process.argv[3])).digest('hex');
if (marker.configSha256 !== digest) {
  throw new Error('customer configuration differs from the configuration verified during installation');
}
NODE
}
