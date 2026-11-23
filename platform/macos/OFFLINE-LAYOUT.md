# macOS offline pilot payload contract

The customer package must be prepared before delivery. The macOS installer never invokes npm and never downloads a runtime.

Required paths inside the authenticated delivery archive:

- `dist/src/cli.js` and the remaining compiled `dist/` tree;
- production-only `node_modules/` whose installed Anthropic package versions match `package.json`;
- pinned official Claude Code and Anthropic Sandbox Runtime packages;
- `runtime/bin/node` and `runtime/bin/rg`, both executable on the package architecture;
- `package.json`, portable schema-v2 `HONGAI-DELIVERY.json`, and `HONGAI-PAYLOAD.json` with matching identity, provenance, runtime and dependency versions.

Create separate `arm64` and `x64` packages. The installer uses only the bundled Node and ripgrep, prepends `runtime/bin` to `PATH`, and does not invoke npm, Homebrew or a system Node installation. The outer HONG AI signed artifact manifest remains the integrity root; the installer rechecks product, platform, architecture, version, required dependency identities, disk space, customer configuration and the full `doctor` preflight before it writes an installation marker.

After the shared delivery controller atomically moves staging into a versioned installation root, run `activate.sh <versioned-root> <current-link>`. `rollback.sh <current-link>` validates both installation markers and uses a durable sibling transaction journal while swapping the current and previous links. If the process or Mac stops between the two atomic link replacements, rerun the same rollback command; it verifies the journal-bound payloads and completes the interrupted swap. Code signing and Apple notarization are still required before general customer distribution.
