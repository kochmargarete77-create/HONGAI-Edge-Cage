# HONG AI Edge Cage

Cross-platform, fail-closed isolation and delivery controller for the official Claude Code CLI.

HONG AI Edge Cage is a secondary development of [ClaudeCage](https://github.com/PACHAKUTlQ/ClaudeCage). The supported alpha delivery path targets Windows and macOS with Anthropic Sandbox Runtime, a customer-authorized Clash chain and a continuously verified final exit. The upstream portable Linux backend is retained as an experimental compatibility path, not as an accepted HONG AI customer deployment.

## Current alpha capabilities

- Strict customer YAML schema.
- Pinned official Claude Code binary (`2.1.330`).
- Pinned Anthropic Sandbox Runtime (`0.0.83`).
- OS-native process-tree filesystem and network isolation.
- Separate `HOME`, `USERPROFILE` and `CLAUDE_CONFIG_DIR` per environment.
- Strict destination allowlist and private-address denial.
- Loopback parent proxy into customer Clash.
- Idempotent Clash.Meta global-script generator with no `DIRECT` fallback.
- Repeated final-exit preflight and runtime exit watchdog.
- Windows WFP provisioning scripts and macOS Seatbelt launch scripts.
- HONG AI hard-gate acceptance matrix.
- Minimal customer-intake compiler that expands front-hop/final-exit fields into a full strict policy.
- Loopback-only HONG AI control room that distinguishes configured policy, observed preflight and actual runtime state.
- Encrypted GitHub Release delivery with signed artifact identity, revocable long-lived licenses and single-use tokens.
- Cross-process authorization-store locking and an idempotent, monotonic delivery-receipt state machine.
- Encrypted, retryable delivery-receipt outbox that never stores the receipt token in plaintext on disk.
- Verified retrieval, collision-safe source extraction, staging-first platform installers, and failure cleanup.
- Clean-tree deterministic source release builder with commit/tree/blob/hash build records and D:/E: output enforcement on Windows.
- Allowlisted host environment with isolated AppData/XDG/npm/Git/GnuPG state.

## Safety invariant

If the configured local proxy is down, the final IPv4 is missing or different, the target platform is wrong, or the system time zone does not match the configured exit, the official Claude Code process is not started. If the exit later disappears or changes, the running session is terminated. There is no direct-network fallback in the generated Claude route group.

## Development

```powershell
npm ci --fund=false --audit=false
npm run check
npm test
npm run build
node dist/src/cli.js validate --config config/customer.example.yaml
node dist/src/cli.js init --config config/intake.example.yaml --output config/customer.local.yaml
```

Read [deployment](docs/DEPLOYMENT.md), [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY-MODEL.md), [isolation tiers](docs/ISOLATION-TIERS.md), [secure delivery](docs/SECURE-DELIVERY.md), [license-service operations](docs/LICENSE-SERVICE.md), [release preparation](docs/RELEASE-PROCESS.md), and the [acceptance matrix](docs/ACCEPTANCE-MATRIX.md) before testing on a customer device.

## Status

`0.2.0-alpha.4` adds architecture-native offline pilot payloads, resumable one-time activation, transactional placement, rollback/doctor entry points, and redacted support bundles. It is an unsigned, operator-controlled pilot—not yet a notarized or Authenticode-signed self-service installer. Do not represent it as an Anthropic product, certification, or official network score. Each end user authenticates to the unmodified official Claude Code flow with credentials they control.

## License and attribution

This repository remains AGPL-3.0. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). Dependencies retain their own licenses and terms.
