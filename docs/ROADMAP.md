# Delivery roadmap

## Milestone 0 — safe foundation

- Strict customer configuration schema.
- Repeated proxy-exit preflight.
- Time-zone consistency gate.
- Sandbox Runtime policy generation.
- Configuration and policy unit tests.
- No mutation of host proxy, DNS, routes, TUN, or firewall.

## Milestone 1 — controlled launcher

- Wrap the full official Claude Code process with Sandbox Runtime.
- Confirm direct egress is blocked while the configured parent proxy works.
- Isolate Claude state from the host profile.
- Add clean shutdown, watchdog, and one-command rollback.
- Produce signed Windows x64 and macOS arm64/x64 artifacts.

## Milestone 2 — Clash integration

- Generate an idempotent Clash Verge merge/script pair.
- Create a one-choice Claude fail-closed group with no DIRECT fallback.
- Store landing credentials in Windows Credential Manager or macOS Keychain.
- Verify the runtime configuration and actual connection logs agree.
- Refuse to launch on profile drift or exit mismatch.

## Milestone 3 — commercial delivery

- Guided installer and customer intake screen.
- HONG AI assessment integration and before/after reports.
- Version pinning, SBOM, checksums, and update channel.
- Offline recovery bundle and support diagnostics.
- Windows and macOS acceptance matrix.
