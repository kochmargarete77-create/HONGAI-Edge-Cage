# Delivery roadmap

状态说明：`[x]` 已在 alpha 实现并有自动测试；`[ ]` 仍是正式交付门槛。

## Milestone 0 — safe foundation

- [x] Strict customer configuration schema.
- [x] Repeated proxy-exit preflight.
- [x] Time-zone consistency gate.
- [x] Sandbox Runtime policy generation.
- [x] Configuration and policy unit tests.
- [x] No mutation of host proxy, DNS, routes, TUN, or firewall.

## Milestone 1 — controlled launcher

- [x] Wrap the official Claude Code process with Sandbox Runtime.
- [x] Isolate Claude state from the host profile.
- [x] Add repeated final-exit watchdog and process-tree termination.
- [ ] Prove allowed parent-proxy egress and denied IPv4/IPv6/UDP/private/loopback paths in privileged per-OS E2E tests.
- [ ] Add ownership-aware Windows WFP rollback and full uninstall transaction.
- [ ] Produce signed Windows x64 and macOS arm64/x64 artifacts.

## Milestone 2 — Clash integration

- [x] Generate an idempotent Clash Verge merge/script pair.
- [x] Create a one-choice Claude fail-closed group with no DIRECT fallback.
- [x] Refuse to launch on exit mismatch.
- [ ] Store landing credentials in Windows Credential Manager or macOS Keychain.
- [ ] Cross-check runtime Clash connection logs against the intended chain.
- [ ] Refuse to launch on profile/script drift.

## Milestone 3 — commercial delivery

- [x] Encrypted GitHub Release protocol, single-use token, revocation and signed artifact descriptor.
- [x] Cross-process authorization-store serialization and idempotent receipt state machine.
- [x] Archive path/type/collision/expanded-size validation and staging-first source deployment.
- [x] Deterministic clean-tree source builder with commit/tree/blob/hash build records.
- [x] Encrypted persistent receipt outbox with explicit pending state and authenticated retry.
- [ ] Migrate the JSON authorization store to SQLite WAL or PostgreSQL with schema migrations.
- [ ] Add signed off-site audit checkpoints, backup/restore drills and key rotation.
- [ ] Add reproducible Release workflow, SBOM, provenance, protected approval and immutable asset verification.
- [ ] Replace online `npm ci` with prebuilt offline signed installers.
- [ ] Add resumable activation lease and partial-download recovery.
- [ ] Add guided installer, customer intake UI, recovery bundle and support diagnostics.
- [ ] Complete Windows/macOS clean-VM acceptance matrix and fault-injection suite.
