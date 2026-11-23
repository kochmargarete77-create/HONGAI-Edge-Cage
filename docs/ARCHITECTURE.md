# HONG AI Edge Cage architecture

## Product boundary

HONG AI Edge Cage is an isolation, network enforcement, verification, and delivery layer. It does not modify the Claude Code binary and does not intermediate end-user authentication. Each customer authenticates through the official flow with credentials they control.

## Runtime path

```text
Official Claude Code
  -> Anthropic Sandbox Runtime process boundary
  -> Edge Cage loopback proxy
  -> customer-local Clash mixed port
  -> selected front-hop proxy
  -> configured final ISP exit
```

The launcher refuses to start when the loopback proxy is unavailable, repeated probes do not agree, the observed IPv4 address differs from the configured final exit, or the host time zone differs from the configured exit time zone.

## Cross-platform enforcement

- Windows: dedicated sandbox identity plus Windows Filtering Platform egress fence supplied by Sandbox Runtime.
- macOS: Seatbelt process policy plus a loopback-only egress channel.
- Linux: bubblewrap filesystem boundary and a separate network namespace.
- Legacy Linux portable mode: the original ClaudeCage RunImage backend remains available for compatibility, but it is not the default delivery engine.

## Separation of state

Every environment receives its own state root, split into two trust zones:

- `agent/`: isolated Claude configuration, home and temporary data. This is the only state subtree visible to the sandboxed process.
- `controller/`: policy, audit chain, delivery receipts and credential-bearing generated files. This subtree is never added to Claude's read or write allowlist.

Host browser profiles, SSH keys, cloud credentials, Clash configuration, controller state, and unrelated projects are denied by default. Only the customer workspace and `agent/` state are writable.

## Process cage and sealed VM

The current alpha implements a process cage. It protects network paths, host software state and sensitive files, but some basic hardware and operating-system properties remain observable through host APIs. A future sealed-VM tier will place the same controller inside a per-customer virtual machine with a fixed virtual CPU, disk, NIC and machine identity. The UI labels these tiers explicitly and never claims that process isolation virtualizes hardware.

## Secure delivery

The public repository contains the AGPL core. Customer delivery artifacts may be stored as signed AES-256-GCM encrypted GitHub Release assets. A HONG AI licensing service validates a long-lived license plus one-time token, records an audit event, and wraps the release content key to an ephemeral X25519 installation key. See `SECURE-DELIVERY.md`.

## Delivery gates

1. Validate the customer configuration.
2. Verify the local proxy listener.
3. Probe the final exit repeatedly through the local proxy.
4. Reject unstable or mismatched exits.
5. Render a strict Sandbox Runtime policy.
6. Start the official agent inside the sandbox.
7. Run controlled file, network, DNS, and recovery tests.
8. Run the HONG AI assessment and produce the delivery report only after passing the configured threshold.
