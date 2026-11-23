# Security model

## Protected assets

- Host browser profiles and cookies.
- Host Claude state and prior login sessions.
- SSH, cloud, container, Kubernetes and Git credentials.
- Clash subscriptions, configuration and unrelated proxy credentials.
- Projects outside the explicitly authorized workspace.
- The host's direct Internet path and local/private network.

## Trust boundary

The official Claude Code process and every child process are treated as untrusted. The trusted computing base is the host operating system, Anthropic Sandbox Runtime, the HONG AI launcher, the loopback parent proxy, and the customer-authorized Clash chain.

## Defense in depth

1. A dedicated state root prevents reuse of host identity data.
2. Native OS sandboxing limits filesystem access for the full process tree.
3. SRT's network proxy and OS egress fence deny direct connections.
4. The parent proxy forces allowed destinations through the customer Clash listener.
5. Generated Clash rules force all allowed Claude destinations through a one-choice chained exit.
6. A preflight verifies the configured final IPv4 before start.
7. A runtime watchdog terminates the session when the final IPv4 disappears or changes.
8. Optional/nonessential Claude traffic is disabled by supported environment variables.

## Known limitations

- This alpha is an OS-level process sandbox, not a full virtual machine. No product can truthfully promise mathematical or absolute isolation from a compromised kernel or administrator.
- Windows Sandbox Runtime is a research preview and documents limitations around token impersonation and system-service-mediated traffic. HONG AI adds a fixed executable, strict allowlist, WFP installation, a parent proxy, Clash fail-closed rules and runtime exit monitoring, but production rollout still requires negative testing on each supported Windows build.
- Browser and Claude Desktop isolation are separate deliverables. This alpha wraps the official Claude Code CLI. It does not claim to sandbox an already-installed desktop application.
- A customer with local administrator/root access can change or remove enforcement. The delivery report only describes the tested configuration and time.
