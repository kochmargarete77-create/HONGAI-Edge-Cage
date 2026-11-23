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

1. A dedicated state root prevents reuse of host identity data, and separates agent-writable state from controller-only policy, audit and delivery state.
2. Host environment variables are allowlisted; AppData, XDG, npm, Git, GnuPG and temporary state are redirected into the agent zone.
3. Native OS sandboxing limits filesystem access for the full process tree.
4. SRT's network proxy and OS egress fence deny direct connections.
5. The parent proxy forces allowed destinations through the customer Clash listener.
6. Generated Clash rules force all allowed Claude destinations through a one-choice chained exit.
7. A preflight verifies the configured final IPv4 before start.
8. A runtime watchdog terminates the session when the final IPv4 disappears or changes.
9. Optional/nonessential Claude traffic is disabled by supported environment variables.
10. The loopback dashboard exchanges the browser-launch fragment for a best-effort tab-scoped session token; a short idempotent retry window tolerates a lost exchange response, then the bootstrap expires. API calls also require loopback Host validation and bearer authentication, and a new launch fragment replaces stale session storage.

## Known limitations

- This alpha is an OS-level process sandbox, not a full virtual machine. No product can truthfully promise mathematical or absolute isolation from a compromised kernel or administrator.
- Process mode cannot fully replace hardware identifiers exposed by the host kernel. Customers that require hardware fingerprint isolation must use the sealed-VM tier once it passes the platform support matrix.
- Windows Sandbox Runtime is a research preview and documents limitations around token impersonation and system-service-mediated traffic. HONG AI adds a fixed executable, strict allowlist, WFP installation, a parent proxy, Clash fail-closed rules and runtime exit monitoring, but production rollout still requires negative testing on each supported Windows build.
- The dashboard bootstrap appears briefly in the browser launch URL. Its short idempotent exchange window limits replay, but a privileged local process or hostile browser extension remains outside this protection boundary; browsers may also clone `sessionStorage` when duplicating a tab.
- Browser and Claude Desktop isolation are separate deliverables. This alpha wraps the official Claude Code CLI. It does not claim to sandbox an already-installed desktop application.
- A customer with local administrator/root access can change or remove enforcement. The delivery report only describes the tested configuration and time.
