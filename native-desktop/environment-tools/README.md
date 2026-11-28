# HONG AI native environment workbench and tool privacy component

The `environment` command adds a native, account-free preparation and diagnostics
workbench. It preserves the official Claude installation, package identity and
updates. Its local browser window manages configuration; Claude itself remains
the official desktop application. It does not embed claude.ai.

The workbench installs its own executable into a stable owned directory, saves
approved local-proxy/exit settings with current-user protected storage, discovers
the official desktop application and profile candidates, and probes the explicit
loopback HTTP/Mixed proxy three times without a direct fallback. A saved daily
entry can request normal official-app activation after successful preparation
checks. Missing settings or failed checks return to the workbench.

Preparation probes do not enforce or prove the complete network behavior of the
official client or its children. Full hardware simulation, system-level network
enforcement, authenticated account acceptance and organizational publisher signing
remain separate unaccepted capabilities. No account is needed for component tests.

```text
hongai-tools environment install --root <dedicated-absolute-directory>
hongai-tools environment open --root <same-directory>
hongai-tools environment use --root <same-directory>
hongai-tools environment inventory
hongai-tools environment support --root <same-directory>
hongai-tools environment uninstall --root <same-directory>
```

Uninstall refuses an active workbench or conflicting MCP edits and recoverably
renames only the owned workbench directory. It never uninstalls official Claude,
clears account state, changes host networking or deletes customer projects.
Clash subscription and final-node credentials remain in the accepted Clash setup;
the workbench accepts only the approved loopback entry, final IPv4 and target time zone.

Environment workbench 0.3 adds native installer frontends, a redacted support
download, preserved cryptographic roots across Windows path case changes, and
explicit recovery instead of overwriting unreadable encrypted settings. An
active workbench must stop before switching its managed runtime during upgrade.
Installer frontends preserve the separate user state directory. Installer and
account/business acceptance are recorded separately.

Native Windows/macOS development component, version `0.1.1-tools-preview`.
This is **not** a completed environment simulator, hardware emulator, sandbox,
network kill switch, Claude installer, or account-safety certification.

## Implemented scope

- A native executable fronts explicitly selected **local stdio MCP servers**.
  The original command, static arguments and server environment are retained in
  a protected binding; no shell command is built from tool arguments.
- Normal requests and meaningful file/code results are preserved. Only explicitly
  configured sensitive literals are replaced in supported text/structured outputs.
  Plain text, JSON escapes and declared URL/base64 representations are supported.
- Optional policy version 2 selects exact JSON Pointer string-value paths inside
  server results/errors. Other business values are untouched, even if they contain
  the same literal. Protocol fields, schemas, resource locations and binary blocks
  cannot be selected. Missing/non-string/protected paths are counted explicitly.
- Both input and filtered output frames have a 4 MiB limit. Output expansion
  stops with a symbolic error; oversized results are never forwarded unfiltered.
- JSON-RPC identifiers retain full numeric precision. Duplicate members, invalid
  UTF-8, invalid framing and oversized messages stop the connection.
- Installation changes only a selected MCP configuration, with an encrypted
  byte-identical backup. Repeat installation is idempotent. Restore refuses to
  overwrite configuration changed by the customer after installation.
- The executable is copied to a stable owned revision before the configuration is
  committed. Deleting the temporary download/extraction folder does not break the
  installed server entry. Recovery copies remain after restoring configuration.
- Windows uses current-user DPAPI with environment-bound entropy. macOS uses
  AES-GCM with a per-environment key in the current user's Keychain. This protects
  storage; it is not a security boundary against arbitrary same-user privileged code.
- Audit files contain counts and coverage flags, never raw messages, tool arguments,
  credentials or upstream stderr. No automatic remote upload.
- Installer intake checks a selected file's publisher signature without running it.
  The source URL is explicitly operator-declared, not fabricated browser-history proof.
- A bounded observer watches one approved directory for newly arriving stable
  candidates and performs verification. It does not launch installers or certify
  that application attachment/first-launch protection is complete.

## Coverage limits

No replacement of native OS/hardware APIs, native Claude telemetry, uncontrolled
subprocess output, remote MCP traffic, encrypted/unknown encodings, or secrets split
across messages is implemented. Images, audio, binary resources, resource identifiers,
cursors and protocol schemas are not rewritten. Binary blocks are counted as uninspected.
Configured literal matching may redact matching business text: approve each rule carefully.

Policy version 1 retains legacy literal matching. Version 2 is opt-in; existing
customer rules/configuration are not migrated automatically. Copy
`policy.scoped.example.json` and select the real tool's exact diagnostic string
field locally. JSON Pointer paths use `/` segments, with `~0` for `~` and `~1` for
`/` inside a property name. No wildcards or whole-object selectors are supported.
Missing fields remain missing; they are not invented or silently changed to a
different device, region or account identity. Redaction markers explicitly identify
omitted values rather than pretending to be original observations.

Paths/values and raw payloads are not included in the audit. Coverage is limited
to the explicitly selected fields; unrelated values can still contain sensitive
data. Binary data, arbitrary encodings and native client telemetry remain outside
this component. The component neither changes nor hides the host's real hardware
or geographical identity from the operating system.

Cancellation closes only the three pipes owned by that bridge invocation and
reaps the direct upstream process. It does not claim to terminate all descendants
or cancel an arbitrary caller-owned Reader that is blocked forever. Third-party
servers still control their own file/cache logging and inherited environment;
the component's redacted audit does not prove they never write raw data.

Current intake supports native Windows EXE/MSIX, macOS PKG publisher checks and
official macOS `.app` identity/Team-ID verification.
It does **not** yet validate every installer's product role, orchestrate installation,
capture arbitrary locations, or guarantee protection before first application launch.
No Claude binary, account or pre-authenticated state is bundled. The official application,
its package identity and its signed update mechanism are not modified by this component.

## Explicit local configuration

Copy `request.example.json` and `policy.example.json` into an approved local service
directory. Specify the actual existing Claude MCP configuration file, a component data
directory with an existing parent, the policy path, and the server names authorized
for wrapping. Do not send policies containing real sensitive values through chat.

Close Claude normally before changing its MCP configuration. Run as the customer
user, not SYSTEM/root or a different administrator's user account.

```text
hongai-tools install --request <absolute-request-path>
hongai-tools restore --data-root <same-component-data-root>
hongai-tools inspect-installer --file <selected-file> --declared-source <official-HTTPS-URL>
hongai-tools watch-downloads --directory <approved-directory> --declared-source <official-HTTPS-URL> --seconds 120
```

Do not put the component inside a path that changes on every launch, or delete its
protected bindings while the client configuration still references them. Restore
the configuration first. Backups and application authentication data are never deleted.
Known Windows npm/npx shims are resolved to the corresponding native Node entry point;
other command shims and remote MCP configurations require separate support.

## Validation

Native tests cover real subprocess forwarding, ordinary file writes/reads, protected
storage and tamper rejection, installation, repeated installation, pending-receipt
recovery, conflict-safe restore, and the actual built CLI. All fixtures are synthetic.
These tests do not accept an authenticated official Claude session or hardware simulation.

Windows publisher signing and macOS Developer ID/notarization are not supplied by CI.
Do not disable platform security checks to install this preview.
