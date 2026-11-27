# HONG AI native tool privacy component

Native Windows/macOS development component, version `0.1.0-tools-preview`.
This is **not** a completed environment simulator, hardware emulator, sandbox,
network kill switch, Claude installer, or account-safety certification.

## Implemented scope

- A native executable fronts explicitly selected **local stdio MCP servers**.
  The original command, static arguments and server environment are retained in
  a protected binding; no shell command is built from tool arguments.
- Normal requests and meaningful file/code results are preserved. Only explicitly
  configured sensitive literals are replaced in supported text/structured outputs.
  Plain text, JSON escapes and declared URL/base64 representations are supported.
- JSON-RPC identifiers retain full numeric precision. Duplicate members, invalid
  UTF-8, invalid framing and oversized messages stop the connection.
- Installation changes only a selected MCP configuration, with an encrypted
  byte-identical backup. Repeat installation is idempotent. Restore refuses to
  overwrite configuration changed by the customer after installation.
- Windows uses current-user DPAPI with environment-bound entropy. macOS uses
  AES-GCM with a per-environment key in the current user's Keychain. This protects
  storage; it is not a security boundary against arbitrary same-user privileged code.
- Audit files contain counts and coverage flags, never raw messages, tool arguments,
  credentials or upstream stderr. No automatic remote upload.
- Installer intake checks a selected file's publisher signature without running it.
  The source URL is explicitly operator-declared, not fabricated browser-history proof.

## Coverage limits

No replacement of native OS/hardware APIs, native Claude telemetry, uncontrolled
subprocess output, remote MCP traffic, encrypted/unknown encodings, or secrets split
across messages is implemented. Images, audio, binary resources, resource identifiers,
cursors and protocol schemas are not rewritten. Binary blocks are counted as uninspected.
Configured literal matching may redact matching business text: approve each rule carefully.

Current intake supports native Windows EXE/MSIX and macOS PKG publisher checks.
It does **not** yet validate every installer's product role, orchestrate installation,
capture arbitrary downloads, or guarantee protection before first application launch.
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
