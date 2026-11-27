# HONG AI CAGE Desktop Native — pilot.3

Native launchers for signature-verified official Claude Desktop files, with a session-owned loopback gateway and an inherited process boundary. This is separate from the WEB_ISOLATION wrapper.

## Important correction from pilot.2

The previous CI used an extracted MSIX executable, while the customer path used an installed WindowsApps executable. Those are different launch conditions. Customer evidence supersedes any claim that the old tests established registered-MSIX compatibility. pilot.2 has been withdrawn from the local sending area.

Windows pilot.3 discovers the real registered official x64 MSIX, reads its app files into a private runtime, compares every copied file by SHA256, verifies the official executable signature, and starts that byte-identical payload inside the signed Sandboxie Classic core. It never changes WindowsApps permissions, invokes the execution alias outside the box, or replaces isolation with broad firewall exceptions. The private runtime has no MSIX package identity. Protocol callbacks, notifications, updates, Cowork and package-dependent integration are separate acceptance items.

Saved setup is now the normal launch path: importing the Clash handoff and choosing a workspace are first-use actions. Later launches start the official desktop automatically. Windows controls are in the tray; Mac controls are in the menu bar. Settings are shown on request or when startup fails.

macOS build 8 also fixes the Foundation Process group-leader/setsid mismatch missed by earlier direct-CLI tests. The helper verifies its own session and process-group ownership before exec. Installed-app daily launch is now tested in addition to CLI smoke tests.

## Evidence

Windows runtime and test source: 9adb63955a4bc9eed24f41615472ab251fc4536e.
Actual registered MSIX, existing/fresh core, cold start, saved-setup automatic launch, storage checks and recoverable uninstall: Windows Server 2022/2025, https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/actions/runs/45935635169

Mac source: bed61340fc5c1b6d5a710ade4cec2058df26918c.
Actual package install, official desktop, installed-workbench launch, saved setup, inherited boundary and uninstall: macOS 15/26 on Apple Silicon/Intel, https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/actions/runs/45934735499

These are installation-test results, not real-account or full-business acceptance. No login was performed. Concrete client hardware, authentication, MCP/extensions, Cowork and system delegation remain unaccepted until tested. Both platforms require use of the CAGE entry point; the ordinary system Claude icon is outside this claim.

The installers do not edit host Wi-Fi, TUN, DNS, system proxy or routes. The enrolled Clash endpoint must be a dedicated listener pinned to the final outbound. Enrollment is not per-connection routing attestation. No hardware fingerprint removal, arbitrary content redaction or zero-leakage guarantee is claimed.

The setup lacks organizational Windows signing, and the Mac package is ad-hoc signed and unnotarized. Use normal operator-approved installation flows, not disabled platform protections. Original Sandboxie Classic identity, valid signatures, GPLv3 notices and corresponding-source directions are retained.

Read the TXT documents in docs for installation, recovery and exact limitations.
