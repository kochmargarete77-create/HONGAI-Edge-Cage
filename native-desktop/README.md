# HONG AI CAGE Desktop Native

Lightweight adapters that launch the unmodified, signature-verified official Claude Desktop inside an OS process boundary. These are native desktop launchers; the separate WEB_ISOLATION archive remains a web wrapper.

Windows 0.3.0-pilot.2 packages the unmodified, signed GPLv3 Sandboxie Classic 5.74.1 core. A box-wide network policy admits only a session-owned IPv4 loopback gateway; tool descendants inherit the boundary. The gateway forwards to one enrolled Clash endpoint, rejects local/private destinations, and expires on a monotonic health lease. The installer supports a fresh core or compatible existing core and uses recoverable uninstall.

macOS 0.3.0 build 7 is a universal AppKit application using the system process sandbox and a session-owned gateway. No VM, TUN, Wi-Fi, DNS, system proxy, routing, or Network Extension configuration is installed. Its protection applies to the process tree launched by CAGE.

Actual installer, native UI and signed official desktop offline-start checks run on Windows Server 2022/2025 and macOS 15/26 on Apple Silicon/Intel. Checks do not authenticate an account or prove business acceptance. Windows 10/11 consumer hardware, physical M5 systems, login, full MCP/extensions, Cowork, system delegation and production publishing remain separate acceptance items.

Installable pilot packages are distinct from a customer-accepted full-feature product. Do not label untested capabilities as PASS, claim hardware fingerprint removal, or describe network enforcement as automatic redaction of arbitrary file/tool content. macOS currently uses ad-hoc code signing and an unnotarized package; Windows' HONG AI setup has no organizational signature, while bundled upstream components retain their original valid signatures.

Read the plain-text documents in docs. The Clash handoff is an enrolled endpoint/IP identity, not proof of every connection's internal proxy chain. Prefer a dedicated Clash listener pinned directly to the final outbound. Existing broad rules must not be silently removed.

Frozen runtime source for both platforms: commit f1ffecd6e7bf99007d9f17d7de7547decb1fb691.
Windows acceptance: https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/actions/runs/45904904009
Mac acceptance: https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/actions/runs/45904903997

Licenses and corresponding-source directions for the bundled Classic component are installed under licenses. Its identity and notices are preserved. HONG AI is an independent integration, without vendor certification or endorsement.
