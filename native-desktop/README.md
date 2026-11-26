# HONG AI Desktop Native development

This project develops OS-enforced boundaries for an unmodified official Claude Desktop. It is separate from the shipped WEB_ISOLATION wrapper and the user-space Desktop Guard pilot.

Current Windows engine is a self-test executable. It only filters its own exact executable identity, inside one WFP transaction. Tests cover the selected TCP loopback endpoint, denial of other ports, other IPs and IPv6, proxy loss, and cleanup. Its dynamic rules disappear after testing and do not apply to Claude or any remote support app.

The macOS Swift package contains a policy engine and a Network Extension development adapter. The adapter has no authenticated policy channel, cannot grant a ready lease, and has no installation/activation path. It is compile-only, not an installable app. Real process attribution, approved tool descendants, extension lifecycle and customer-machine recovery are outstanding work.

No release in this project is customer accepted. Code compilation and archive hashes do not establish runtime isolation. The customer release gate remains closed until install, enforcement, failure, restart, upgrade and rollback evidence is complete on the supported OS and hardware matrix.

References:

- https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- https://claude.com/docs/third-party/claude-desktop/network-proxy
