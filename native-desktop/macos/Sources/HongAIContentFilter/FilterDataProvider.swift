import Foundation
import NetworkExtension
import Security
import GuardPolicy

// Development adapter only. No activation entry point or unsigned installer is provided.
// Targets remain closed: authenticated policy/lease IPC is not implemented yet.
public final class FilterDataProvider: NEFilterDataProvider {
    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings, completionHandler: completionHandler)
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let token = flow.sourceAppAuditToken, let identifier = signingIdentifier(auditToken: token) else {
            // Without provenance we must not accidentally disconnect the entire customer's host.
            // This makes complete attribution a mandatory release gate, not an assumed guarantee.
            return .allow()
        }
        if identifier == "com.anthropic.claudefordesktop" || identifier.hasPrefix("com.anthropic.claudefordesktop.") {
            return .drop()
        }
        return .allow()
    }

    // sourceAppIdentifier is an iOS-only property. macOS identity must be resolved
    // from the kernel-supplied audit token, not a PID or a renderer-provided string.
    private func signingIdentifier(auditToken: Data) -> String? {
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(rawValue: 0), &code) == errSecSuccess,
              let code = code,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: 0), nil) == errSecSuccess else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any] else { return nil }
        return values[kSecCodeInfoIdentifier as String] as? String
    }
}
