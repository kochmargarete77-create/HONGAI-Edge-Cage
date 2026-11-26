import Foundation
import NetworkExtension
import GuardPolicy

// Development adapter only. No activation entry point or unsigned installer is provided.
// Targets remain closed: authenticated policy/lease IPC is not implemented yet.
public final class FilterDataProvider: NEFilterDataProvider {
    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings, completionHandler: completionHandler)
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let identifier = flow.sourceAppIdentifier else {
            // Without provenance we must not accidentally disconnect the entire customer's host.
            // This makes complete attribution a mandatory release gate, not an assumed guarantee.
            return .allow()
        }
        if identifier == "com.anthropic.claudefordesktop" || identifier.hasPrefix("com.anthropic.claudefordesktop.") {
            return .drop()
        }
        return .allow()
    }
}
