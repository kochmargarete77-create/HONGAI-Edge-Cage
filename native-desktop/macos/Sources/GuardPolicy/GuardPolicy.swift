import Foundation

public enum EgressVerdict: Equatable {
    case allowUnmanaged
    case allowVerifiedLoopback
    case block(String)
}

public struct AppIdentity: Equatable {
    public let signingIdentifier: String
    public let buildHash: String
    public init(signingIdentifier: String, buildHash: String) {
        self.signingIdentifier = signingIdentifier
        self.buildHash = buildHash
    }
}

public struct FlowDestination {
    public let host: String
    public let port: UInt16
    public let ipProtocol: Int
    public init(host: String, port: UInt16, ipProtocol: Int) {
        self.host = host; self.port = port; self.ipProtocol = ipProtocol
    }
}

public struct GuardPolicy {
    public let proxyPort: UInt16
    public let expectedExit: String
    public let protectedBuilds: [String: Set<String>]

    public init(proxyPort: UInt16, expectedExit: String, protectedBuilds: [String: Set<String>]) throws {
        guard proxyPort >= 1024, !protectedBuilds.isEmpty, !expectedExit.isEmpty else { throw PolicyError.invalidConfiguration }
        for (identifier, hashes) in protectedBuilds {
            guard !identifier.isEmpty, !hashes.isEmpty, hashes.allSatisfy({ !$0.isEmpty }) else { throw PolicyError.invalidConfiguration }
        }
        self.proxyPort = proxyPort; self.expectedExit = expectedExit; self.protectedBuilds = protectedBuilds
    }

    // A lease is an internal primitive. The shipping product still needs authenticated IPC
    // plus independent route/exit verification before it can grant one.
    public struct Lease {
        fileprivate let expectedExit: String
        fileprivate let expiresAtUptime: TimeInterval
        public init(verifiedExit: String, issuedAtUptime: TimeInterval, duration: TimeInterval) throws {
            guard issuedAtUptime.isFinite, issuedAtUptime >= 0, duration.isFinite, duration > 0, duration <= 15 else { throw PolicyError.invalidLease }
            self.expectedExit = verifiedExit; self.expiresAtUptime = issuedAtUptime + duration
        }
    }

    public func evaluate(app: AppIdentity, destination: FlowDestination?, lease: Lease?, uptime: TimeInterval) -> EgressVerdict {
        guard let builds = protectedBuilds[app.signingIdentifier] else { return .allowUnmanaged }
        guard builds.contains(app.buildHash) else { return .block("UNVERIFIED_APP_BUILD") }
        guard uptime.isFinite, uptime >= 0, let lease = lease, lease.expectedExit == expectedExit, uptime < lease.expiresAtUptime else { return .block("PROXY_NOT_VERIFIED") }
        guard let destination = destination else { return .block("UNKNOWN_DESTINATION") }
        guard destination.ipProtocol == 6 else { return .block("NON_TCP_DENIED") }
        guard destination.host == "127.0.0.1", destination.port == proxyPort else { return .block("DIRECT_OR_OTHER_ENDPOINT_DENIED") }
        return .allowVerifiedLoopback
    }
}

public enum PolicyError: Error { case invalidConfiguration, invalidLease }
