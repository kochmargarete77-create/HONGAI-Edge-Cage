import XCTest
@testable import GuardPolicy

final class GuardPolicyTests: XCTestCase {
    let claude = AppIdentity(signingIdentifier: "com.anthropic.claudefordesktop", buildHash: "verified-build-fixture")
    func policy() throws -> GuardPolicy {
        try GuardPolicy(proxyPort: 17896, expectedExit: "approved-exit-fixture", protectedBuilds: [claude.signingIdentifier: [claude.buildHash]])
    }
    func lease() throws -> GuardPolicy.Lease { try GuardPolicy.Lease(verifiedExit: "approved-exit-fixture", issuedAtUptime: 100, duration: 10) }
    func endpoint(_ host: String = "127.0.0.1", _ port: UInt16 = 17896, _ proto: Int = 6) -> FlowDestination { .init(host: host, port: port, ipProtocol: proto) }
    func testClosedWithoutLease() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint(), lease: nil, uptime: 101), .block("PROXY_NOT_VERIFIED"))
    }
    func testOnlyVerifiedEndpointAllowed() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint(), lease: lease(), uptime: 101), .allowVerifiedLoopback)
    }
    func testOtherAppsRemainUnmanaged() throws {
        let app = AppIdentity(signingIdentifier: "com.example.remote-support", buildHash: "fixture")
        XCTAssertEqual(try policy().evaluate(app: app, destination: endpoint("remote-fixture", 443), lease: nil, uptime: 101), .allowUnmanaged)
    }
    func testNoDirectAndNoOtherLoopback() throws {
        for host in ["8.8.8.8", "192.168.1.1", "127.0.0.2", "::1", "::ffff:127.0.0.1", "localhost", "0x7f000001"] {
            XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint(host), lease: lease(), uptime: 101), .block("DIRECT_OR_OTHER_ENDPOINT_DENIED"))
        }
    }
    func testOtherPortDenied() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint("127.0.0.1", 7897), lease: lease(), uptime: 101), .block("DIRECT_OR_OTHER_ENDPOINT_DENIED"))
    }
    func testUdpAndQuicDenied() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint("127.0.0.1", 17896, 17), lease: lease(), uptime: 101), .block("NON_TCP_DENIED"))
    }
    func testLeaseExpiryBlocks() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint(), lease: lease(), uptime: 110), .block("PROXY_NOT_VERIFIED"))
    }
    func testWrongExitBlocks() throws {
        let wrong = try GuardPolicy.Lease(verifiedExit: "other-fixture", issuedAtUptime: 100, duration: 10)
        XCTAssertEqual(try policy().evaluate(app: claude, destination: endpoint(), lease: wrong, uptime: 101), .block("PROXY_NOT_VERIFIED"))
    }
    func testNewAppBuildIsClosedUntilRevalidated() throws {
        let updated = AppIdentity(signingIdentifier: claude.signingIdentifier, buildHash: "new-build")
        XCTAssertEqual(try policy().evaluate(app: updated, destination: endpoint(), lease: lease(), uptime: 101), .block("UNVERIFIED_APP_BUILD"))
    }
    func testUnknownDestinationDenied() throws {
        XCTAssertEqual(try policy().evaluate(app: claude, destination: nil, lease: lease(), uptime: 101), .block("UNKNOWN_DESTINATION"))
    }
    func testInvalidConfigurationAndLeaseRejected() throws {
        XCTAssertThrowsError(try GuardPolicy(proxyPort: 80, expectedExit: "fixture", protectedBuilds: [:]))
        XCTAssertThrowsError(try GuardPolicy.Lease(verifiedExit: "fixture", issuedAtUptime: 100, duration: 3600))
        XCTAssertThrowsError(try GuardPolicy.Lease(verifiedExit: "fixture", issuedAtUptime: .nan, duration: 10))
    }
}
