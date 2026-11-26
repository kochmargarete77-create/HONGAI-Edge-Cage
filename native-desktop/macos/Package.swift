// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "HONGAIDesktopBoundary",
    platforms: [.macOS(.v13)],
    products: [.library(name: "GuardPolicy", targets: ["GuardPolicy"]), .library(name: "HongAIContentFilter", targets: ["HongAIContentFilter"])],
    targets: [
        .target(name: "GuardPolicy"),
        .target(name: "HongAIContentFilter", dependencies: ["GuardPolicy"], linkerSettings: [.linkedFramework("NetworkExtension"), .linkedFramework("Network"), .linkedFramework("Security")]),
        .testTarget(name: "GuardPolicyTests", dependencies: ["GuardPolicy"])
    ]
)
