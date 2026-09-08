// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecretBrokerIOS",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SecretBrokerMobileCore", targets: ["SecretBrokerMobileCore"]),
        .executable(name: "SecretBrokerIOSApp", targets: ["SecretBrokerIOSApp"]),
    ],
    targets: [
        .target(name: "SecretBrokerMobileCore"),
        .executableTarget(
            name: "SecretBrokerIOSApp",
            dependencies: ["SecretBrokerMobileCore"]
        ),
        .testTarget(
            name: "SecretBrokerMobileCoreTests",
            dependencies: ["SecretBrokerMobileCore"]
        ),
    ]
)
