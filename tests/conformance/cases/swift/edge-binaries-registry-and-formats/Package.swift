// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "EdgeKit",
    platforms: [.iOS("15.4")],
    products: [.library(name: "EdgeKit", targets: ["EdgeKit"])],
    dependencies: [
        // A Swift package registry identity, not a git URL.
        .package(id: "acme.networking", from: "2.3.0"),
        .package(url: "https://github.com/pointfreeco/swift-snapshot-testing", .upToNextMajor(from: "1.17.0")),
        // .package(url: "https://github.com/example/commented-out.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "EdgeKit", dependencies: ["Analytics", "LocalCrypto", "Unverified"]),
        .binaryTarget(
            name: "Analytics",
            url: "https://cdn.acme.example.internal/Analytics-4.2.0.xcframework.zip",
            checksum: "0f3c6e1d2b4a5968776a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
        ),
        .binaryTarget(name: "LocalCrypto", path: "Frameworks/LocalCrypto.xcframework"),
        .binaryTarget(
            name: "Unverified",
            url: "https://cdn.acme.example.internal/Unverified.zip"
        ),
    ]
)
