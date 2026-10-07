// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ConformanceApp",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .executable(name: "app", targets: ["App"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", exact: "1.6.1"),
        .package(url: "https://github.com/apple/swift-collections.git", .upToNextMinor(from: "1.1.0")),
        .package(url: "https://github.com/apple/swift-numerics.git", "1.0.0"..<"2.0.0"),
        .package(url: "https://github.com/apple/swift-system.git", branch: "main"),
        .package(url: "https://github.com/apple/swift-atomics.git", revision: "cd142fd2f64be2100422d658e7411e39489da985"),
        .package(path: "../LocalKit"),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "Numerics", package: "swift-numerics"),
                .product(name: "SystemPackage", package: "swift-system"),
                .product(name: "Atomics", package: "swift-atomics"),
                .product(name: "LocalKit", package: "LocalKit"),
            ],
            plugins: [.plugin(name: "Generate")]
        ),
        .plugin(name: "Generate", capability: .buildTool()),
    ]
)
