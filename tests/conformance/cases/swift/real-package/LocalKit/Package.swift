// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "LocalKit",
    products: [.library(name: "LocalKit", targets: ["LocalKit"])],
    targets: [.target(name: "LocalKit")]
)
