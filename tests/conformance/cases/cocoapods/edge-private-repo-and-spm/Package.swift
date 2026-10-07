// swift-tools-version:5.9
// The same library through Swift Package Manager, beside the Podfile.
import PackageDescription

let package = Package(
    name: "ShopSPM",
    dependencies: [
        .package(url: "https://github.com/onevcat/Kingfisher.git", from: "7.10.0"),
    ],
    targets: [.target(name: "ShopSPM", dependencies: ["Kingfisher"])]
)
