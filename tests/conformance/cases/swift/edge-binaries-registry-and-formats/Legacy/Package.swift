// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "Legacy",
    dependencies: [
        .package(name: "Alamofire", url: "https://github.com/Alamofire/Alamofire.git", .exact("5.4.4")),
    ],
    targets: [.target(name: "Legacy", dependencies: ["Alamofire"])]
)
