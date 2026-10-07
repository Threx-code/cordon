// swift-tools-version:5.9
import PackageDescription

/*
 Retired after the 2024 review:
 .package(url: "https://github.com/example/retired-networking.git", from: "3.0.0"),
*/
let package = Package(
    name: "Regression",
    dependencies: [
        // .package(url: "https://github.com/example/commented-logging.git", from: "1.0.0"),
        .package(url: "https://github.com/Alamofire/Alamofire", from: "5.9.0"), // trailing comment with .package(url: "x")
        .package(url: "git@github.com:onevcat/Kingfisher.git", exact: "7.12.0"),
    ],
    targets: [.target(name: "Regression", dependencies: ["Alamofire", "Kingfisher"])]
)
