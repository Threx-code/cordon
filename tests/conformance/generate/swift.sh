#!/bin/sh
# Regenerates the real-world Swift conformance case: SwiftPM resolves a manifest using every
# requirement form (from:, exact:, .upToNextMinor, a range, branch:, revision:), a local path
# package, a build-tool plugin, platforms and products. (A binary target is downloaded by
# resolution itself, so it is covered by the handwritten edge case instead.)
# `swift package resolve` clones sources only: nothing is built, no plugin runs.
# `swift package show-dependencies --format json` is the authoritative inventory.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" swift:6.0 sh /conformance/generate/swift.sh
set -eu
OUT=/conformance/cases/swift/real-package
rm -rf /tmp/s && mkdir -p /tmp/s/App/Sources/App /tmp/s/LocalKit/Sources/LocalKit && cd /tmp/s

cat > LocalKit/Package.swift <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "LocalKit",
    products: [.library(name: "LocalKit", targets: ["LocalKit"])],
    targets: [.target(name: "LocalKit")]
)
EOF
echo 'public enum LocalKit {}' > LocalKit/Sources/LocalKit/LocalKit.swift

cat > App/Package.swift <<'EOF'
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
EOF
echo 'print("app")' > App/Sources/App/main.swift
mkdir -p App/Plugins/Generate && cat > App/Plugins/Generate/plugin.swift <<'EOF'
import PackagePlugin
@main struct Generate: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] { [] }
}
EOF

cd App
swift package resolve >/dev/null
swift package show-dependencies --format json > /tmp/deps.json

rm -rf "$OUT" && mkdir -p "$OUT/App" "$OUT/LocalKit"
cp Package.swift Package.resolved "$OUT/App/"
cp ../LocalKit/Package.swift "$OUT/LocalKit/"

command -v python3 >/dev/null || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1; }
python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
deps = json.load(open("/tmp/deps.json"))
found, unversioned = set(), {}
def owner_repo(url):
    # Advisories name a Swift package `owner/repo`; so does the record.
    parts = [p for p in url.removesuffix(".git").split("/") if p]
    return "/".join(parts[-2:]).lower()
def walk(node):
    for child in node.get("dependencies", []):
        if child.get("path", "").endswith("LocalKit"):
            pass  # the local package: the project's own code
        elif child.get("version") in (None, "unspecified"):
            unversioned[owner_repo(child["url"])] = "pinned to a branch or revision: SwiftPM reports no version, the record keeps the commit"
        else:
            found.add(f"{owner_repo(child['url'])}@{child['version']}")
        walk(child)
walk(deps)
document = {"tool": "swift package show-dependencies --format json", "packages": sorted(found), "ignore": unversioned}
json.dump(document, open(f"{out}/authoritative.json", "w"), indent=1)
print("listed", len(found))
PY
head -30 Package.resolved
cat "$OUT/authoritative.json"
echo done
