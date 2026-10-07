#!/bin/sh
# Regenerates the real-world CocoaPods conformance case: CocoaPods resolves a Podfile (installing
# pods, never building them) with an explicit spec source, an exact version, an optimistic
# version, a subspec, a git pod at a tag, a local pod with a podspec of its own (dependencies,
# subspecs, a prepare_command), a debug-only pod and a post_install hook. CocoaPods' own
# Pod::Lockfile reads the result back as the authoritative inventory.
# Run inside Docker only (as an unprivileged user, which `pod` requires):
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" ruby:3.3 sh /conformance/generate/cocoapods.sh
set -eu
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq rsync >/dev/null 2>&1
gem install cocoapods --no-document >/dev/null 2>&1
id builder >/dev/null 2>&1 || useradd -m builder
rm -rf /tmp/c && mkdir -p /tmp/c/LocalKit && chown -R builder /tmp/c

cat > /tmp/c/LocalKit/LocalKit.podspec <<'EOF'
Pod::Spec.new do |s|
  s.name         = "LocalKit"
  s.version      = "0.3.0"
  s.summary      = "An internal pod, required by path."
  s.homepage     = "https://example.invalid/localkit"
  s.license      = { :type => "MIT" }
  s.author       = "conformance"
  s.source       = { :git => "https://example.invalid/localkit.git", :tag => s.version.to_s }
  s.ios.deployment_target = "15.0"
  s.swift_version = "5.9"
  s.prepare_command = "echo preparing LocalKit"
  s.default_subspec = "Core"
  s.subspec "Core" do |core|
    core.source_files = "Sources/Core/**/*.swift"
    core.dependency "SwiftyJSON", "~> 5.0"
  end
  s.subspec "UI" do |ui|
    ui.source_files = "Sources/UI/**/*.swift"
    ui.dependency "LocalKit/Core"
  end
end
EOF

# A minimal Xcode project with the Debug and Release configurations, written by the xcodeproj gem
# CocoaPods ships with, so a configuration-restricted pod has configurations to name.
ruby -rxcodeproj -e '
project = Xcodeproj::Project.new("/tmp/c/App.xcodeproj")
project.new_target(:application, "App", :ios, "15.0")
project.save
'

cat > /tmp/c/Podfile <<'EOF'
source "https://cdn.cocoapods.org/"

platform :ios, "15.0"
project "App.xcodeproj"
install! "cocoapods", :integrate_targets => false
use_frameworks!

target "App" do
  pod "Alamofire", "~> 5.9"
  pod "SwiftyJSON", "5.0.2"
  pod "SDWebImage/Core", "~> 5.19"
  pod "Moya", :git => "https://github.com/Moya/Moya.git", :tag => "15.0.0"
  pod "LocalKit", :path => "./LocalKit", :subspecs => ["Core", "UI"]
  pod "CocoaLumberjack/Swift", "~> 3.8", :configurations => ["Debug"]
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each { |c| c.build_settings["IPHONEOS_DEPLOYMENT_TARGET"] = "15.0" }
  end
end
EOF
chown -R builder /tmp/c
su builder -c "cd /tmp/c && pod install >/tmp/c/install.log 2>&1" || { tail -20 /tmp/c/install.log; exit 1; }

OUT=/conformance/cases/cocoapods/real-podfile
rm -rf "$OUT" && mkdir -p "$OUT/LocalKit"
cp /tmp/c/Podfile /tmp/c/Podfile.lock "$OUT/" && cp /tmp/c/LocalKit/LocalKit.podspec "$OUT/LocalKit/"
ruby -rcocoapods -rjson -e '
lock = Pod::Lockfile.from_file(Pathname("/tmp/c/Podfile.lock"))
names = lock.pod_names.map { |n| n.split("/").first }.uniq.reject { |n| n == "LocalKit" }
packages = names.map { |n| "#{n}@#{lock.version(n)}" }.sort
File.write(ARGV[0] + "/authoritative.json", JSON.pretty_generate(
  "tool" => "Pod::Lockfile (CocoaPods #{Pod::VERSION})",
  "packages" => packages,
  "ignore" => {"LocalKit" => "a path pod: the project'"'"'s own code, read as source"},
))
puts "locked #{packages.size}"
' "$OUT"
cat "$OUT/Podfile.lock"
echo done
