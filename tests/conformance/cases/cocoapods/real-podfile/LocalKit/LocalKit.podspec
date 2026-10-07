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
