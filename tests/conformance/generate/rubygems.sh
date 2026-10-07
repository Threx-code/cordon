#!/bin/sh
# Regenerates the real-world RubyGems conformance case: Bundler resolves a Gemfile with groups,
# platform-conditional gems, a git gem, a path gem, the project's own gemspec, a source block, a
# Ruby version, a native gem locked for two platforms, and per-gem checksums. `bundle lock` only:
# nothing is installed, no gem's code or extension build runs. Bundler's own LockfileParser reads
# the result back as the authoritative inventory.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" ruby:3.3 sh /conformance/generate/rubygems.sh
set -eu
OUT=/conformance/cases/rubygems/real-bundler
rm -rf /tmp/r && mkdir -p /tmp/r/vendor/acme-util/lib && cd /tmp/r
gem install bundler -v 2.6.2 --no-document >/dev/null 2>&1
export BUNDLE_LOCKFILE_CHECKSUMS=true

cat > vendor/acme-util/acme-util.gemspec <<'EOF'
Gem::Specification.new do |s|
  s.name = "acme-util"
  s.version = "0.3.0"
  s.summary = "An internal gem, required by path."
  s.authors = ["conformance"]
  s.files = []
  s.add_dependency "concurrent-ruby", "~> 1.3"
end
EOF

cat > conformance.gemspec <<'EOF'
Gem::Specification.new do |s|
  s.name = "conformance"
  s.version = "1.0.0"
  s.summary = "The project itself, a gem."
  s.authors = ["conformance"]
  s.files = []
  s.required_ruby_version = ">= 3.1"
  s.add_dependency "zeitwerk", "~> 2.6"
  s.add_development_dependency "rake", "~> 13.2"
end
EOF

echo "3.3.6" > .ruby-version

cat > Gemfile <<'EOF'
source "https://rubygems.org"

ruby ">= 3.1"

gemspec

gem "rails", "~> 7.2.2"
gem "pg", "~> 1.5"
gem "nokogiri", "~> 1.18"
gem "rack-test", git: "https://github.com/rack/rack-test", tag: "v2.2.0"
gem "acme-util", path: "vendor/acme-util"
gem "tzinfo-data", platforms: %i[windows jruby]

source "https://rubygems.org" do
  gem "faraday", "~> 2.12"
end

group :development, :test do
  gem "rspec-rails", "~> 7.1"
  gem "debug", platforms: %i[mri windows], require: "debug/prelude"
end

group :test do
  gem "capybara", "~> 3.40"
end
EOF

bundle lock --add-platform x86_64-linux aarch64-linux-gnu >/dev/null
bundle lock --add-checksums >/dev/null 2>&1 || true

ruby -rbundler -rjson -e '
out = ARGV[0]
require "fileutils"
if Dir.exist?(out)
  Dir.children(out).each { |name| FileUtils.rm_rf(File.join(out, name)) unless name == "expect.yaml" }
end
FileUtils.mkdir_p(File.join(out, "vendor/acme-util"))
%w[Gemfile Gemfile.lock conformance.gemspec .ruby-version vendor/acme-util/acme-util.gemspec].each do |f|
  FileUtils.cp(f, File.join(out, f))
end
parser = Bundler::LockfileParser.new(File.read("Gemfile.lock"))
local = %w[acme-util conformance]
truth = parser.specs.map { |s| "#{s.name}@#{s.version}" }.uniq.sort.reject { |c| local.include?(c.split("@").first) }
File.write(File.join(out, "authoritative.json"), JSON.pretty_generate(
  "tool" => "Bundler::LockfileParser (Bundler #{Bundler::VERSION})",
  "packages" => truth,
  "ignore" => {
    "acme-util" => "a path gem: the project'"'"'s own code, read as source",
    "conformance" => "the project'"'"'s own gemspec",
  },
  "exclude" => {
    "dependency_type" => {"tool" => "BUNDLED WITH names the Bundler that wrote the lock, which LockfileParser does not list among its specs"},
  },
))
puts "locked #{truth.size}; platforms #{parser.platforms.map(&:to_s).join(",")}; bundler #{parser.bundler_version}"
' "$OUT"
grep -n "^[A-Z]" Gemfile.lock
sed -n '/CHECKSUMS/,/^$/p' Gemfile.lock | head -5
echo done
