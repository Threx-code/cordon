# gems.rb is Bundler's alternative name for a Gemfile, and gems.locked for its lock.
source "https://rubygems.org"
source "https://gems.acme.example.internal"

ruby file: ".ruby-version"

gem "sinatra", "~> 4.1", ">= 4.1.1"
gem "acme-auth" # resolves from whichever global source has it
gem "rack-protection", github: "sinatra/sinatra", branch: "main"
gem "puma", require: false

if ENV["WITH_REDIS"]
  gem "redis", "~> 5.3"
end

install_if -> { RUBY_PLATFORM.include?("darwin") } do
  gem "terminal-notifier", "~> 2.0"
end

platforms :jruby do
  gem "jruby-openssl"
end

group :production do
  gem "newrelic_rpm"
end

=begin
gem "commented-out-gem"
=end
