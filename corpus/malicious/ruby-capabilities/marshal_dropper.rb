require "net/http"
require "base64"
raw = Net::HTTP.get(URI("https://example.test/obj"))
obj = Marshal.load(Base64.decode64(raw))
