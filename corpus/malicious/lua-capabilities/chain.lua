local packed = base64.decode(blob)
local code = zlib.inflate()(packed)
loadstring(code)()
