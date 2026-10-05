local http = require('socket.http')
local body = http.request('https://example.test/obj')
local obj = binser.deserialize(base64.decode(body))
