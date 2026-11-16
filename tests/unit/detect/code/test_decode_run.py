"""`DecodeRun` (`detect/code/decode_run`): a run is excused from a decode-run pairing only when it cannot
be running the decoded bytes. A JavaScript run whose argv is all literals was excused even when it
named the very file the decode was written to, or the name that file was moved to; a run naming a
file the unit writes keeps the pairing, as a fixed Python spawn naming one always has."""

from __future__ import annotations

import json

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

COMPOSITES = {"SUSPECT.DECODE_EXEC.001", "MALWARE.INSTALL.DECODED_LAUNCH.001"}
DECODE = "Buffer.from(BLOB, 'base" + "64')"
HEAD = "const fs = require('fs');\nconst { spawn } = require('child_process');\n"


class DecodeRunKit:
    @staticmethod
    def paired(tmp_path, body: str) -> bool:
        """Whether a package's install hook running `body` reports a decode-run composite."""
        manifest = {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node a.js"}}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (tmp_path / "a.js").write_text(HEAD + body, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return bool({f.rule_id for f in found} & COMPOSITES)


class TestARunOfAWrittenFile:
    @pytest.mark.parametrize(
        "body",
        [
            f"fs.writeFileSync('x.js', {DECODE});\nspawn('node', ['x.js']);\n",
            f"fs.writeFileSync('/tmp/x.bin', {DECODE});\nfs.renameSync('/tmp/x.bin', '/tmp/x.js');\n"
            "spawn('node', ['/tmp/x.js']);\n",
            f"fs.writeFileSync('x.bin', {DECODE});\nfs.copyFileSync('x.bin', 'run.js');\n"
            "spawn('node',\n  ['run.js']);\n",
        ],
        ids=["written-and-run", "renamed-then-run", "copied-then-run-over-two-lines"],
    )
    def test_it_keeps_the_pairing(self, tmp_path, body: str) -> None:
        assert DecodeRunKit.paired(tmp_path, body)

    def test_a_run_of_another_file_is_still_excused(self, tmp_path) -> None:
        body = f"fs.writeFileSync('shot.png', {DECODE});\nspawn('git', ['status']);\n"
        assert not DecodeRunKit.paired(tmp_path, body)


DROPPER = "SUSPECT.DROPPER.001"


class DropperKit:
    @staticmethod
    def rules(tmp_path, body: str, *, hook: bool = False) -> set[str]:
        """The rule ids a package reports whose entry file is `body`."""
        manifest = {"name": "x", "version": "1.0.0", "main": "a.js"}
        if hook:
            manifest["scripts"] = {"postinstall": "node a.js"}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (tmp_path / "a.js").write_text(HEAD + body, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return {f.rule_id for f in found}


class TestADropperPairsAProcessOnlyWithWhatItRuns:
    """`SUSPECT.DROPPER.001` pairs a request with a process started beside a decode. A process whose command is a tool by its
    name with nothing fetched, decoded or received flowing into it (`git status`) is not that process: the analysis the decode-run
    composites use, taken for this composite's spawn half. A call that names a path, a script or program file or a shell is not
    a tool by its name -- a payload unpacked or written beside it is what it starts."""

    CAPTURE = (
        "async function shot(url) {\n"
        "  const reply = await fetch(url);\n"
        "  const payload = await reply.json();\n"
        f"  fs.writeFileSync('shot.png', {DECODE.replace('BLOB', 'payload.data')});\n"
        "}\n"
        "function revision() {\n"
        "  spawn('git', ['rev-parse', '--short', 'HEAD'], { stdio: 'ignore' });\n"
        "}\n"
        "module.exports = { shot, revision };\n"
    )

    def test_a_tool_started_beside_a_decoded_screenshot_is_not_a_dropper(self, tmp_path) -> None:
        assert DROPPER not in DropperKit.rules(tmp_path, self.CAPTURE)

    def test_nor_is_it_one_at_install(self, tmp_path) -> None:
        assert DROPPER not in DropperKit.rules(tmp_path, self.CAPTURE, hook=True)

    @pytest.mark.parametrize(
        "run",
        [
            "spawn('./bin/tool', ['--setup']);",
            "spawn('node', ['setup.js']);",
            "spawn('bin/tool', []);",
            "spawn('/tmp/tool', []);",
            "spawn('sh', ['-i']);",
            "spawn(process.env.TMPDIR + '/tool', []);",
            "spawn('git', ['status']); spawn('./bin/tool', []);",
        ],
        ids=[
            "relative-path",
            "script-file",
            "program-in-a-directory",
            "temporary-path",
            "shell",
            "environment-location",
            "second-call-on-the-line",
        ],
    )
    def test_a_call_naming_a_file_or_a_shell_is_still_one(self, tmp_path, run: str) -> None:
        body = (
            "async function go(u) {\n  const r = await fetch(u);\n  const t = await r.text();\n"
            f"  const blob = {DECODE.replace('BLOB', 't')};\n  {run}\n}}\n"
        )
        assert DROPPER in DropperKit.rules(tmp_path, body)

    @pytest.mark.parametrize(
        "body",
        [
            # the decoded bytes are what the process is given
            "async function run(u) {\n  const r = await fetch(u);\n  const t = await r.text();\n"
            f"  const code = {DECODE.replace('BLOB', 't')}.toString();\n  spawn('sh', ['-c', code]);\n}}\n",
            # the process runs the file the decode was written to
            "async function run(u) {\n  const r = await fetch(u);\n  const t = await r.text();\n"
            f"  fs.writeFileSync('x.js', {DECODE.replace('BLOB', 't')});\n  spawn('node', ['x.js']);\n}}\n",
            # the command is built from what was fetched
            "async function run(u) {\n  const r = await fetch(u);\n  const t = await r.text();\n"
            f"  const a = {DECODE.replace('BLOB', 't')}.toString();\n  spawn(a, []);\n}}\n",
            # a parameter's value is not known to be a tool by its name
            "async function run(u, program) {\n  const r = await fetch(u);\n  const t = await r.text();\n"
            f"  const blob = {DECODE.replace('BLOB', 't')};\n  spawn(program, [blob]);\n}}\n",
        ],
        ids=["decoded-argument", "written-then-run", "decoded-program", "parameter-program"],
    )
    def test_a_process_given_what_was_decoded_or_unknown_is_still_one(
        self, tmp_path, body: str
    ) -> None:
        assert DROPPER in DropperKit.rules(tmp_path, body)
