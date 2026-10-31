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
