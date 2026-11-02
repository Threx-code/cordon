"""SUSPECT.OBFUSCATION.REQUIRE_ALIAS.001: Node's `require` stored under a short global name, so the
code's module loads never name it (GuardDog's hidden-code shape, our own form: 7 content misses in 7
groups, 0 of 35,876 benign; scratchpad jsm/pairn.txt). Inert fixtures: the alias loads nothing."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.OBFUSCATION.REQUIRE_ALIAS.001"


class AliasKit:
    @staticmethod
    def found(tmp_path: Path, name: str, text: str) -> list:  # type: ignore[type-arg]
        buffer = io.BytesIO()
        members = {
            "package/package.json": json.dumps({"name": "p", "version": "1.0.0"}),
            f"package/{name}": text,
        }
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, body in members.items():
                data = body.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return [f for f in result.findings if f.rule_id == RULE]


class TestTheAlias:
    @pytest.mark.parametrize(
        "text",
        [
            "global['r'] = require;\nmodule.exports = 1;\n",
            'globalThis["_$"]=require;\n',
            "global [ 'loader12345' ] = require\n",
        ],
    )
    def test_blocks_with_the_verdict_on(self, tmp_path: Path, text: str) -> None:
        found = AliasKit.found(tmp_path, "index.js", text)
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_reported_once_per_file(self, tmp_path: Path, verdict_off: None) -> None:
        text = "global['a'] = require;\nglobal['b'] = require;\n"
        assert len(AliasKit.found(tmp_path, "index.js", text)) == 1

    @pytest.mark.parametrize(
        "text",
        [
            "// global['r'] = require\nmodule.exports = 1;\n",
            "/*\n   global['r'] = require\n*/\nmodule.exports = 1;\n",
            "const doc = \"global['r'] = require\";\n",
            "global.r = require;\n",
            "global['aVeryLongLoaderName'] = require;\n",
            "global['r'] = requireJson;\n",
        ],
    )
    def test_does_not_fire(self, tmp_path: Path, text: str, verdict_off: None) -> None:
        assert not AliasKit.found(tmp_path, "index.js", text)

    def test_only_in_javascript(self, tmp_path: Path, verdict_off: None) -> None:
        assert not AliasKit.found(tmp_path, "notes.py", "x = \"global['r'] = require\"\n")
