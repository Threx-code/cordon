"""An enumeration of `process.env` that reads one family of variables, or hands the environment
to a child process, is not credential theft (review 98: 6 of 8 benign extensions blocked as it)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config

SEND = (
    "\nconst https = require('https');\n"
    "const req = https.request({hostname: 'example.invalid', method: 'POST'});\n"
    "req.end(JSON.stringify(o));\n"
)


class EnvKit:
    @staticmethod
    def rules(tmp_path: Path, read: str) -> set[str]:
        (tmp_path / "index.js").write_text(read + SEND, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestNarrowedEnvironment:
    @pytest.mark.parametrize(
        "read",
        [
            "const o = Object.keys(process.env).filter(k => /^debug_/i.test(k));",
            "const o = {}; for (const [k, v] of Object.entries(process.env)) "
            "if (k.startsWith('LANGCHAIN_')) o[k] = v;",
            "const o = Object.create(null); Object.keys(process.env).forEach(k => o[k] = "
            "process.env[k]); o.ELECTRON_RUN_AS_NODE = '1';",
        ],
    )
    def test_is_not_exfiltration(self, tmp_path: Path, read: str) -> None:
        assert not {r for r in EnvKit.rules(tmp_path, read) if "EXFIL" in r}

    @pytest.mark.parametrize(
        "read",
        [
            "Object.keys(process.env).forEach(k => o[k] = process.env[k]); send(o);",
            "Object.entries(process.env).map(([k, v]) => k + '=' + v).join('&')",
        ],
    )
    def test_the_whole_environment_is_not_narrowed(self, read: str) -> None:
        from cordon_scanner.detect.code.capability import CapabilityDetector
        from cordon_scanner.foundation.content import FileContent

        content = FileContent.from_bytes("index.js", read.encode())
        end = read.index("process.env") + len("process.env")
        assert not CapabilityDetector._narrowed_environment(content, end)
