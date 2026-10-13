"""A CI check beside the user's opt-out or a terminal test is a courtesy, not an evasion.

The shapes are the ones that blocked 29 `@readystack` MCP linters in the 200K corpus (review 98):
a licence ping skipped under `DO_NOT_TRACK` or CI, and a progress line skipped off a terminal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

RULE = "SUSPECT.ANTI_ANALYSIS.001"
SEND = "const https = require('https');\nfunction ping() {\n  {gate}\n  https.get('https://example.invalid/v1/ping');\n}\nmodule.exports = ping;\n"


class GateKit:
    @staticmethod
    def rules(tmp_path: Path, gate: str) -> set[str]:
        (tmp_path / "ping.js").write_text(SEND.replace("{gate}", gate), encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestCourtesyGates:
    @pytest.mark.parametrize(
        "gate",
        [
            "if (process.env.DO_NOT_TRACK === '1' || process.env.CI) return;",
            "if (!process.stderr.isTTY || process.env.CI) return;",
            "if (process.env.CI || process.env.MYTOOL_TELEMETRY_DISABLED) return;",
        ],
    )
    def test_is_not_anti_analysis(self, tmp_path: Path, gate: str) -> None:
        assert RULE not in GateKit.rules(tmp_path, gate)


class TestTheBareBailOutStillReports:
    def test_a_ci_check_alone(self, tmp_path: Path) -> None:
        assert RULE in GateKit.rules(tmp_path, "if (process.env.CI) return;")
