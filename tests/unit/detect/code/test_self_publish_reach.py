"""In a published npm package, a publishing script nothing runs for a consumer warns; one that runs blocks.

Review 98 G6: `SUSPECT.REGISTRY.SELF_PUBLISH.001` was the only blocker on 35 benign units -- release
tooling (`tasks/admin/register.js`) and a person-run spam publisher whose `auto.js` nothing requires,
no hook runs and no entry point names (its six labelled siblings adjudicated clause (c), no consumer
payload). Named as `main`, loaded by an entry point, or run by an install hook, it still blocks.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.REGISTRY.SELF_PUBLISH.001"
PUBLISHER = (
    "const fs = require('fs');\n"
    "const { exec } = require('child_process');\n"
    "const data = JSON.parse(fs.readFileSync('package.json'));\n"
    "data.name = 'next-' + Date.now();\n"
    "fs.writeFileSync('package.json', JSON.stringify(data));\n"
    "exec('npm publish --access public');\n"
)


class PublishKit:
    @staticmethod
    def severities(tmp_path: Path, manifest: dict, files: dict[str, str]) -> list[Severity]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            members = {
                "package/package.json": json.dumps({"name": "p", "version": "1.0.0", **manifest})
            }
            for name, text in {**members, **files}.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        findings = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return [f.severity for f in findings if f.rule_id == RULE]


class TestAPublishingScriptNothingRuns:
    def test_it_is_reported_below_the_gate(self, tmp_path: Path) -> None:
        found = PublishKit.severities(
            tmp_path, {"scripts": {"start": "next start"}}, {"package/auto.js": PUBLISHER}
        )
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_a_publishing_command_a_person_runs_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        found = PublishKit.severities(
            tmp_path, {"bin": {"pub": "bin/pub.js"}}, {"package/bin/pub.js": PUBLISHER}
        )
        assert found and all(s <= Severity.MEDIUM for s in found)


class TestAPublishingScriptThatRuns:
    def test_as_the_main_entry(self, tmp_path: Path) -> None:
        found = PublishKit.severities(tmp_path, {"main": "auto.js"}, {"package/auto.js": PUBLISHER})
        assert any(s >= Severity.HIGH for s in found)

    def test_loaded_by_the_entry(self, tmp_path: Path) -> None:
        files = {"package/index.js": "require('./lib/auto');\n", "package/lib/auto.js": PUBLISHER}
        found = PublishKit.severities(tmp_path, {}, files)
        assert any(s >= Severity.HIGH for s in found)

    def test_run_by_an_install_hook(self, tmp_path: Path) -> None:
        found = PublishKit.severities(
            tmp_path, {"scripts": {"postinstall": "node auto.js"}}, {"package/auto.js": PUBLISHER}
        )
        assert any(s >= Severity.HIGH for s in found)

    def test_a_source_tree_is_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "auto.js").write_text(PUBLISHER, encoding="utf-8")
        found = [f.severity for f in Scanner().scan(tmp_path).findings if f.rule_id == RULE]
        assert any(s >= Severity.HIGH for s in found)
