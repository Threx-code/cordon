"""LL-3: a learned pack using each package-scope term fires on its benign-shaped fixture and not on its control; a pack carrying
code, or a term the scanner cannot compute, is refused at load.

The fixtures are ordinary packages built in a temporary folder: a helper that starts `git status` and checks a status page."""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.rules.loader import RuleLoader

HELPER = """const { spawn } = require('child_process');
const https = require('https');
function refresh() { const c = spawn('git', ['status']); https.get('https://example.com/status', () => {}); return c; }
module.exports = { refresh };
"""
ORPHAN_INDEX = "module.exports = (a, b) => a + b;\n"
LOADING_INDEX = "const helper = require('./lib/helper');\nmodule.exports = helper;\n"


class Kit:
    @staticmethod
    def rule(term: str, rule_id: str = "LEARNED.TERM.001") -> str:
        return f"""
pack: {{id: test.terms, version: 1.0.0, license: Apache-2.0}}
rules:
  - id: {rule_id}
    category: suspicious
    severity: high
    confidence: medium
    title: A learned conjunction
    message: A file starts a process and reaches the network, in the place the term names.
    remediation: Review the file.
    match:
      kind: composite
      scope: package
      all:
        - {term}
"""

    @staticmethod
    def fired(
        tmp_path: Path,
        term: str,
        *,
        scripts: dict[str, str] | None = None,
        index: str = ORPHAN_INDEX,
    ) -> bool:
        manifest = {
            "name": "terms-demo",
            "version": "1.0.0",
            "main": "index.js",
            **({"scripts": scripts} if scripts else {}),
        }
        files = {
            "package/package.json": json.dumps(manifest),
            "package/index.js": index,
            "package/lib/helper.js": HELPER,
        }
        archive = tmp_path / "terms-demo-1.0.0.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        pack = tmp_path / "pack.yaml"
        pack.write_text(Kit.rule(term), encoding="utf-8")
        result = Scanner(replace(Config.default(), extra_rule_paths=(str(pack),))).scan(archive)
        return any(f.rule_id == "LEARNED.TERM.001" for f in result.findings)

    BOTH = "{where: %s, capabilities: [spawn, egress]}"


class TestEachTermFiresOnItsFixtureAndNotOnItsControl:
    def test_a_file_in_a_named_place(self, tmp_path: Path) -> None:
        term = "file: " + Kit.BOTH % "install_hook"
        hooked = {"postinstall": "node lib/helper.js"}
        assert Kit.fired(tmp_path, term, scripts=hooked)
        (tmp_path / "control").mkdir()
        assert not Kit.fired(tmp_path / "control", term)

    def test_a_file_nothing_reaches(self, tmp_path: Path) -> None:
        term = "file: " + Kit.BOTH % "unreached"
        assert Kit.fired(tmp_path, term)
        (tmp_path / "control").mkdir()
        assert not Kit.fired(tmp_path / "control", term, index=LOADING_INDEX)

    def test_a_file_by_how_it_is_reached(self, tmp_path: Path) -> None:
        term = "file: " + Kit.BOTH % "reach:placed"
        assert Kit.fired(tmp_path, term, index=LOADING_INDEX)
        (tmp_path / "control").mkdir()
        assert not Kit.fired(tmp_path / "control", term)

    def test_a_file_anywhere(self, tmp_path: Path) -> None:
        term = "file: " + Kit.BOTH % "any"
        assert Kit.fired(tmp_path, term)

    def test_a_lifecycle_hook(self, tmp_path: Path) -> None:
        assert Kit.fired(
            tmp_path, "hook: postinstall", scripts={"postinstall": "node lib/helper.js"}
        )
        (tmp_path / "control").mkdir()
        assert not Kit.fired(tmp_path / "control", "hook: postinstall")

    def test_what_was_scanned(self, tmp_path: Path) -> None:
        both = "file: " + Kit.BOTH % "any"
        assert Kit.fired(tmp_path, f"{both}\n        - target: package")
        (tmp_path / "control").mkdir()
        assert not Kit.fired(tmp_path / "control", f"{both}\n        - target: image")


class TestAPackThatCarriesCodeOrAnUncomputableTermIsRefused:
    @staticmethod
    def load(tmp_path: Path, text: str) -> None:
        pack = tmp_path / "bad.yaml"
        pack.write_text(text, encoding="utf-8")
        RuleLoader().load_file(pack)

    @pytest.mark.parametrize("key", ["run", "python", "script", "eval", "code", "exec"])
    def test_a_rule_with_a_code_field_is_refused(self, tmp_path: Path, key: str) -> None:
        text = Kit.rule("hook: postinstall").replace(
            "      kind: composite",
            f"      {key}: \"__import__('os').system('id')\"\n      kind: composite",
        )
        with pytest.raises(RulePackError):
            self.load(tmp_path, text)

    def test_a_term_of_a_kind_the_scanner_cannot_compute_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(RulePackError):
            self.load(tmp_path, Kit.rule("change: {kind: new_hook}"))

    @pytest.mark.parametrize(
        "term", ["name: left-pad", "host: a.example", "age: young", "publisher: someone"]
    )
    def test_a_term_of_a_refused_kind_is_refused(self, tmp_path: Path, term: str) -> None:
        with pytest.raises(RulePackError):
            self.load(tmp_path, Kit.rule(term))
