"""Package-scope composite rules (learning loop LL-3): a conjunction of facts about the whole package, written in the
terms the learning loop learns in, evaluated on a real scan. The packages below are ordinary code built in a temporary
folder: a helper that runs `git status` and checks a status page, shipped where nothing the package runs reaches it."""

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
from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.rules.fact_terms import FactTerms
from cordon_scanner.rules.loader import RuleLoader

HELPER = """const { spawn } = require('child_process');
const https = require('https');

function refresh() {
  const child = spawn('git', ['status']);
  https.get('https://example.com/status', () => {});
  return child;
}

module.exports = { refresh };
"""

RULE = """
pack: {id: test.learned, version: 1.0.0, license: Apache-2.0}
rules:
  - id: LEARNED.TEST.001
    category: suspicious
    severity: high
    confidence: medium
    title: Shipped code nothing starts spawns and reaches the network
    message: A file nothing in the package runs both starts a process and reaches the network.
    remediation: Remove the file, or start it from the package's own entry point.
    match:
      kind: composite
      scope: package
      all:
        - file: {where: unreached, capabilities: [spawn, egress]}
"""


class PackageKit:
    @staticmethod
    def tarball(tmp_path: Path, *, index: str) -> Path:
        files = {
            "package/package.json": json.dumps(
                {"name": "facts-demo", "version": "1.0.0", "main": "index.js"}
            ),
            "package/index.js": index,
            "package/lib/helper.js": HELPER,
        }
        path = tmp_path / "facts-demo-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def scan(tmp_path: Path, *, index: str, rule: str = RULE):
        pack = tmp_path / "learned.yaml"
        pack.write_text(rule, encoding="utf-8")
        config = replace(Config.default(), extra_rule_paths=(str(pack),))
        return Scanner(config).scan(PackageKit.tarball(tmp_path, index=index))


class TestARuleOverTheWholePackage:
    def test_it_fires_on_the_file_nothing_reaches(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        learned = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        assert len(learned) == 1
        assert learned[0].location.path.endswith("lib/helper.js")
        assert learned[0].detector == "package_rules"

    def test_it_does_not_fire_when_the_entry_point_loads_the_file(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="const helper = require('./lib/helper');\nmodule.exports = helper;\n"
        )
        assert not [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]

    def test_the_facts_export_and_the_rule_read_the_same_terms(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        record = ScanFacts.of(result)
        assert ("file", "unreached", "egress", "spawn") in FactTerms.of_facts(record)
        assert record["package"]["unreached_capability_files"] >= 1


RULE_BY_REACH = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.002").replace(
    "where: unreached", "where: reach:unreached"
)
RULE_BY_STRING = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.003").replace(
    "where: unreached", "where: reach:path_string"
)


class TestARuleByHowAFileIsReached:
    """`reach:KIND` in a learned rule is read from the scanner's own reach (`decide/reach.py`)."""

    def test_a_rule_on_the_orphan_fires(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="module.exports = (a, b) => a + b;\n", rule=RULE_BY_REACH
        )
        assert [
            f.location.path.endswith("lib/helper.js")
            for f in result.findings
            if f.rule_id == "LEARNED.TEST.002"
        ] == [True]

    def test_a_rule_on_a_path_string_fires_only_when_a_string_names_the_file(
        self, tmp_path
    ) -> None:
        named = "module.exports = ['lib/helper.js'];\n"
        fired = PackageKit.scan(tmp_path, index=named, rule=RULE_BY_STRING)
        assert [f for f in fired.findings if f.rule_id == "LEARNED.TEST.003"]
        (tmp_path / "again").mkdir()
        orphan = PackageKit.scan(
            tmp_path / "again", index="module.exports = 1;\n", rule=RULE_BY_STRING
        )
        assert not [f for f in orphan.findings if f.rule_id == "LEARNED.TEST.003"]


class TestARuleThatCouldNeverFireIsRefusedAtLoad:
    def test_repository_scope_is_refused_with_its_reason(self, tmp_path) -> None:
        pack = tmp_path / "repo.yaml"
        pack.write_text(RULE.replace("scope: package", "scope: repository"), encoding="utf-8")
        with pytest.raises(RulePackError, match="declared but not implemented"):
            RuleLoader().load_file(pack)

    def test_a_package_term_the_evaluator_does_not_read_is_refused(self, tmp_path) -> None:
        pack = tmp_path / "bad.yaml"
        pack.write_text(RULE.replace("where: unreached", "where: somewhere"), encoding="utf-8")
        with pytest.raises(RulePackError, match="unknown where"):
            RuleLoader().load_file(pack)
