"""A pack rule with no capability reports on its own (CDI §5): the indicator packs the feed delivers.

Before `PackRuleDetector`, such a rule loaded, passed its samples and matched nothing in a scan.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.foundation.models import Severity

PACK = """
pack: {{id: test.indicators, version: 1.0.0, license: Apache-2.0}}
rules:
  - id: TEST.INDICATOR.001
    category: {category}
    severity: high
    confidence: high
{extra}
    title: An indicator
    message: The indicator is present.
    remediation: Remove it.
    match: {{kind: regex, pattern: 'marker_7f3a\\(\\)'}}
    tests: {{positive: ["marker_7f3a()"], negative: ["marker_7f3b()"]}}
"""


class PackKit:
    @staticmethod
    def findings(
        tmp_path: Path, files: dict[str, str], category: str = "suspicious", extra: str = ""
    ):
        pack = tmp_path / "pack.yaml"
        pack.write_text(PACK.format(category=category, extra=extra), encoding="utf-8")
        root = tmp_path / "project"
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        scanner = Scanner(replace(Config.default(), extra_rule_paths=(str(pack),)))
        return [f for f in scanner.scan(root).findings if f.rule_id.startswith("TEST.")]


class TestAPlainPackRuleReports:
    def test_in_source(self, tmp_path: Path) -> None:
        (finding,) = PackKit.findings(tmp_path, {"app/main.py": "x = 1\nmarker_7f3a()\n"})
        assert finding.severity is Severity.HIGH and finding.location.line == 2

    def test_in_a_workflow(self, tmp_path: Path) -> None:
        workflow = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: marker_7f3a()\n"
        found = PackKit.findings(tmp_path, {".github/workflows/ci.yml": workflow})
        assert [f.rule_id for f in found] == ["TEST.INDICATOR.001"]

    def test_once_per_file(self, tmp_path: Path) -> None:
        found = PackKit.findings(tmp_path, {"a.py": "marker_7f3a()\nmarker_7f3a()\n"})
        assert len(found) == 1

    def test_not_where_it_does_not_match(self, tmp_path: Path) -> None:
        assert PackKit.findings(tmp_path, {"a.py": "marker_7f3b()\n"}) == []


class TestTheUsualRestraint:
    def test_a_non_malicious_rule_is_ceilinged_in_test_material(self, tmp_path: Path) -> None:
        (finding,) = PackKit.findings(tmp_path, {"tests/test_a.py": "marker_7f3a()\n"})
        assert finding.severity is Severity.LOW

    def test_a_malicious_rule_is_not(self, tmp_path: Path) -> None:
        extra = "    provenance: {kind: incident, reference: test}"
        (finding,) = PackKit.findings(
            tmp_path, {"tests/test_a.py": "marker_7f3a()\n"}, category="malicious", extra=extra
        )
        assert finding.severity >= Severity.HIGH

    def test_a_capability_rule_still_reports_only_through_a_composite(self, tmp_path: Path) -> None:
        found = PackKit.findings(
            tmp_path, {"a.py": "marker_7f3a()\n"}, extra="    capability: egress"
        )
        assert found == []


class TestABrokenPackDoesNotRun:
    def test_a_pack_whose_samples_fail_is_refused(self, tmp_path: Path) -> None:
        pack = tmp_path / "pack.yaml"
        # The pattern no longer matches the positive sample the rule declares.
        broken = PACK.format(category="suspicious", extra="").replace(
            "pattern: 'marker", "pattern: 'zz"
        )
        pack.write_text(broken, encoding="utf-8")
        with pytest.raises(RulePackError, match="fails its own positive sample"):
            Scanner(replace(Config.default(), extra_rule_paths=(str(pack),)))
