"""M-08: commands documented across the README, the design documents, the Action
and the pre-commit hooks that did not exist.

`rules diff` is the load-bearing one. `RuleProvenance.protected` exists solely so
that it "fails when one is removed or weakened without an explicit review
trailer" -- so with no implementation, `provenance: incident` guaranteed nothing.
"""

from __future__ import annotations

import json
import xml.dom.minidom
from pathlib import Path

import pytest

from cordon.cli.main import main

PAYLOAD = "const p = atob(B);\neval(p);\n"

PACK = """pack:
  id: t
  version: 1.0.0
  license: Apache-2.0
rules:
  - id: T.ORDINARY.001
    title: ordinary
    category: suspicious
    severity: high
    confidence: medium
    message: x
    remediation: x
    match:
      kind: regex
      patterns:
        - "ordinary_marker"
    tests:
      positive: ["ordinary_marker"]
      negative: ["nothing"]
  - id: T.INCIDENT.001
    title: from an incident
    category: malicious
    severity: critical
    confidence: high
    message: x
    remediation: x
    provenance:
      kind: incident
      reference: "a real package compromise"
    match:
      kind: regex
      patterns:
        - "incident_marker"
    tests:
      positive: ["incident_marker"]
      negative: ["nothing"]
"""


@pytest.fixture
def result_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.js").write_text(PAYLOAD)
    out = tmp_path / "result.json"
    main(["scan", str(repo), "--no-cache", "-f", f"json:{out}", "-q"])
    return out


class TestReportConvert:
    """One scan, every format. A pipeline wanting SARIF for code scanning,
    markdown for a PR comment and JUnit for its test reporter otherwise scans
    three times, and three scans of a moving tree need not agree."""

    def test_the_result_is_written(self, result_file: Path) -> None:
        assert result_file.is_file()
        assert json.loads(result_file.read_text())["findings"]

    @pytest.mark.parametrize("fmt", ["text", "json", "sarif", "junit", "markdown", "github"])
    def test_every_format_renders(self, result_file: Path, fmt: str, capsys) -> None:
        assert main(["report", "convert", str(result_file), "-f", fmt]) == 0
        assert capsys.readouterr().out.strip()

    def test_sarif_is_valid_json(self, result_file: Path, tmp_path) -> None:
        out = tmp_path / "out.sarif"
        assert main(["report", "convert", str(result_file), "-f", "sarif", "-o", str(out)]) == 0
        document = json.loads(out.read_text())
        assert document["runs"][0]["results"]

    def test_junit_is_well_formed(self, result_file: Path, tmp_path) -> None:
        out = tmp_path / "out.xml"
        assert main(["report", "convert", str(result_file), "-f", "junit", "-o", str(out)]) == 0
        # The input is a file this test just produced, not untrusted data.
        xml.dom.minidom.parse(str(out))  # noqa: S318

    def test_the_findings_survive_the_round_trip(self, result_file: Path, tmp_path) -> None:
        out = tmp_path / "again.json"
        assert main(["report", "convert", str(result_file), "-f", "json", "-o", str(out)]) == 0
        before = {f["rule_id"] for f in json.loads(result_file.read_text())["findings"]}
        after = {f["rule_id"] for f in json.loads(out.read_text())["findings"]}
        assert before == after

    def test_a_missing_file_is_an_error(self, tmp_path) -> None:
        assert main(["report", "convert", str(tmp_path / "nope.json")]) == 2

    def test_a_file_that_is_not_a_result_is_a_config_error(self, tmp_path) -> None:
        """The user pointed at the wrong file. That is exit 3, not a crash."""
        bad = tmp_path / "bad.json"
        bad.write_text('{"hello": "world"}')
        assert main(["report", "convert", str(bad)]) == 3


class TestRulesDiff:
    @pytest.fixture
    def packs(self, tmp_path):
        before = tmp_path / "before"
        before.mkdir()
        (before / "p.yaml").write_text(PACK)
        after = tmp_path / "after"
        after.mkdir()
        return before, after

    def test_identical_packs_report_no_change(self, packs, capsys) -> None:
        before, after = packs
        (after / "p.yaml").write_text(PACK)
        assert main(["rules", "diff", str(before), str(after)]) == 0
        assert "no rule changes" in capsys.readouterr().out

    def test_an_added_rule_is_reported_and_passes(self, packs, capsys) -> None:
        """New rules are not a regression."""
        before, after = packs
        (after / "p.yaml").write_text(PACK.replace("T.ORDINARY.001", "T.ORDINARY.002"))
        code = main(["rules", "diff", str(before), str(after)])
        out = capsys.readouterr().out
        assert "added" in out and "removed" in out
        assert code == 0, "an ordinary rule changing is not a protected-rule failure"

    def test_removing_a_protected_rule_fails(self, packs, capsys) -> None:
        """A rule derived from a real incident is the easiest kind to lose: it
        looks arbitrary out of context, so a cleanup deletes it and the diff
        reads as an improvement."""
        before, after = packs
        head, _, _ = PACK.partition("  - id: T.INCIDENT.001")
        (after / "p.yaml").write_text(head)
        assert main(["rules", "diff", str(before), str(after)]) == 1
        captured = capsys.readouterr()
        assert "PROTECTED" in captured.out
        assert "T.INCIDENT.001" in captured.err

    def test_weakening_a_protected_rule_fails(self, packs, capsys) -> None:
        """Weakening does not read as removal in a text diff, which is what
        makes it worth checking separately."""
        before, after = packs
        (after / "p.yaml").write_text(
            PACK.replace(
                "    title: from an incident\n    category: malicious\n    severity: critical",
                "    title: from an incident\n    category: malicious\n    severity: low",
            )
        )
        assert main(["rules", "diff", str(before), str(after)]) == 1
        assert "weakened" in capsys.readouterr().out

    def test_disabling_a_protected_rule_fails(self, packs, capsys) -> None:
        before, after = packs
        (after / "p.yaml").write_text(
            PACK.replace(
                "    title: from an incident\n",
                "    title: from an incident\n    enabled: false\n",
            )
        )
        assert main(["rules", "diff", str(before), str(after)]) == 1
        assert "disabled" in capsys.readouterr().out

    def test_weakening_an_unprotected_rule_is_reported_but_passes(self, packs, capsys) -> None:
        """The gate is narrow on purpose. A tool that fails on every rule
        adjustment gets excluded from the pipeline that runs it."""
        before, after = packs
        (after / "p.yaml").write_text(
            PACK.replace(
                "    title: ordinary\n    category: suspicious\n    severity: high",
                "    title: ordinary\n    category: suspicious\n    severity: low",
            )
        )
        assert main(["rules", "diff", str(before), str(after)]) == 0
        assert "weakened" in capsys.readouterr().out

    def test_it_defaults_to_the_installed_packs(self, tmp_path, capsys) -> None:
        builtin = Path(__file__).resolve().parents[2] / "src" / "cordon" / "rules" / "builtin"
        assert main(["rules", "diff", str(builtin)]) == 0
        assert "no rule changes" in capsys.readouterr().out
