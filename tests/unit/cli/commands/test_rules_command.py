"""`rules show | test | diff`: what each prints, and what makes `diff` and `test` fail (`cli/commands/rules.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.rules import RulesCommand
from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.rules import tester
from cordon_scanner.rules.loader import RuleLoader

PACK = """
pack:
  id: edge.test
  version: 1.0.0
  license: Apache-2.0
  expires: 2099-12-31

rules:
  - id: EDGE.TEST.001
    category: suspicious
    severity: {severity}
    confidence: {confidence}
    enabled: {enabled}
    title: A test detector
    message: Something happened.
{provenance}    remediation: Fix it.
    match:
      kind: regex
      pattern: 'dangerous_call'
    tests:
      positive:
        - "dangerous_call(x)"
      negative:
        - "safe_call(x)"
"""


class _Base:
    @staticmethod
    def run(action: str | None, **over: Any) -> int:
        return RulesCommand.run(argparse.Namespace(rules_command=action, **over))

    @staticmethod
    def pack(
        tmp_path: Path,
        name: str,
        *,
        severity: str = "high",
        confidence: str = "high",
        enabled: str = "true",
        protected: bool = False,
    ) -> Path:
        provenance = (
            "    provenance:\n      kind: incident\n      reference: a real package that arrived\n"
            if protected
            else ""
        )
        path = tmp_path / name
        path.write_text(
            PACK.format(
                severity=severity, confidence=confidence, enabled=enabled, provenance=provenance
            ),
            encoding="utf-8",
        )
        return path


class TestAction(_Base):
    def test_an_unknown_action_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError, match="unknown rules action: nope"):
            self.run("nope")

    def test_a_rule_that_does_not_exist_is_refused_by_name(self) -> None:
        with pytest.raises(CordonError, match=r"no such rule: NO\.SUCH\.RULE"):
            self.run("show", rule_id="NO.SUCH.RULE")


class TestShow(_Base):
    def test_a_rule_with_languages_a_capability_and_protected_provenance_prints_each(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rule = next(
            r.rule
            for pack in RuleLoader.load_builtin()
            for r in pack.rules
            if r.rule.languages and r.rule.capability and r.rule.provenance
        )
        assert self.run("show", rule_id=rule.id) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert f"languages   {', '.join(rule.languages)}" in out
        assert f"capability  {rule.capability}" in out
        assert f"provenance  {rule.provenance.kind}" in out
        if rule.provenance.protected:
            assert "(protected)" in out


class TestTest(_Base):
    def test_a_failing_sample_is_named_on_stderr_and_the_exit_is_findings(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        failure = SimpleNamespace(
            rule_id="X.1", kind="positive", detail="did not match", sample="abc"
        )
        monkeypatch.setattr(
            tester.RuleTester,
            "run",
            staticmethod(lambda pack: [failure] if pack is not None else []),
        )
        assert self.run("test") == int(ExitCode.FINDINGS)
        err = capsys.readouterr().err
        assert "rule sample(s) failed" in err
        assert "X.1 [positive] did not match" in err
        assert "sample: abc" in err


class TestDiff(_Base):
    def test_a_rule_made_weaker_is_named_with_each_way_it_was_weakened_and_does_not_fail_an_unprotected_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        before = self.pack(tmp_path, "before.yaml")
        after = self.pack(tmp_path, "after.yaml", severity="low", confidence="low", enabled="false")
        assert self.run("diff", before=str(before), after=str(after)) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "weakened  EDGE.TEST.001: disabled" in out
        assert "EDGE.TEST.001: severity" in out
        assert "EDGE.TEST.001: confidence" in out

    def test_a_protected_rule_weakened_fails_and_says_it_needs_review(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        before = self.pack(tmp_path, "before.yaml", protected=True)
        after = self.pack(tmp_path, "after.yaml", protected=True, severity="low")
        assert self.run("diff", before=str(before), after=str(after)) == int(ExitCode.FINDINGS)
        captured = capsys.readouterr()
        assert "weakened  PROTECTED EDGE.TEST.001" in captured.out
        assert "1 protected rule(s) removed or weakened: EDGE.TEST.001" in captured.err

    def test_two_equal_packs_have_no_rule_changes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        before = self.pack(tmp_path, "before.yaml")
        assert self.run("diff", before=str(before), after=str(before)) == int(ExitCode.CLEAN)
        assert "no rule changes" in capsys.readouterr().out

    def test_a_pack_that_does_not_exist_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(CordonError, match="no such pack"):
            self.run("diff", before=str(tmp_path / "gone.yaml"), after=None)
