"""H-03: detector-declared rules must be visible and tunable.

The rule loader opens by claiming detection rules are "data, not code ...
reviewable by a security team without reading Python". That was true of the five
YAML packs and false of the rules that fire most often in practice: the secret,
container, CI, IaC, obfuscation and dependency rules were emitted from Python
literals, appeared in no pack, and `cordon rules show SECRET.AWS.ACCESS_KEY.001`
answered "no such rule" for a rule the tool emits.

The harms were concrete. An organisation could not see what would run, could not
read a rule's message and remediation without opening the source, and could not
turn one off without patching the installed package.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cli.main import main
from cordon_scanner.core.config import Config, ConfigResolver
from cordon_scanner.core.registry import Registry
from cordon_scanner.detect.catalogue import RuleCatalogue

SECRET_LINE = "API_SECRET=" + "k3JHd82" + "hdKJHd82" + "hKJHd8\n"


def config(**kw) -> Config:
    return Config.default().with_overrides(use_cache=False, **kw)


class TestTheCatalogue:
    def test_every_detector_declares_its_rules(self) -> None:
        declared = RuleCatalogue.from_detectors(Registry().detectors())
        detectors = {r.detector for r in declared}
        assert {"secrets", "config", "obfuscation", "dependency", "lockfile", "manifest"} <= (
            detectors
        )

    def test_the_rules_that_fire_most_often_are_declared(self) -> None:
        ids = {r.id for r in RuleCatalogue.from_detectors(Registry().detectors())}
        for expected in (
            "SECRET.AWS.ACCESS_KEY.001",
            "SECRET.GENERIC.ASSIGNMENT.001",
            "SUSPECT.IAC.PRIVILEGED.001",
            "SUSPECT.CI.FETCH_EXEC.001",
            "SUSPECT.CONTAINER.FETCH_EXEC.001",
            "MALWARE.INSTALL.FETCH_EXEC.001",
            "SUSPECT.DEPENDENCY.TYPOSQUAT.001",
            "SUSPECT.OBFUSCATION.BIDI.001",
        ):
            assert expected in ids, expected

    def test_each_declaration_carries_what_a_reviewer_needs(self) -> None:
        for rule in RuleCatalogue.from_detectors(Registry().detectors()):
            assert rule.id and rule.title and rule.detector
            assert rule.severity is not None
            assert rule.confidence is not None

    def test_the_origin_is_stated(self) -> None:
        """The difference from a pack rule is visible rather than inferred: a
        declared rule carries no mandatory samples, no provenance requirement
        and no independent version."""
        for rule in RuleCatalogue.from_detectors(Registry().detectors()):
            assert rule.origin == "detector"

    def test_a_detector_without_declarations_is_tolerated(self) -> None:
        """Third-party detectors are not obliged to declare, and refusing to
        list the built-ins because a plugin does not is the wrong trade."""

        class Bare:
            id = "bare"

        assert RuleCatalogue.from_detectors([Bare()]) == ()


class TestVisibility:
    def test_rules_list_reports_declared_rules(self, capsys) -> None:
        assert main(["rules", "list"]) == 0
        out = capsys.readouterr().out
        assert "declared by detectors" in out
        assert "SECRET.GENERIC.ASSIGNMENT.001" in out

    def test_rules_show_answers_for_a_declared_rule(self, capsys) -> None:
        assert main(["rules", "show", "SECRET.AWS.ACCESS_KEY.001"]) == 0
        out = capsys.readouterr().out
        assert "SECRET.AWS.ACCESS_KEY.001" in out
        assert "remediation" in out

    def test_rules_show_states_which_guarantees_do_not_apply(self, capsys) -> None:
        """Honesty about the difference is the point. Listing them without
        saying they are not pack rules would trade one wrong impression for
        another."""
        assert main(["rules", "show", "SUSPECT.IAC.PRIVILEGED.001"]) == 0
        out = capsys.readouterr().out
        assert "does not" in out and "pack guarantees" in out

    def test_pack_rules_still_resolve(self, capsys) -> None:
        assert main(["rules", "show", "SUSPECT.DECODE_EXEC.001"]) == 0
        assert "SUSPECT.DECODE_EXEC.001" in capsys.readouterr().out


class TestTunability:
    """An organisation could not disable a secret, IaC, container or CI rule
    without patching the installed package."""

    @pytest.fixture
    def project(self, tmp_path):
        (tmp_path / ".env").write_text(SECRET_LINE)
        (tmp_path / "a.js").write_text("const p = atob(B);\neval(p);\n")
        return tmp_path

    def ids(self, root, cfg=None) -> set[str]:
        return {f.rule_id for f in Scanner(cfg or config()).scan(root).findings}

    def test_the_rule_fires_by_default(self, project) -> None:
        assert "SECRET.GENERIC.ASSIGNMENT.001" in self.ids(project)

    def test_a_declared_rule_can_be_disabled(self, project) -> None:
        (project / "cordon_scanner.yaml").write_text(
            "rules:\n  disabled:\n    - SECRET.GENERIC.ASSIGNMENT.001\n"
        )
        cfg = ConfigResolver.resolve(root=project).with_overrides(use_cache=False)
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in self.ids(project, cfg)

    def test_disabling_one_rule_does_not_disable_others(self, project) -> None:
        (project / "cordon_scanner.yaml").write_text(
            "rules:\n  disabled:\n    - SECRET.GENERIC.ASSIGNMENT.001\n"
        )
        cfg = ConfigResolver.resolve(root=project).with_overrides(use_cache=False)
        assert "SUSPECT.DECODE_EXEC.001" in self.ids(project, cfg)

    def test_a_pack_rule_can_be_disabled_the_same_way(self, project) -> None:
        (project / "cordon_scanner.yaml").write_text(
            "rules:\n  disabled:\n    - SUSPECT.DECODE_EXEC.001\n"
        )
        cfg = ConfigResolver.resolve(root=project).with_overrides(use_cache=False)
        assert "SUSPECT.DECODE_EXEC.001" not in self.ids(project, cfg)

    def test_disabling_is_reported(self, project) -> None:
        """Consistent with every other reduction in coverage: a rule that was
        turned off and a rule that found nothing must not look the same."""
        (project / "cordon_scanner.yaml").write_text(
            "rules:\n  disabled:\n    - SECRET.GENERIC.ASSIGNMENT.001\n"
        )
        cfg = ConfigResolver.resolve(root=project).with_overrides(use_cache=False)
        assert "POLICY.COVERAGE.RULE_DISABLED" in self.ids(project, cfg)

    def test_operational_findings_cannot_be_disabled(self, tmp_path) -> None:
        """A configuration that could silence these could hide the fact that it
        had silenced everything else."""
        (tmp_path / "a.js").write_text("const x = 1;\n")
        (tmp_path / "cordon_scanner.yaml").write_text(
            'scan:\n  exclude:\n    - "**/*"\n'
            "rules:\n  disabled:\n    - POLICY.COVERAGE.NOTHING_SCANNED\n"
        )
        cfg = ConfigResolver.resolve(root=tmp_path).with_overrides(use_cache=False)
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in self.ids(tmp_path, cfg)

    def test_the_setting_round_trips_through_serialisation(self) -> None:
        """Config crosses a process boundary to every parallel worker; a setting
        that does not round-trip is one the workers silently ignore."""
        cfg = Config.from_dict({"rules": {"disabled": ["A.B.001"]}}, source="t")
        assert Config.from_dict(cfg.to_dict(), source="t").disabled_rules == {"A.B.001"}

    def test_the_setting_changes_the_cache_fingerprint(self) -> None:
        """Otherwise a warm cache serves findings from a rule that is now off."""
        base = Config.default()
        assert base.with_overrides(disabled_rules=frozenset({"A.B.001"})).fingerprint() != (
            base.fingerprint()
        )
