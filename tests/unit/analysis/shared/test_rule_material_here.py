"""`SourcePaths.is_rule_material_here`: the rule-material judgement lowers only a configuration or
posture finding, only in a repository file nothing runs (fail-open audit, 2 Nov, option B)."""

from __future__ import annotations

import types

import pytest

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.foundation.models import Category

POSTURE_RULE = "SUSPECT.IAC.PUBLIC_INGRESS.001"
REACH = (
    "install_hook_paths",
    "import_entry_paths",
    "install_entry_paths",
    "library_closure_paths",
    "consumer_install_paths",
    "agent_run_paths",
)


class MaterialKit:
    @staticmethod
    def ctx(package: bool = False, **reached: frozenset[str]) -> types.SimpleNamespace:
        sets = {name: reached.get(name, frozenset()) for name in REACH}
        return types.SimpleNamespace(package_distribution=package, **sets)

    @staticmethod
    def content(material: bool = True, path: str = "rules/sample.tf") -> types.SimpleNamespace:
        return types.SimpleNamespace(path=path, is_rule_material=material)

    @staticmethod
    def lowers(
        content: types.SimpleNamespace | None = None,
        ctx: types.SimpleNamespace | None = None,
        rule_id: str = POSTURE_RULE,
        category: Category = Category.SUSPICIOUS,
        capabilities: tuple[str, ...] = (),
    ) -> bool:
        return SourcePaths.is_rule_material_here(
            content or MaterialKit.content(),
            ctx or MaterialKit.ctx(),
            rule_id,
            category,
            capabilities,
        )


class TestWhereTheJudgementMayLower:
    def test_a_posture_finding_in_a_repository_file_nothing_runs(self) -> None:
        assert MaterialKit.lowers()

    def test_not_rule_material_at_all(self) -> None:
        assert not MaterialKit.lowers(content=MaterialKit.content(material=False))

    def test_never_in_a_published_package(self) -> None:
        assert not MaterialKit.lowers(ctx=MaterialKit.ctx(package=True))

    @pytest.mark.parametrize("reach", REACH)
    def test_never_in_a_file_something_runs(self, reach: str) -> None:
        ctx = MaterialKit.ctx(**{reach: frozenset({"rules/sample.tf"})})
        assert not MaterialKit.lowers(ctx=ctx)


class TestWhatTheJudgementMayLower:
    @pytest.mark.parametrize(
        "rule_id",
        [
            "SECRET.GITHUB.TOKEN.001",
            "SUSPECT.EXFIL.CREDENTIAL_STORE.001",
            "SUSPECT.DESTROY.HOME_OR_ROOT.001",
            "SUSPECT.OBFUSCATION.BIDI.001",
            "SUSPECT.POLYGLOT.MISMATCH.001",
        ],
    )
    def test_never_an_attack_finding_even_where_nothing_runs(self, rule_id: str) -> None:
        assert not MaterialKit.lowers(rule_id=rule_id)

    def test_never_a_rule_with_no_known_category(self) -> None:
        # UNSPECIFIED, and any category added later, is an attack until it is listed as posture.
        assert not MaterialKit.lowers(rule_id="NOT.A.RULE.001")

    def test_never_a_malicious_finding_whatever_its_rule(self) -> None:
        assert not MaterialKit.lowers(category=Category.MALICIOUS)

    @pytest.mark.parametrize(
        "rule_id", ["SUSPECT.IAC.PUBLIC_INGRESS.001", "SUSPECT.CI.UNPINNED_ACTION.001"]
    )
    def test_configuration_and_posture_keep_the_ceiling(self, rule_id: str) -> None:
        assert MaterialKit.lowers(rule_id=rule_id)

    def test_never_a_posture_rule_that_names_an_act(self) -> None:
        # `curl | sh` in a Makefile is filed as a build misconfiguration and declares egress and
        # spawn: a dropper however it is filed (corpus/malicious/make-fetch-exec).
        assert not MaterialKit.lowers(
            rule_id="SUSPECT.BUILD.MAKE_FETCH_EXEC.001", capabilities=("egress", "spawn")
        )


class TestWhatRuns:
    @pytest.mark.parametrize("reach", REACH)
    def test_each_reach_set_runs_the_file(self, reach: str) -> None:
        ctx = MaterialKit.ctx(**{reach: frozenset({"lib/index.js"})})
        assert SourcePaths.runs_here("lib/index.js", ctx)

    def test_a_file_in_none_does_not_run(self) -> None:
        assert not SourcePaths.runs_here("lib/index.js", MaterialKit.ctx())
