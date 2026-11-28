"""A days-old release of an established package that changed who publishes it, or how, is held; and no check
that reads a release's content or history is ever skipped because the package's name is popular."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.supply.registries.detector import RegistryDetector
from cordon_scanner.detect.supply.registries.takeover_hold import HOLD_DAYS, RULE, TakeoverHold
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Finding, Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.registries.record_sources.base import Release
from cordon_scanner.intel.registries.registry_client import PackageFacts, RegistryError
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from support import ROOT

LEDGER = "cordon_scanner.intel.registries.archive_sources.base.ArchiveFetch"


class TakeoverHoldHelpers:
    """Helpers for test_takeover_hold.py."""

    @staticmethod
    def dependency(name: str) -> Dependency:
        return Dependency(
            purl=f"pkg:pypi/{name}@9.9.9",
            ecosystem="pypi",
            name=name,
            version="9.9.9",
            direct=True,
            scope=Scope.RUNTIME,
            declared_in="poetry.lock",
        )

    @staticmethod
    def findings(name: str = "requests") -> list[Finding]:
        ctx = ScanContext(
            config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()), offline=False
        )
        return list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(TakeoverHoldHelpers.dependency(name),)), ctx
            )
        )

    @staticmethod
    def ids(name: str = "requests") -> list[str]:
        return [f.rule_id for f in TakeoverHoldHelpers.findings(name)]

    @staticmethod
    def ago(days: float) -> datetime:
        return datetime.now(UTC) - timedelta(days=days)

    @staticmethod
    def facts(*, days: float, attested: bool = True, attested_versions: int = 0) -> PackageFacts:
        return PackageFacts(
            name="requests",
            version="9.9.9",
            latest="9.9.9",
            last_published=TakeoverHoldHelpers.ago(days).isoformat(),
            attested=attested,
            attested_versions=attested_versions,
        )


class TakeoverHoldFixtures:
    """The registry's answer and its release history, both fixed."""

    @pytest.fixture
    def answer(self, monkeypatch):
        """Substitute the registry with a fixed answer."""

        def install(facts: PackageFacts) -> None:
            monkeypatch.setattr(
                "cordon_scanner.intel.registries.registry_client.RegistryClient.facts",
                lambda ecosystem, name, version, source=None: facts,
            )

        return install

    @pytest.fixture
    def history(self, monkeypatch):
        """Substitute the release history: this release and the one before it, or an error."""
        asked: list[str] = []

        def install(
            this: Release | None, before: Release | None, error: Exception | None = None
        ) -> list[str]:
            def releases(ecosystem: str, name: str, version: str) -> list[Release]:
                asked.append(name)
                if error is not None:
                    raise error
                return [r for r in (this, before) if r is not None]

            def previous_release(ecosystem: str, name: str, version: str) -> Release | None:
                return before

            monkeypatch.setattr(f"{LEDGER}.releases", staticmethod(releases))
            monkeypatch.setattr(f"{LEDGER}.previous_release", staticmethod(previous_release))
            return asked

        return install


class TestATakenOverReleaseIsHeld(TakeoverHoldFixtures):
    def test_a_new_publisher_on_a_days_old_release_is_held(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=2))
        history(
            Release("9.9.9", TakeoverHoldHelpers.ago(2), "stranger"),
            Release("9.9.8", TakeoverHoldHelpers.ago(90), "maintainer"),
        )
        held = [f for f in TakeoverHoldHelpers.findings() if f.rule_id == RULE]
        assert len(held) == 1
        assert "`stranger`" in held[0].message and "`maintainer`" in held[0].message

    def test_a_release_that_lost_its_provenance_is_held(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=1, attested=False, attested_versions=30))
        history(
            Release("9.9.9", TakeoverHoldHelpers.ago(1), "maintainer"),
            Release("9.9.8", TakeoverHoldHelpers.ago(60), "maintainer"),
        )
        ids = TakeoverHoldHelpers.ids()
        assert RULE in ids and "SUSPECT.PACKAGE.PROVENANCE.001" in ids

    def test_the_hold_ends_when_the_release_is_older_than_it(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=HOLD_DAYS - 1))
        history(
            Release("9.9.9", TakeoverHoldHelpers.ago(HOLD_DAYS + 1), "stranger"),
            Release("9.9.8", TakeoverHoldHelpers.ago(90), "maintainer"),
        )
        assert RULE not in TakeoverHoldHelpers.ids()

    def test_a_release_published_as_before_is_not_held(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=1, attested=True, attested_versions=30))
        history(
            Release("9.9.9", TakeoverHoldHelpers.ago(1), "maintainer"),
            Release("9.9.8", TakeoverHoldHelpers.ago(60), "maintainer"),
        )
        assert RULE not in TakeoverHoldHelpers.ids()

    def test_a_publisher_the_registry_does_not_name_is_no_change(self) -> None:
        this = Release("2", TakeoverHoldHelpers.ago(1), "")
        before = Release("1", TakeoverHoldHelpers.ago(9), "maintainer")
        assert TakeoverHold.reasons(this, before, PackageFacts("x", "2"), min_attested=3) == []
        assert TakeoverHold.reasons(this, None, PackageFacts("x", "2"), min_attested=3) == []


class TestOnlyWhatCanBeHeldCostsARequest(TakeoverHoldFixtures):
    def test_a_name_that_is_not_established_is_never_asked_about(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=1))
        asked = history(None, None)
        TakeoverHoldHelpers.ids("zz-not-established-name-q")
        assert asked == []

    def test_a_package_whose_newest_release_is_old_is_never_asked_about(
        self, answer, history
    ) -> None:
        answer(TakeoverHoldHelpers.facts(days=HOLD_DAYS + 3))
        asked = history(None, None)
        TakeoverHoldHelpers.ids()
        assert asked == []

    def test_a_history_that_cannot_be_read_holds_nothing_and_says_so(self, answer, history) -> None:
        answer(TakeoverHoldHelpers.facts(days=1))
        history(None, None, error=RegistryError("down"))
        assert RULE not in TakeoverHoldHelpers.ids()


class TestAPopularNameSkipsOnlyLookAlikeChecks:
    """The popular list answers one question: is this name a look-alike of another? A popular name that
    skipped any other check would be the one a taken-over account publishes under. Every place that reads
    the list is named here with the look-alike question it answers; a new one fails until it is."""

    #: File -> how many times it may ask whether a name is popular, each for a look-alike check.
    LOOKALIKE_SITES: ClassVar[dict[str, int]] = {
        "src/cordon_scanner/detect/supply/dependency.py": 2,
        "src/cordon_scanner/detect/supply/manifests/identity_findings.py": 1,
        "src/cordon_scanner/detect/agents/mcp_servers/handlers.py": 1,
        "src/cordon_scanner/detect/supply/registries/takeover_hold.py": 1,
    }

    @staticmethod
    def uses(path: Path) -> int:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        return sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr == "is_known"
            and isinstance(node.value, ast.Name)
            and node.value.id == "PopularPackageNames"
        )

    def test_only_the_named_sites_ask_whether_a_name_is_popular(self) -> None:
        root = ROOT
        found = {
            path.relative_to(root).as_posix(): count
            for path in sorted((root / "src").rglob("*.py"))
            if (count := self.uses(path))
        }
        assert found == self.LOOKALIKE_SITES

    def test_the_release_comparison_never_reads_the_popular_list(self) -> None:
        root = ROOT / "src" / "cordon_scanner"
        for relative in ("detect/supply/release_diff.py", "sources/previous.py"):
            text = (root / relative).read_text(encoding="utf-8")
            assert "PopularPackageNames" not in text and "EstablishedPackageNames" not in text
