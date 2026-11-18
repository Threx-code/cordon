"""Coverage of every known MCP-server and AI-agent attack technique, one inert fixture per case.

Each case is a directory `corpus/coverage/mcp/<family>/<sub-technique>/<way>/` holding:

  positive/      a small MCP server that performs the technique (inert: reserved hosts, no working payload)
  negative/      the same server shape doing the legitimate thing that looks like it
  expect.yaml    what the scanner must do with each: `positive: {block: true}` or `positive: {signal: <category>}`,
                 and `negative: {block: false}`

A positive the scanner does not flag is a missing rule; a negative the scanner blocks is a false block. The cases are
discovered from the directory, so adding a case is adding a directory.

`coverage-baseline.json` lists the positives the scanner flags today. A listed positive that stops being flagged fails
this suite (a rule regressed). A positive not yet listed is reported as a gap and expected to fail until its rule lands;
running this file as a script prints coverage per family and, with `--update`, adds newly flagged positives to the
baseline so they are held from then on. A negative that blocks always fails.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser
from cordon_scanner.foundation.models import Category
from support import ROOT, requires_corpus

pytestmark = requires_corpus

COVERAGE = ROOT / "corpus" / "coverage" / "mcp"
BASELINE = COVERAGE / "coverage-baseline.json"


@dataclass(frozen=True)
class Case:
    """One technique written one way: where it lives and what is expected of it."""

    path: Path
    positive: dict[str, object]
    negative: dict[str, object]

    @property
    def id(self) -> str:
        return self.path.relative_to(COVERAGE).as_posix()

    @property
    def family(self) -> str:
        return self.id.split("/", 1)[0]


class Cases:
    """Discovery of the cases and the baseline of positives already flagged."""

    @staticmethod
    def all() -> list[Case]:
        found = []
        for expect in sorted(COVERAGE.glob("*/*/*/expect.yaml")) if COVERAGE.is_dir() else ():
            spec = RestrictedYamlParser._load_yaml_subset(expect.read_text(encoding="utf-8"), source=str(expect)) or {}
            found.append(Case(expect.parent, dict(spec.get("positive") or {}), dict(spec.get("negative") or {})))
        return found

    @staticmethod
    def baseline() -> set[str]:
        if not BASELINE.is_file():
            return set()
        return set(json.loads(BASELINE.read_text(encoding="utf-8")).get("flagged", []))


class Outcome:
    """What the scanner did with one fixture directory, judged the way a pipeline acts on it."""

    _config = Config.default().with_overrides(use_cache=False)

    @classmethod
    def of(cls, directory: Path) -> tuple[bool, set[str]]:
        """Whether a content finding (not an operational one) fails the default policy, and the categories found."""
        result = Scanner(cls._config).scan(directory)
        verdict = PolicyGate.evaluate(result, cls._config.policy)
        blocked = verdict.exit_code is ExitCode.FINDINGS and any(
            f.category is not Category.OPERATIONAL for f in verdict.triggering
        )
        return blocked, {str(f.category) for f in result.active if f.category is not Category.OPERATIONAL}

    @classmethod
    def flagged(cls, case: Case) -> bool:
        blocked, categories = cls.of(case.path / "positive")
        if "signal" in case.positive:
            return str(case.positive["signal"]) in categories
        return blocked


CASES = Cases.all()


@pytest.mark.corpus
class TestMcpCoverage:
    """Every negative stays unblocked; every positive in the baseline stays flagged."""

    @pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
    def test_negative_is_not_blocked(self, case: Case) -> None:
        blocked, _ = Outcome.of(case.path / "negative")
        assert not blocked, f"{case.id}: the legitimate look-alike is blocked"

    @pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
    def test_positive_is_flagged(self, case: Case) -> None:
        if case.id not in Cases.baseline():
            pytest.xfail(f"{case.id}: no rule flags this technique yet (a gap)")
        assert Outcome.flagged(case), f"{case.id}: a rule that flagged this technique no longer does"


class CoverageReport:
    """`python tests/integration/test_mcp_coverage.py [--update]`: coverage per family, and the baseline ratchet."""

    @staticmethod
    def main(argv: list[str]) -> int:
        flagged_now = {case.id for case in CASES if Outcome.flagged(case)}
        false_blocks = {case.id for case in CASES if Outcome.of(case.path / "negative")[0]}
        total, hit = Counter(c.family for c in CASES), Counter(c.family for c in CASES if c.id in flagged_now)
        wrong = Counter(c.family for c in CASES if c.id in false_blocks)
        print("family  flagged positives   blocked negatives")
        for family in sorted(total):
            print(f"{family:6} {hit[family]:4} / {total[family]:4}   {wrong[family]:4} / {total[family]:4}")
        print(f"all    {len(flagged_now):4} / {len(CASES):4}   {len(false_blocks):4} / {len(CASES):4}")
        way = lambda c: c.id.rsplit("/", 1)[-1]  # noqa: E731
        ways, way_hit = Counter(way(c) for c in CASES), Counter(way(c) for c in CASES if c.id in flagged_now)
        print("by way: " + ", ".join(f"{w} {way_hit[w]}/{ways[w]}" for w in sorted(ways)))
        print("gaps: " + " ".join(sorted(c.id for c in CASES if c.id not in flagged_now)))
        print("false blocks: " + " ".join(sorted(false_blocks)))
        if "--update" in argv:
            held = sorted(Cases.baseline() | flagged_now)
            BASELINE.write_text(json.dumps({"flagged": held}, indent=1) + "\n", encoding="utf-8")
            print(f"baseline holds {len(held)} flagged positives")
        return 0


if __name__ == "__main__":
    raise SystemExit(CoverageReport.main(sys.argv[1:]))
