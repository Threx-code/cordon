"""Every MITRE ATT&CK and ATLAS technique has a verdict, and every `outside` has its reason.

```
  tests/attack/catalogue.tsv ──► every id ──► verdict_of(id) ──► block | signal | outside(reason)
```
"""

from __future__ import annotations

import sys
from pathlib import Path

ATTACK = Path(__file__).resolve().parents[1] / "attack"
sys.path.insert(0, str(ATTACK))

import verdicts  # noqa: E402


class AttackCatalogue:
    @staticmethod
    def ids() -> list[str]:
        lines = (ATTACK / "catalogue.tsv").read_text(encoding="utf-8").splitlines()
        return [line.split("\t")[0] for line in lines if line and not line.startswith("#")]


class TestAttackCoverage:
    def test_the_catalogue_is_whole(self) -> None:
        ids = AttackCatalogue.ids()
        assert len(ids) == 867
        assert len(set(ids)) == len(ids)

    def test_every_technique_has_a_verdict(self) -> None:
        missing = [t for t in AttackCatalogue.ids() if verdicts.verdict_of(t) is None]
        assert missing == []

    def test_every_outside_row_gives_a_recorded_reason(self) -> None:
        for technique in AttackCatalogue.ids():
            verdict, why = verdicts.verdict_of(technique) or ("", ())
            if verdict == verdicts.OUTSIDE:
                assert why and all(reason in verdicts.REASONS for reason in why), technique
            else:
                assert verdict in (verdicts.BLOCK, verdicts.SIGNAL) and why, technique
