#!/usr/bin/env python3
"""Which rules may block an install alone: the admission table of release item 45.

    python3 scripts/measure/measure_admission.py <out.json> <rows.jsonl> ...

Read from baseline rows (the gate's scan output, one JSON object per unit: `set`, `tags`, `exit`,
`findings` as [rule, severity, confidence, category, path], `verdict` with `area`, `score`,
`block`). Nothing here changes a verdict: it computes the table that a later engine change would
read, and the gate re-measures it on every run, so a rule qualifies or stops qualifying as the rows
and rules change. Until one qualifies, nothing in the engine reads it.

A unit is SOLO for a rule when that rule's evidence family is the only content family at the gate
(high, critical or malicious), intel and the verdict model aside. A (rule, area) qualifies to stop
blocking alone only when all of these hold (notes/45-block-alone-admission.md, its review changes):

- at least FLOOR solo benign blocks, so no rule moves on two or three units;
- it spends more of the false-alarm budget than of the miss budget, with intervals, not points:
  lower Wilson(benign solo rate) / FA_BUDGET > upper Wilson(malware solo rate) / MISS_BUDGET;
- its solo malware blocks are recovered by corroboration, the verdict model over the same unit,
  with at most k = max(1, floor(0.10 x n)) of its n solo malware units lost, each one named.

Two columns read the model the same way. `benign_removed` counts the solo benign blocks the model
does not also block, the only ones a demotion could remove. `lost` names the malware a demotion
would let through. The probe column (an inert evasion probe of the rule's attack class) and the
reached split are filled by the gate; this script reports them as unchecked.
"""

from __future__ import annotations

import collections
import json
import math
import sys
from pathlib import Path
from typing import Any, ClassVar


class Admission:
    """The admission table from baseline rows."""

    FA_BUDGET: ClassVar[float] = 0.005
    MISS_BUDGET: ClassVar[float] = 0.02
    FLOOR: ClassVar[int] = 5
    INTEL: ClassVar[frozenset[str]] = frozenset(
        {
            "MALWARE.PACKAGE.KNOWN.001",
            "MALWARE.DEPENDENCY.KNOWN.001",
            "MALWARE.DEPENDENCY.BUNDLED.001",
            "SUSPECT.VERDICT.MODEL.001",
        }
    )
    NOT_CONTENT: ClassVar[tuple[str, ...]] = ("OPERATIONAL.", "VULNERABLE.", "POLICY.")
    #: Rules that fire from one observation are one piece of evidence (review change 3).
    EVIDENCE_FAMILY: ClassVar[dict[str, str]] = {
        "SUSPECT.DROPPER.001": "dropper",
        "MALWARE.DROPPER.001": "dropper",
        "SUSPECT.DROPPER.REMOTE_CODE.001": "dropper",
        "MALWARE.INSTALL.REMOTE_CODE.001": "dropper",
        "SUSPECT.DECODE_EXEC.001": "decode-run",
        "SUSPECT.DECODE_CHAIN.001": "decode-run",
        "SUSPECT.PERSIST.001": "persist",
        "MALWARE.INSTALL.PERSIST.001": "persist",
        "SUSPECT.PACKAGE.NAME_RISK.001": "name",
        "SUSPECT.TYPOSQUAT.PACKAGE_NAME.001": "name",
    }

    @staticmethod
    def family(rule: str) -> str:
        """The evidence family a rule belongs to: listed, an exfiltration flow's, or its own."""
        if rule in Admission.EVIDENCE_FAMILY:
            return Admission.EVIDENCE_FAMILY[rule]
        if ".EXFIL.FLOW_" in rule:
            return "exfil-flow"  # MALWARE.EXFIL.FLOW_* and SUSPECT.EXFIL.FLOW_* on one flow
        return rule

    @staticmethod
    def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
        """The 95% Wilson score interval of k in n."""
        if n == 0:
            return 0.0, 1.0
        p = k / n
        d = 1 + z * z / n
        c = p + z * z / (2 * n)
        h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
        return max(0.0, (c - h) / d), min(1.0, (c + h) / d)

    @staticmethod
    def gate_families(row: dict[str, Any]) -> dict[str, set[str]]:
        """The content rules at the gate on a unit, by evidence family."""
        out: dict[str, set[str]] = collections.defaultdict(set)
        for finding in row.get("findings") or []:
            rule, severity, category = finding[0], finding[1].lower(), finding[3]
            if rule in Admission.INTEL or rule.startswith(Admission.NOT_CONTENT):
                continue
            if category == "malicious" or severity in ("high", "critical"):
                out[Admission.family(rule)].add(rule)
        return out

    @staticmethod
    def model_blocks(row: dict[str, Any]) -> bool:
        """Whether the verdict model alone puts the unit over its line."""
        verdict = row.get("verdict") or {}
        score, block = verdict.get("score"), verdict.get("block")
        return score is not None and block is not None and score >= block

    @staticmethod
    def kind(row: dict[str, Any]) -> str | None:
        """`benign` or `malware` for a row the table counts; None for one it does not."""
        if "error" in row or "placeholder" in row.get("tags", []):
            return None
        rules = {f[0] for f in row.get("findings") or []}
        if row["set"] == "benign-npm":
            return None if "MALWARE.PACKAGE.KNOWN.001" in rules else "benign"
        return "malware" if row["set"].startswith("malware") else None

    @classmethod
    def table(cls, rows: list[dict[str, Any]]) -> dict[str, Any]:
        pools: collections.Counter[tuple[str, str]] = collections.Counter()
        benign: collections.Counter[tuple[str, str]] = collections.Counter()
        benign_model: collections.Counter[tuple[str, str]] = collections.Counter()
        malware: collections.Counter[tuple[str, str]] = collections.Counter()
        lost: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
        for row in rows:
            kind = cls.kind(row)
            if kind is None:
                continue
            area = (row.get("verdict") or {}).get("area") or "?"
            pools[(kind, area)] += 1
            families = cls.gate_families(row)
            if len(families) != 1:
                continue
            for rule in next(iter(families.values())):
                key = (rule, area)
                if kind == "benign" and row.get("exit") in (1, 4):
                    benign[key] += 1
                    benign_model[key] += cls.model_blocks(row)
                elif kind == "malware":
                    malware[key] += 1
                    if not cls.model_blocks(row):
                        lost[key].append(row["path"].rsplit("/", 1)[-1])
        entries = [
            cls.entry(key, benign[key], benign_model[key], malware[key], lost[key], pools)
            for key in sorted(set(benign) | set(malware))
        ]
        return {"pools": {f"{k}:{a}": n for (k, a), n in sorted(pools.items())}, "table": entries}

    @classmethod
    def entry(
        cls,
        key: tuple[str, str],
        benign_solo: int,
        benign_model: int,
        malware_solo: int,
        lost: list[str],
        pools: collections.Counter[tuple[str, str]],
    ) -> dict[str, Any]:
        rule, area = key
        b_lo, b_hi = cls.wilson(benign_solo, pools[("benign", area)])
        m_lo, m_hi = cls.wilson(malware_solo, pools[("malware", area)])
        spends_more = b_lo / cls.FA_BUDGET > m_hi / cls.MISS_BUDGET
        k = max(1, math.floor(0.10 * malware_solo))
        floor_met = benign_solo >= cls.FLOOR
        return {
            "rule": rule,
            "area": area,
            "family": cls.family(rule),
            "benign_solo": benign_solo,
            "benign_pool": pools[("benign", area)],
            "benign_rate_wilson": [round(b_lo, 5), round(b_hi, 5)],
            "benign_removed": benign_solo - benign_model,
            "malware_solo": malware_solo,
            "malware_pool": pools[("malware", area)],
            "malware_rate_wilson": [round(m_lo, 5), round(m_hi, 5)],
            "floor_met": floor_met,
            "spends_more_fa_than_miss": spends_more,
            "lost": sorted(lost),
            "k": k,
            "probe": "unchecked",
            "reached_split": "unmeasured",
            "qualifies": floor_met and spends_more and len(lost) <= k,
        }


if __name__ == "__main__":
    out_path, sources = sys.argv[1], sys.argv[2:]
    rows = [
        json.loads(line)
        for src in sources
        for line in Path(src).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    result = Admission.table(rows)
    Path(out_path).write_text(json.dumps(result, indent=1), encoding="utf-8")
    qualifying = [e for e in result["table"] if e["qualifies"]]
    print(
        f"{len(result['table'])} (rule, area) entries; {len(qualifying)} qualify to stop blocking alone"
    )
    for e in qualifying:
        print(f"  {e['rule']} {e['area']}: removes {e['benign_removed']}, loses {len(e['lost'])}")
