"""Does `decide()` agree with today's `PolicyGate`? Over recorded scan rows x the grid of failure policies.

Reads scan rows (JSON lines whose `findings` are `[rule, severity, confidence, category, path, line, detector]`),
takes a fixed sample by a hash of the file name and line number (so a rerun takes the same rows), builds a real
`ScanResult` from each, and for every (row, policy) pair of `LegacyBridge.policy_grid()` runs the real
`PolicyGate.evaluate` and `Decider.decide` and counts where they disagree (`LegacyBridge.differences`). It prints
counts only: pairs, agreements, disagreements by kind. No unit, path or rule is printed.

    python bench/tools/legacy_equivalence.py --per-group 40 'rows_a.jsonl' 'census/rows-*.jsonl'

Each argument is one group (a glob); `--per-group` rows are sampled from the rows that a content rule blocks and the
same number from the rest, so both outcomes are in every group.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from datetime import date
from pathlib import Path

from content import CONTENT_GAPS, Content

from cordon_scanner.decide.decision.legacy import LegacyBridge
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.foundation.results import ScanResult


class Rows:
    """Recorded scan rows turned into scan results."""

    @staticmethod
    def finding(entry: list) -> Finding | None:
        """One recorded finding as a `Finding`, or `None` when its fields are not a finding's."""
        try:
            rule, severity, confidence, category, path, line, detector = entry[:7]
            return Finding(
                rule_id=rule,
                category=Category(category),
                severity=Severity[str(severity).upper()],
                confidence=Confidence[str(confidence).upper()],
                message="recorded",
                location=Location(path=str(path), line=int(line) if str(line).isdigit() else None),
                evidence=Evidence(
                    kind=EvidenceKind.HASH, match_hash="0" * 16, redaction=RedactionMode.HASH_ONLY
                ),
                remediation="",
                explanation=Explanation(summary="recorded", matched_rule=rule),
                risk=RiskScore(value=10, base=10, confidence_multiplier=1.0),
                detector=detector or "",
            )
        except (ValueError, KeyError, TypeError):
            return None

    @classmethod
    def result(cls, row: dict) -> tuple[ScanResult, int]:
        """(the scan result of a row, how many of its findings were not a finding's)."""
        entries = [
            entry
            for entry in row.get("findings") or ()
            if isinstance(entry, list) and len(entry) >= 7
        ]
        built = [cls.finding(entry) for entry in entries]
        findings = tuple(item for item in built if item is not None)
        gaps = tuple(
            (item.rule_id, item.location.path) for item in findings if item.rule_id in CONTENT_GAPS
        )
        complete = row.get("content_complete") is not False
        return ScanResult(findings=findings, content_gaps=gaps, complete=complete), len(
            built
        ) - len(findings)

    @staticmethod
    def blocked(row: dict) -> bool:
        return any(
            len(f) >= 7
            and Content.fails(f[0], f[1], f[2], f[3])
            and Content.is_content(f[0], f[6] or "")
            for f in row.get("findings") or ()
        )


class Harness:
    @classmethod
    def sample(cls, pattern: str, per_group: int) -> list[dict]:
        """`per_group` rows that are blocked and as many that are not: the ones whose hash of file and line is
        smallest, so a rerun takes the same rows."""
        kept: dict[bool, list[tuple[str, dict]]] = {True: [], False: []}
        for path in sorted(Path(pattern).parent.glob(Path(pattern).name)):
            with Path(path).open(encoding="utf-8") as handle:
                for number, line in enumerate(handle):
                    if not line.strip():
                        continue
                    digest = hashlib.sha256(f"{path}:{number}".encode()).hexdigest()
                    bucket = kept[False]
                    if (
                        len(bucket) >= per_group
                        and digest > bucket[-1][0]
                        and len(kept[True]) >= per_group
                        and digest > kept[True][-1][0]
                    ):
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(row, dict):
                        continue
                    bucket = kept[Rows.blocked(row)]
                    bucket.append((digest, row))
                    bucket.sort(key=lambda item: item[0])
                    del bucket[per_group:]
        return [row for _, row in kept[True]] + [row for _, row in kept[False]]

    @classmethod
    def run(cls, patterns: list[str], per_group: int) -> int:
        grid = LegacyBridge.policy_grid()
        today = date.today()
        pairs = agree = rows_seen = unusable = 0
        kinds: collections.Counter[str] = collections.Counter()
        outcomes: collections.Counter[str] = collections.Counter()
        for pattern in patterns:
            for row in cls.sample(pattern, per_group):
                result, bad = Rows.result(row)
                unusable += bad
                rows_seen += 1
                for policy in grid:
                    pairs += 1
                    problems = LegacyBridge.differences(
                        result, policy, today, check_schema=pairs % 50 == 0
                    )
                    if problems:
                        kinds.update(problem.split(":")[0] for problem in problems)
                    else:
                        agree += 1
        outcomes["pairs"], outcomes["agree"], outcomes["differ"] = pairs, agree, pairs - agree
        print(
            f"groups {len(patterns)} rows {rows_seen} policies {len(grid)} pairs {pairs} agree {agree} differ {pairs - agree}"
            f" (each also run twice and with the findings reversed; {-(-pairs // 50)} validated against decision/v1)"
        )
        print(f"findings that were not a finding's fields (skipped): {unusable}")
        print("differences by kind:", dict(kinds))
        return 0 if pairs == agree else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-group", type=int, default=40)
    parser.add_argument("patterns", nargs="+")
    arguments = parser.parse_args()
    raise SystemExit(Harness.run(arguments.patterns, arguments.per_group))
