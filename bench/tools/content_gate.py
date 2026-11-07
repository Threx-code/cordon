#!/usr/bin/env python3
"""The merge gate for a change that narrows a detection (release 0.8.0 item 18): content blocks
compared per unit, before against after, on the same units.

Two narrowing changes (07398602, c604b7ca) each claimed "lose 0" from exit statuses and from the
subset they meant to touch, and each lost PyPI content blocks (15 and 2) that intel hid. Exit status
mixes content with intel; a subset hides what the change reached outside it. So this reads every
row, scores each unit as content recall does (`content.py`, G4), and compares unit by unit:

```
  malware rows:  content-blocked before, not after  -> LOST     (fails the gate)
  benign rows:   content-blocked after, not before  -> ADDED    (fails the gate)
  either:        a scan complete before, failed after -> BROKE  (fails the gate)
  a unit in one file and not the other, or two rows for one unit that disagree -> input error
```

A loss or an added block the change means to make is named in `--accept` (a file of
`unit<TAB>why` lines); everything else fails. The rules each changed unit gained and lost are in
the report, so a trade can be read rather than counted.

    python bench/tools/content_gate.py --kind malware before.jsonl after.jsonl
    python bench/tools/content_gate.py --kind benign before.jsonl after.jsonl --accept trades.tsv

Exit 0: passed. 1: an unaccepted LOST, ADDED or BROKE. 2: the inputs cannot be compared.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from content import Content


class GateInputError(Exception):
    """The two row files cannot be compared unit by unit."""


@dataclass(frozen=True)
class UnitScore:
    """One unit's row, as the gate reads it."""

    blocked: bool
    complete: bool
    rules: frozenset[str]

    @staticmethod
    def of(row: dict[str, Any]) -> UnitScore:
        """A row from the rescan harness: `findings` as [rule, severity, confidence, category,
        path, _, detector]; a row with no `findings` (a timeout, a parse error) is a failed scan."""
        rules = frozenset(
            f[0]
            for f in row.get("findings") or ()
            if Content.fails(f[0], f[1], f[2], f[3]) and Content.is_content(f[0], f[6] or "")
        )
        complete = "findings" in row and bool(row.get("content_complete", False))
        return UnitScore(blocked=bool(rules), complete=complete, rules=rules)


@dataclass
class GateReport:
    kind: str
    units: int = 0
    lost: list[dict[str, Any]] = field(default_factory=list)
    added: list[dict[str, Any]] = field(default_factory=list)
    broke: list[dict[str, Any]] = field(default_factory=list)
    gained: list[str] = field(default_factory=list)
    accepted: list[dict[str, Any]] = field(default_factory=list)
    blocked_before: int = 0
    blocked_after: int = 0

    @property
    def failing(self) -> list[dict[str, Any]]:
        return [*self.lost, *self.added, *self.broke]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "units": self.units,
            "blocked_before": self.blocked_before,
            "blocked_after": self.blocked_after,
            "lost": self.lost,
            "added": self.added,
            "broke": self.broke,
            "gained": self.gained,
            "accepted": self.accepted,
            "passed": not self.failing,
        }


class ContentGate:
    """Before against after, per unit."""

    @staticmethod
    def rows(path: Path) -> dict[str, UnitScore]:
        """Each unit's score. A unit written twice (a resumed run) is read once when both rows
        agree, and refused when they do not."""
        scores: dict[str, UnitScore] = {}
        with path.open(encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    unit = row["file"]
                except (json.JSONDecodeError, KeyError, TypeError) as error:
                    raise GateInputError(f"{path}:{number}: not a scan row ({error})") from error
                score = UnitScore.of(row)
                if unit in scores and scores[unit] != score:
                    raise GateInputError(f"{path}: two rows for {unit} disagree")
                scores[unit] = score
        return scores

    @staticmethod
    def accepted(path: Path | None) -> dict[str, str]:
        if path is None:
            return {}
        out: dict[str, str] = {}
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            unit, _, why = line.partition("\t")
            if not why.strip():
                raise GateInputError(f"{path}:{number}: an accepted unit needs a reason")
            out[unit] = why.strip()
        return out

    @staticmethod
    def compare(
        kind: str,
        before: dict[str, UnitScore],
        after: dict[str, UnitScore],
        accept: dict[str, str],
    ) -> GateReport:
        if kind not in ("malware", "benign"):
            raise GateInputError(f"--kind is malware or benign, not {kind!r}")
        only = sorted(set(before) ^ set(after))
        if only:
            raise GateInputError(
                f"{len(only)} units are in one file and not the other, e.g. {only[:3]}"
            )
        unknown = sorted(set(accept) - set(before))
        if unknown:
            raise GateInputError(f"accepted units not in the rows: {unknown[:3]}")
        report = GateReport(kind=kind, units=len(before))
        for unit in sorted(before):
            b, a = before[unit], after[unit]
            report.blocked_before += b.blocked
            report.blocked_after += a.blocked
            entry = {
                "unit": unit,
                "rules_lost": sorted(b.rules - a.rules),
                "rules_gained": sorted(a.rules - b.rules),
            }
            if b.complete and not a.complete:
                bucket = report.broke
            elif kind == "malware" and b.blocked and not a.blocked:
                bucket = report.lost
            elif kind == "benign" and a.blocked and not b.blocked:
                bucket = report.added
            else:
                if kind == "malware" and a.blocked and not b.blocked:
                    report.gained.append(unit)
                continue
            if unit in accept:
                report.accepted.append({**entry, "why": accept[unit]})
            else:
                bucket.append(entry)
        return report

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("before", type=Path)
        parser.add_argument("after", type=Path)
        parser.add_argument("--kind", required=True, choices=("malware", "benign"))
        parser.add_argument(
            "--accept", type=Path, help="unit<TAB>why lines: trades made on purpose"
        )
        parser.add_argument("--json", type=Path, help="write the full report here")
        args = parser.parse_args(argv)
        try:
            report = ContentGate.compare(
                args.kind,
                ContentGate.rows(args.before),
                ContentGate.rows(args.after),
                ContentGate.accepted(args.accept),
            )
        except (GateInputError, OSError) as error:
            print(f"content gate: cannot compare: {error}", file=sys.stderr)
            return 2
        if args.json is not None:
            args.json.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(
            f"{report.kind}: {report.units} units, content-blocked {report.blocked_before} -> "
            f"{report.blocked_after}; lost {len(report.lost)}, added {len(report.added)}, "
            f"broke {len(report.broke)}, accepted {len(report.accepted)}, "
            f"gained {len(report.gained)}"
        )
        for name, rows in (("LOST", report.lost), ("ADDED", report.added), ("BROKE", report.broke)):
            for row in rows:
                print(
                    f"  {name} {row['unit']}  -{','.join(row['rules_lost']) or '.'}"
                    f"  +{','.join(row['rules_gained']) or '.'}"
                )
        print("PASSED" if not report.failing else "FAILED")
        return 0 if not report.failing else 1


if __name__ == "__main__":
    sys.exit(ContentGate.main())
