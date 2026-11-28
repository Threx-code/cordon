"""Coverage that can only go up: every source file's count of untested lines (and branches, when measured) is recorded,
and a run fails when any file has more than its record.

A whole-suite percentage hides a regression: a change that adds a hundred tested lines to one file and leaves ten
untested in another keeps the total where it was. Counting per file closes that. A file not in the record is new code
and is held to zero untested lines from its first commit. A file in the record that no longer exists fails too, so
the record cannot keep a dead entry. When tests close a gap, `--update` lowers that file's number; nothing ever
raises one.

    python scripts/checks/coverage_floor.py check coverage.json
    python scripts/checks/coverage_floor.py update coverage.json      # after closing gaps: record the new, lower counts

`coverage.json` is `coverage json` output of the whole suite (CI's joined parts).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, ClassVar


class CoverageFloor:
    RECORD: ClassVar[str] = "tests/unit/repository/release/coverage_floors.json"
    PREFIX: ClassVar[str] = "src/"

    @classmethod
    def untested(cls, report: dict[str, Any]) -> dict[str, int]:
        """Untested lines plus untested branches, per source file under `src/`."""
        out: dict[str, int] = {}
        for name, data in report.get("files", {}).items():
            path = Path(name).as_posix()
            at = path.find(cls.PREFIX)
            if at < 0:
                continue
            summary = data["summary"]
            out[path[at:]] = int(summary.get("missing_lines", 0)) + int(
                summary.get("missing_branches", 0)
            )
        return out

    @classmethod
    def problems(cls, measured: dict[str, int], record: dict[str, int]) -> list[str]:
        found = []
        for path, count in sorted(measured.items()):
            allowed = record.get(path, 0)
            if count > allowed:
                origin = "recorded" if path in record else "new file, allowed"
                found.append(f"{path}: {count} untested, {origin} {allowed}: add tests")
        for path in sorted(set(record) - set(measured)):
            found.append(f"{path}: in the record but not measured: remove it from {cls.RECORD}")
        return found

    @classmethod
    def lowered(cls, measured: dict[str, int], record: dict[str, int]) -> dict[str, int]:
        """The record after closing gaps: each file's count only falls; files at zero and dead files leave it."""
        out = {}
        for path, count in measured.items():
            kept = min(count, record.get(path, count))
            if kept > 0:
                out[path] = kept
        return dict(sorted(out.items()))

    @classmethod
    def main(cls, argv: list[str]) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("action", choices=("check", "update"))
        parser.add_argument("report", type=Path)
        parser.add_argument("--root", type=Path, default=Path.cwd())
        args = parser.parse_args(argv)
        measured = cls.untested(json.loads(args.report.read_text(encoding="utf-8")))
        if not measured:
            print("the report measured no source file under src/: refusing to judge an empty run")
            return 2
        path = args.root / cls.RECORD
        record = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        if args.action == "update":
            new = cls.lowered(measured, record)
            path.write_text(json.dumps(new, indent=1) + "\n", encoding="utf-8")
            print(
                f"{len(new)} file(s) still below 100%; {sum(new.values())} untested lines/branches"
            )
            return 0
        found = cls.problems(measured, record)
        print(
            f"{len(measured)} source files measured; {len(record)} recorded below 100%; {len(found)} problem(s)"
        )
        for line in found:
            print(f"  {line}")
        return 1 if found else 0


if __name__ == "__main__":
    sys.exit(CoverageFloor.main(sys.argv[1:]))
