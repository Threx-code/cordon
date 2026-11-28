"""Reasons that rest on a dated reading of the world, re-read before they go stale.

A reason that says why an ecosystem lacks something ("no verifiable per-release signature was found on ...
(checked 2026-11-25)") is true only as of that reading: a registry that starts publishing provenance, or a dataset
that adds an ecosystem, turns the reason into a gap without any code changing. This lists every dated reason in the
source and the narrow-site record, and fails when one is older than MAX_AGE_DAYS, so the reading is redone (and the
reason re-dated, or the gap built) instead of the reason quietly outliving the fact.

Run by the scheduled `recheck-reasons` workflow, never by the test suite: a check that depends on today's date
belongs on a schedule, not in tests that must pass on any day.

    python scripts/checks/stale_reasons.py [--today YYYY-MM-DD] [--max-age-days N]
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path
from typing import ClassVar


class StaleReasons:
    #: Where dated reasons live: the source tree and the narrow-site record.
    PLACES: ClassVar[tuple[str, ...]] = ("src", "tests/unit/ecosystems/coverage/narrow_sites.json")
    DATED: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:checked|read on)\s+(\d{4}-\d{2}-\d{2})", re.IGNORECASE
    )
    MAX_AGE_DAYS: ClassVar[int] = 120

    @classmethod
    def files(cls, root: Path) -> list[Path]:
        out: list[Path] = []
        for place in cls.PLACES:
            path = root / place
            if path.is_file():
                out.append(path)
            elif path.is_dir():
                out.extend(sorted(p for p in path.rglob("*.py") if p.is_file()))
        return out

    @classmethod
    def dated(cls, root: Path) -> list[tuple[str, int, datetime.date]]:
        """(file, line, date) for every dated reason."""
        found = []
        for path in cls.files(root):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for match in cls.DATED.finditer(line):
                    try:
                        when = datetime.date.fromisoformat(match.group(1))
                    except ValueError:
                        continue
                    found.append((path.relative_to(root).as_posix(), number, when))
        return found

    @classmethod
    def stale(
        cls, root: Path, today: datetime.date, max_age_days: int
    ) -> list[tuple[str, int, datetime.date]]:
        return [d for d in cls.dated(root) if (today - d[2]).days > max_age_days]

    @classmethod
    def main(cls, argv: list[str]) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--today", type=datetime.date.fromisoformat, default=None)
        parser.add_argument("--max-age-days", type=int, default=cls.MAX_AGE_DAYS)
        parser.add_argument(
            "--root", type=Path, default=Path.cwd(), help="the repository root (default: .)"
        )
        args = parser.parse_args(argv)
        today = args.today or datetime.datetime.now(datetime.UTC).date()
        dated = cls.dated(args.root)
        stale = cls.stale(args.root, today, args.max_age_days)
        print(f"{len(dated)} dated reason(s); {len(stale)} older than {args.max_age_days} days")
        for file, line, when in stale:
            print(
                f"  {file}:{line}: checked {when.isoformat()}: re-read the source and re-date, or build the gap"
            )
        return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(StaleReasons.main(sys.argv[1:]))
