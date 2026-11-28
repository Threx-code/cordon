"""`scripts/checks/coverage_floor.py`: a file's untested count can only fall, new files start at zero, and every line
kept out of coverage says why."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from support import ROOT


class Kit:
    @staticmethod
    def floor():
        spec = importlib.util.spec_from_file_location(
            "coverage_floor", ROOT / "scripts/checks/coverage_floor.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.CoverageFloor

    @staticmethod
    def report(**files: tuple[int, int]) -> dict:
        return {
            "files": {
                f"/tmp/w/src/cordon_scanner/{name}.py": {
                    "summary": {"missing_lines": lines, "missing_branches": branches}
                }
                for name, (lines, branches) in files.items()
            }
        }


class TestCounting:
    def test_lines_and_branches_both_count(self) -> None:
        measured = Kit.floor().untested(Kit.report(a=(3, 2)))
        assert measured == {"src/cordon_scanner/a.py": 5}

    def test_files_outside_src_are_ignored(self) -> None:
        report = {"files": {"/tmp/copy/x.py": {"summary": {"missing_lines": 9}}}}
        assert Kit.floor().untested(report) == {}


class TestCheck:
    def test_a_file_at_its_record_passes(self) -> None:
        floor = Kit.floor()
        assert floor.problems({"src/a.py": 4}, {"src/a.py": 4}) == []

    def test_one_more_untested_line_fails(self) -> None:
        found = Kit.floor().problems({"src/a.py": 5}, {"src/a.py": 4})
        assert len(found) == 1 and "src/a.py: 5 untested" in found[0]

    def test_a_new_file_must_be_fully_tested(self) -> None:
        found = Kit.floor().problems({"src/new.py": 1}, {})
        assert len(found) == 1 and "new file" in found[0]

    def test_a_new_fully_tested_file_passes(self) -> None:
        assert Kit.floor().problems({"src/new.py": 0}, {}) == []

    def test_a_dead_record_entry_fails(self) -> None:
        found = Kit.floor().problems({}, {"src/gone.py": 3})
        assert len(found) == 1 and "remove it" in found[0]


class TestUpdate:
    def test_counts_only_fall(self) -> None:
        new = Kit.floor().lowered({"src/a.py": 2, "src/b.py": 9}, {"src/a.py": 5, "src/b.py": 4})
        assert new == {"src/a.py": 2, "src/b.py": 4}

    def test_a_file_at_zero_leaves_the_record(self) -> None:
        assert Kit.floor().lowered({"src/a.py": 0}, {"src/a.py": 5}) == {}

    def test_an_empty_report_is_refused(self, tmp_path: Path) -> None:
        report = tmp_path / "c.json"
        report.write_text('{"files": {}}', encoding="utf-8")
        assert Kit.floor().main(["check", str(report), "--root", str(tmp_path)]) == 2


class TestTheRecord:
    def test_every_entry_names_a_source_file_with_a_positive_count(self) -> None:
        path = ROOT / Kit.floor().RECORD
        record = json.loads(path.read_text(encoding="utf-8"))
        for name, count in record.items():
            assert (ROOT / name).is_file(), f"{name} is recorded but does not exist"
            assert isinstance(count, int) and count > 0, f"{name}: {count!r}"


class TestExclusionsSayWhy:
    #: `pragma: no cover` followed by a dash and a reason of at least three words.
    REASONED = re.compile(r"pragma: no cover\s*[-—]+\s*\S+(?:\s+\S+){2,}")

    def test_every_excluded_line_carries_a_reason(self) -> None:
        bare = []
        for path in sorted((ROOT / "src").rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "pragma: no cover" in line and not self.REASONED.search(line):
                    bare.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
        assert not bare, (
            "a line kept out of coverage must say why, in three words or more after a dash "
            "(`# pragma: no cover - only Windows has no fork`), or be tested instead:\n  "
            + "\n  ".join(bare)
        )
