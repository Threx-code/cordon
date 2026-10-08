"""A Windows checkout reads the same as the repository: every case again, with CRLF line ends.

Git on Windows checks text out with `\\r\\n` under `core.autocrlf`, which is its default. A parser
written against `\\n` then loses part of the file without an error: a pnpm 10 lockfile's
project document, a Kubernetes manifest's later workloads, a Terraform module after a heredoc,
a local action's steps. Each was found by running this comparison; the unit tests that
reproduce them are beside their fixes. So every valid case is scanned twice, as committed and
with every text file converted, and the dependencies and the findings must be the same.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conformancekit import ConformanceCase, ConformanceRun

CASES = [
    c
    for c in ConformanceCase.all()
    if {"valid", "real-world"} & set(c.expect.get("kinds") or ())
    # A tarball target is bytes, not text: it has no line ends to convert.
    and not c.expect.get("target")
]


class LineEndings:
    @staticmethod
    def to_crlf(root: Path) -> int:
        """Convert every text file under `root` as git would on checkout. Returns how many."""
        converted = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if b"\0" in data or b"\r\n" in data or b"\n" not in data:
                continue
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            path.write_bytes(data.replace(b"\n", b"\r\n"))
            converted += 1
        return converted

    @staticmethod
    def summary(report: dict) -> tuple[set, set]:
        dependencies = {
            (d["ecosystem"], d["name"], d.get("version") or "") for d in report["dependencies"]
        }
        findings = {(f["rule_id"], f["location"].get("path")) for f in report["findings"]}
        return dependencies, findings


class TestAWindowsCheckout:
    @pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
    def test_reads_the_same(self, case, tmp_path) -> None:
        committed = ConformanceRun.report(case.copy_to(tmp_path / "lf"), case)
        project = case.copy_to(tmp_path / "crlf")
        if not LineEndings.to_crlf(project):
            pytest.skip("no text file to convert")
        windows = ConformanceRun.report(project, case)
        (deps_lf, found_lf), (deps_crlf, found_crlf) = (
            LineEndings.summary(committed),
            LineEndings.summary(windows),
        )
        assert deps_crlf == deps_lf, (
            f"{case.id}: with CRLF, lost {sorted(deps_lf - deps_crlf)[:5]}, "
            f"gained {sorted(deps_crlf - deps_lf)[:5]}"
        )
        assert found_crlf == found_lf, (
            f"{case.id}: with CRLF, findings lost {sorted(found_lf - found_crlf)[:5]}, "
            f"gained {sorted(found_crlf - found_lf)[:5]}"
        )
