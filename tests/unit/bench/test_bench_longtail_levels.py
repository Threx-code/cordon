"""The long-tail summary separates what must not be mixed, and checks its own data before use.

```
  split       sha256("<eco>:<name>")[0] even -> work, odd -> holdout   (fixed, published)
  kind        VULNERABLE.* -> vulnerability · SECRET.* -> secret · MALWARE./SUSPECT.* -> code
              SUSPECT.IAC./K8S./CFN. -> iac-or-policy
  incomplete  members rejected / truncated / timeout -> content     (a detection gap)
              only advisory notes                    -> advisory-only (every byte was read)
  integrity   one result per manifest entry · scanner errors < 0.1% · scanner version recorded
  holdout     adjudicate.show refuses holdout files unless --release
```
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "tools"))
sys.path.insert(0, str(REPO / "bench" / "suites"))
sys.path.insert(0, str(REPO / "bench"))

from adjudicate import Adjudicate
from longtail_levels import Incomplete, Kind, LongtailLevels, Split


class TestSplit:
    def test_the_rule_is_stable_and_case_insensitive(self) -> None:
        assert Split.of("npm", "Left-Pad") == Split.of("npm", "left-pad")
        assert Split.of("npm", "left-pad") in ("work", "holdout")

    def test_both_halves_are_used(self) -> None:
        halves = {Split.of("npm", f"pkg-{i}") for i in range(50)}
        assert halves == {"work", "holdout"}


class TestKind:
    def test_rule_families(self) -> None:
        assert Kind.of("VULNERABLE.DEPENDENCY.KNOWN.001") == "vulnerability"
        assert Kind.of("SECRET.PRIVATE_KEY.001") == "secret"
        assert Kind.of("MALWARE.DROPPER.001") == "malicious-or-suspicious-code"
        assert Kind.of("SUSPECT.K8S.HOST_NETWORK.001") == "iac-or-policy"

    def test_code_outranks_a_cve_when_both_block(self) -> None:
        assert Kind.primary({"vulnerability", "malicious-or-suspicious-code"}) == (
            "malicious-or-suspicious-code"
        )


class TestIncomplete:
    def test_a_rejected_member_is_a_content_gap(self) -> None:
        rec = {
            "complete": False,
            "findings": [["OPERATIONAL.ARCHIVE.MEMBER_REJECTED", "", "", "", ""]],
        }
        assert Incomplete.kind(rec) == "content"

    def test_a_missing_feed_alone_is_not(self) -> None:
        rec = {
            "complete": False,
            "findings": [["OPERATIONAL.ADVISORY.NO_FEED.001", "", "", "", ""]],
        }
        assert Incomplete.kind(rec) == "advisory-only"

    def test_a_complete_scan_has_no_kind(self) -> None:
        assert Incomplete.kind({"complete": True, "findings": []}) is None


class LongtailData:
    @staticmethod
    def write(tmp: Path, manifest: list[dict], scans: list[dict], version: bool = True) -> Path:
        (tmp / "manifest.jsonl").write_text(
            "".join(json.dumps(m) + "\n" for m in manifest), "utf-8"
        )
        (tmp / "scans.jsonl").write_text("".join(json.dumps(s) + "\n" for s in scans), "utf-8")
        if version:
            (tmp / "scanner-version.json").write_text('{"commit": "x"}', "utf-8")
        return tmp


class TestIntegrity:
    MANIFEST: ClassVar[list[dict[str, str]]] = [
        {"file": "npm/a-1.tgz", "ecosystem": "npm", "name": "a"},
        {"file": "npm/b-1.tgz", "ecosystem": "npm", "name": "b"},
    ]

    def test_a_complete_run_is_ok(self, tmp_path: Path) -> None:
        scans = [{"file": m["file"], "exit": 0, "findings": []} for m in self.MANIFEST]
        summary = LongtailLevels.main(LongtailData.write(tmp_path, self.MANIFEST, scans))
        assert summary["integrity"]["ok"]

    def test_a_missing_result_is_reported(self, tmp_path: Path) -> None:
        scans = [{"file": "npm/a-1.tgz", "exit": 0, "findings": []}]
        integrity = LongtailLevels.main(LongtailData.write(tmp_path, self.MANIFEST, scans))[
            "integrity"
        ]
        assert not integrity["ok"] and integrity["missing"] == 1

    def test_scanner_errors_void_the_run(self, tmp_path: Path) -> None:
        scans = [{"file": m["file"], "exit": 2} for m in self.MANIFEST]
        integrity = LongtailLevels.main(LongtailData.write(tmp_path, self.MANIFEST, scans))[
            "integrity"
        ]
        assert not integrity["ok"]
        assert any("scanner errors" in p for p in integrity["problems"])

    def test_an_unnamed_scanner_is_reported(self, tmp_path: Path) -> None:
        scans = [{"file": m["file"], "exit": 0, "findings": []} for m in self.MANIFEST]
        integrity = LongtailLevels.main(
            LongtailData.write(tmp_path, self.MANIFEST, scans, version=False)
        )["integrity"]
        assert not integrity["ok"]


class TestHoldoutRefusal:
    def manifest(self, n: int = 40) -> dict:
        return {f"npm/p{i}-1.tgz": {"ecosystem": "npm", "name": f"p{i}"} for i in range(n)}

    def test_holdout_files_are_refused_while_tuning(self) -> None:
        manifest = self.manifest()
        refused = Adjudicate.holdout_refused(manifest, list(manifest))
        assert refused
        assert all(Split.of("npm", manifest[f]["name"]) == "holdout" for f in refused)

    def test_show_stops_before_fetching_anything(self, tmp_path: Path) -> None:
        manifest = self.manifest()
        holdout = Adjudicate.holdout_refused(manifest, list(manifest))[0]
        rows = [{"file": f, **m} for f, m in manifest.items()]
        LongtailData.write(tmp_path, rows, [{"file": holdout, "exit": 1, "findings": []}])
        with pytest.raises(SystemExit, match="holdout"):
            Adjudicate.show(tmp_path, [holdout])

    def test_excluded_files_leave_the_holdout_half(self, tmp_path: Path) -> None:
        manifest = self.manifest()
        rows = [{"file": f, **m} for f, m in manifest.items()]
        scans = [{"file": f, "exit": 0, "findings": []} for f in manifest]
        LongtailData.write(tmp_path, rows, scans)
        before = LongtailLevels.main(tmp_path, "holdout")["all"]["scanned"]
        excluded = Adjudicate.holdout_refused(manifest, list(manifest))[:2]
        (tmp_path / "holdout-excluded.txt").write_text("\n".join(excluded), "utf-8")
        after = LongtailLevels.main(tmp_path, "holdout")["all"]["scanned"]
        assert after == before - 2
