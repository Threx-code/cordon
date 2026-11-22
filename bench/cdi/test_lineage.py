"""SI-Q11: the lineage check groups by the normalised-content key, never by sha256 alone, and it blocks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench.cdi.gate import Gate
from bench.cdi.lineage import Lineage

SKILL = [["SUSPECT.AGENT.SKILL_INSTRUCTIONS.001", "high", "high", "suspicious", "a/SKILL.md", 3, "agent"]]
OTHER = [["MALWARE.DROPPER.001", "critical", "high", "malicious", "b/setup.py", 9, "dropper"]]
MAL = [["MALWARE.DROPPER.001", "critical", "high", "malicious"]]


class Kit:
    @staticmethod
    def row(name: str, sha: str, findings: list[list[Any]], exit_code: int = 1) -> dict[str, Any]:
        return {"file": name, "sha256": sha, "exit": exit_code, "findings": findings, "seconds": 1.0}


    @staticmethod
    def write(path: Path, rows: list[dict[str, Any]]) -> str:
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return str(path)


class TestTheContentKey:
    def test_a_reworded_copy_has_another_sha256_and_the_same_content_key(self) -> None:
        original = Kit.row("train/a", "sha-1", SKILL)
        reworded = Kit.row("held/a2", "sha-2", [[*SKILL[0][:5], 40, "agent"]])  # same finding, another line
        assert Lineage.sha(original) != Lineage.sha(reworded)
        assert Lineage.content_key(original) == Lineage.content_key(reworded)

    def test_other_content_has_another_key(self) -> None:
        assert Lineage.content_key(Kit.row("a", "s", SKILL)) != Lineage.content_key(Kit.row("b", "s", OTHER))

    def test_the_scanner_and_intel_versions_do_not_move_it(self) -> None:
        a = Kit.row("a", "s", SKILL)
        b = {**a, "verdict": {}, "scanner": "9.9"}
        assert Lineage.content_key(a) == Lineage.content_key(b)

    def test_a_unit_with_no_content_feature_has_no_key(self) -> None:
        assert Lineage.content_key(Kit.row("clean", "s", [], exit_code=0)) is None


class TestTheOverlap:
    def test_a_reworded_copy_is_an_overlap_a_sha256_check_misses(self) -> None:
        train = {"t": Kit.row("train/a", "sha-1", SKILL)}
        held = {"h": Kit.row("held/a2", "sha-2", [[*SKILL[0][:5], 40, "agent"]])}
        assert Lineage.overlap(train, held) == {
            "units": 1,
            "by_content": 1,
            "by_sha256": 0,
            "missed_by_sha256": 1,
        }

    def test_the_same_archive_is_found_by_both(self) -> None:
        train = {"t": Kit.row("a", "sha-1", SKILL)}
        assert Lineage.overlap(train, {"h": Kit.row("b", "sha-1", SKILL)})["by_sha256"] == 1

    def test_two_clean_units_are_not_an_overlap_of_content(self) -> None:
        train = {"t": Kit.row("a", "sha-1", [], 0)}
        held = {"h": Kit.row("b", "sha-2", [], 0)}
        assert Lineage.overlap(train, held)["units"] == 0

    def test_a_clean_unit_is_still_found_by_its_sha256(self) -> None:
        train = {"t": Kit.row("a", "sha-1", [], 0)}
        found = Lineage.overlap(train, {"h": Kit.row("b", "sha-1", [], 0)})
        assert found["units"] == 1 and found["by_content"] == 0

    def test_a_unit_found_by_both_counts_once(self) -> None:
        train = {"t": Kit.row("a", "sha-1", SKILL)}
        assert Lineage.overlap(train, {"h": Kit.row("b", "sha-1", SKILL)})["units"] == 1

    def test_unrelated_units_do_not_overlap(self) -> None:
        train = {"t": Kit.row("a", "sha-1", SKILL)}
        assert Lineage.overlap(train, {"h": Kit.row("b", "sha-2", OTHER)})["units"] == 0


class TestTheGateBlocks:
    def spec(self, tmp_path: Path, train: list[dict], held: list[dict], **extra: Any) -> dict[str, Any]:
        mal = [Kit.row("m1", "x1", MAL), Kit.row("m2", "x2", [], 0)]
        return {
            "candidate_id": "cand:q11",
            "sets": [
                {
                    "name": "mal",
                    "kind": "malware",
                    "area": "pypi",
                    "off": Kit.write(tmp_path / "mo", mal),
                    "on": Kit.write(tmp_path / "mn", mal),
                }
            ],
            "lineage": {
                "train_scans": Kit.write(tmp_path / "train", train),
                "eval_scans": [Kit.write(tmp_path / "held", held)],
            },
            **extra,
        }

    def test_a_reworded_copy_in_train_and_held_fails_the_gate_and_rejects(self, tmp_path: Path) -> None:
        train = [Kit.row("train/a", "sha-1", SKILL)]
        held = [Kit.row("held/a2", "sha-2", [[*SKILL[0][:5], 40, "agent"]])]
        _, decision = Gate.evaluate(self.spec(tmp_path, train, held))
        assert decision["gates"]["lineage"]["result"] == "fail"
        assert "1 of them none by sha256" in decision["gates"]["lineage"]["reason"]
        assert decision["outcome"] == "reject"

    def test_disjoint_content_passes(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(
            self.spec(tmp_path, [Kit.row("a", "s1", SKILL)], [Kit.row("b", "s2", OTHER)])
        )
        assert decision["gates"]["lineage"]["result"] == "pass"

    def test_a_trained_candidate_with_no_lineage_check_fails(self, tmp_path: Path) -> None:
        spec = self.spec(tmp_path, [], [], trained=True)
        del spec["lineage"]
        _, decision = Gate.evaluate(spec)
        assert decision["gates"]["lineage"]["result"] == "fail"
        assert decision["outcome"] == "reject"

    def test_a_candidate_without_a_trained_component_is_not_applicable(self, tmp_path: Path) -> None:
        spec = self.spec(tmp_path, [], [])
        del spec["lineage"]
        _, decision = Gate.evaluate(spec)
        assert decision["gates"]["lineage"]["result"] == "not_applicable"

    def test_the_key_file_form_still_works(self, tmp_path: Path) -> None:
        spec = self.spec(tmp_path, [], [])
        (tmp_path / "tk").write_text("k1\nk2\n", encoding="utf-8")
        (tmp_path / "ek").write_text("k2\n", encoding="utf-8")
        spec["lineage"] = {"train_keys": str(tmp_path / "tk"), "eval_keys": [str(tmp_path / "ek")]}
        _, decision = Gate.evaluate(spec)
        assert decision["gates"]["lineage"]["result"] == "fail"
