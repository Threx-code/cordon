"""The invariants of a paired run: declared sides, a digest checked before the run, and rows that are never edited."""

from __future__ import annotations

from pathlib import Path

import pytest
from bench.cdi.harness import BadDeclaration, EditedRow, EditedTree, PairRun, Row, TreeDigest

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


class Kit:
    @staticmethod
    def tree(root: Path, body: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "rules.yaml").write_text(body, encoding="utf-8")
        (root / "engine.py").write_text("RULES = 1\n", encoding="utf-8")
        return root

    @classmethod
    def declared(cls, tmp_path: Path):
        base = cls.tree(tmp_path / "base", "rule: a\n")
        cand = cls.tree(tmp_path / "cand", "rule: b\n")
        digests = {"base": TreeDigest.of_directory(base), "candidate": TreeDigest.of_directory(cand)}
        return (
            PairRun.declare("base", COMMIT_A, digests["base"]),
            PairRun.declare("candidate", COMMIT_B, digests["candidate"]),
            base,
            cand,
            digests,
        )


class TestAPairRunOnAnEditedTreeIsRefused:
    def test_untouched_trees_may_run_and_the_record_names_the_harness(self, tmp_path: Path) -> None:
        base, cand, _, _, digests = Kit.declared(tmp_path)
        record = PairRun.start(base, cand, digests)
        assert record["harness"] == "1" and record["base"]["commit"] == COMMIT_A

    def test_a_candidate_tree_edited_after_it_was_declared_is_refused_by_name(self, tmp_path: Path) -> None:
        base, cand, _, cand_dir, _ = Kit.declared(tmp_path)
        (cand_dir / "rules.yaml").write_text("rule: b\nextra: 1\n", encoding="utf-8")
        now = {"base": TreeDigest.of_directory(tmp_path / "base"), "candidate": TreeDigest.of_directory(cand_dir)}
        with pytest.raises(EditedTree, match="candidate tree was edited"):
            PairRun.start(base, cand, now)

    def test_a_base_tree_edited_after_it_was_declared_is_refused_by_name(self, tmp_path: Path) -> None:
        base, cand, base_dir, _, _ = Kit.declared(tmp_path)
        (base_dir / "engine.py").write_text("RULES = 2\n", encoding="utf-8")
        now = {"base": TreeDigest.of_directory(base_dir), "candidate": TreeDigest.of_directory(tmp_path / "cand")}
        with pytest.raises(EditedTree, match="base tree was edited"):
            PairRun.start(base, cand, now)

    def test_a_file_added_to_a_tree_changes_its_digest(self, tmp_path: Path) -> None:
        root = Kit.tree(tmp_path / "t", "x: 1\n")
        before = TreeDigest.of_directory(root)
        (root / "new.py").write_text("x = 1\n", encoding="utf-8")
        assert TreeDigest.of_directory(root) != before

    def test_the_same_files_in_another_folder_have_the_same_digest(self, tmp_path: Path) -> None:
        assert TreeDigest.of_directory(Kit.tree(tmp_path / "one", "x: 1\n")) == TreeDigest.of_directory(
            Kit.tree(tmp_path / "two", "x: 1\n")
        )


class TestBothSidesAreDeclared:
    def test_a_side_named_neither_base_nor_candidate_is_refused(self) -> None:
        with pytest.raises(BadDeclaration, match="base or the candidate"):
            PairRun.declare("head", COMMIT_A, "0" * 64)

    def test_a_commit_that_is_not_a_hash_is_refused(self) -> None:
        with pytest.raises(BadDeclaration, match="not a commit hash"):
            PairRun.declare("base", "main", "0" * 64)

    def test_a_digest_that_is_not_a_sha256_is_refused(self) -> None:
        with pytest.raises(BadDeclaration, match="not a sha256"):
            PairRun.declare("candidate", COMMIT_A, "abc")

    def test_the_sides_may_not_be_swapped(self, tmp_path: Path) -> None:
        base, cand, _, _, digests = Kit.declared(tmp_path)
        with pytest.raises(BadDeclaration, match="not declared as the base"):
            PairRun.start(cand, base, digests)

    def test_one_tree_declared_for_both_sides_is_refused(self, tmp_path: Path) -> None:
        base, _, _, _, digests = Kit.declared(tmp_path)
        twin = PairRun.declare("candidate", COMMIT_B, base["tree_digest"])
        with pytest.raises(BadDeclaration, match="same tree"):
            PairRun.start(base, twin, digests)


class TestRowsAreNeverEdited:
    def test_a_sealed_row_reads_back_unchanged(self) -> None:
        row = Row.seal({"unit": "u1", "blocked": True})
        assert Row.read(row) == {"unit": "u1", "blocked": True, "harness": "1"}

    def test_an_edited_row_is_refused(self) -> None:
        row = Row.seal({"unit": "u1", "blocked": True})
        row["blocked"] = False
        with pytest.raises(EditedRow, match="edited after"):
            Row.read(row)

    def test_a_row_with_no_harness_version_is_refused(self) -> None:
        with pytest.raises(EditedRow, match="no harness version"):
            Row.read({"unit": "u1", "blocked": True, "row_digest": "x"})
