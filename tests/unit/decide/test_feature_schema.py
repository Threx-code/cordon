"""The verdict features' schema version (`decide/feature_schema`): derived from the extractor's code
and the feature names, moved by what changes the features and by nothing else."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cordon_scanner.decide.feature_schema import FeatureSchema
from cordon_scanner.decide.verdict import Verdict
from cordon_scanner.foundation.paths import PackagePaths


class SchemaKit:
    """A copy of the extractor's files, to edit and read the version of."""

    @staticmethod
    def tree(where: Path) -> Path:
        for path, _ in FeatureSchema.EXTRACTOR:
            (where / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(PackagePaths.root() / path, where / path)
        return where

    @staticmethod
    def edit(root: Path, path: str, old: str, new: str) -> None:
        text = (root / path).read_text(encoding="utf-8")
        assert text.count(old) == 1, old
        (root / path).write_text(text.replace(old, new), encoding="utf-8")


class TestTheVersion:
    def test_it_is_derived_and_stable(self) -> None:
        version = FeatureSchema.version()
        assert version.startswith(FeatureSchema.PREFIX)
        assert version == FeatureSchema.version() == FeatureSchema.current()

    def test_a_copy_of_the_tree_has_the_same_version(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        assert FeatureSchema.version(root, FeatureSchema.names()) == FeatureSchema.version()

    def test_a_docstring_or_comment_edit_leaves_it(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root,
            "decide/verdict.py",
            '"""What the model scores, from (rule, severity, confidence, category, path) per finding.',
            '"""What the model scores (reworded), from (rule, severity, confidence, category, path).\n'
            "        # and a comment",
        )
        assert FeatureSchema.version(root, FeatureSchema.names()) == FeatureSchema.version()

    def test_a_change_to_what_is_computed_moves_it(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root,
            "decide/verdict.py",
            'out[key + "#n"] = out.get(key + "#n", 0.0) + 1.0',
            'out[key + "#n"] = out.get(key + "#n", 0.0) + 2.0',
        )
        assert FeatureSchema.version(root, FeatureSchema.names()) != FeatureSchema.version()

    def test_a_new_feature_name_moves_it(self) -> None:
        names = FeatureSchema.names()
        assert FeatureSchema.version(None, [*names, "pkg:new_fact"]) != FeatureSchema.version()

    def test_a_stale_extractor_list_fails_loudly(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root, "engine/pipeline/history.py", "def registry_facts(", "def renamed_facts("
        )
        with pytest.raises(LookupError, match=r"History\.registry_facts"):
            FeatureSchema.version(root, FeatureSchema.names())


class TestTheRecord:
    def test_every_verdict_record_names_its_schema(self) -> None:
        _, summary = Verdict.decide(
            [], [("package/package.json", 10)], {"package/package.json": b"{}"}
        )
        assert summary["schema"] == FeatureSchema.current()
