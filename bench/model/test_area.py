"""The one-entry-point contract helpers (pure): training-list sha + metrics.json."""

from __future__ import annotations

import json

from bench.model import area


class TestTrainingListSha:
    def test_order_and_dupes_do_not_matter(self):
        assert area.Contract.training_list_sha(["b", "a", "a"]) == area.Contract.training_list_sha(["a", "b"])

    def test_different_set_different_sha(self):
        assert area.Contract.training_list_sha(["a", "b"]) != area.Contract.training_list_sha(["a", "c"])

    def test_prefixed(self):
        assert area.Contract.training_list_sha(["a"]).startswith("sha256:")


class TestFileSha:
    def test_same_bytes_same_sha(self, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text('{"x": 1}', encoding="utf-8")
        b.write_text('{"x": 1}', encoding="utf-8")
        assert area.Contract.file_sha(a) == area.Contract.file_sha(b)
        assert area.Contract.file_sha(a).startswith("sha256:")

    def test_different_bytes_differ(self, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text('{"x": 1}', encoding="utf-8")
        b.write_text('{"x": 2}', encoding="utf-8")
        assert area.Contract.file_sha(a) != area.Contract.file_sha(b)


class TestWriteContract:
    def test_writes_both_artefacts(self, tmp_path):
        body = area.Contract.write_contract(
            tmp_path / "m",
            area="verdict",
            seed=7,
            train_ids=["pkg:a@1", "pkg:b@2"],
            metrics={"recall": 0.989, "benign_rate": 0.004, "threshold": 0.42},
        )
        out = tmp_path / "m"
        sha = (out / "training_list.sha256").read_text(encoding="utf-8").strip()
        meta = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
        assert sha == area.Contract.training_list_sha(["pkg:a@1", "pkg:b@2"])
        assert meta["area"] == "verdict"
        assert meta["seed"] == 7
        assert meta["n_train"] == 2
        assert meta["training_list_sha"] == sha
        assert meta["recall"] == 0.989
        assert body == meta

    def test_deterministic(self, tmp_path):
        kw = {"area": "code", "seed": 0, "train_ids": ["x", "y"], "metrics": {"recall": 1.0}}
        a = area.Contract.write_contract(tmp_path / "a", **kw)
        b = area.Contract.write_contract(tmp_path / "b", **kw)
        assert a == b
