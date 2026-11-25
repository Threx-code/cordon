"""BP-15-14: the release writes `SHA256SUMS` and one in-toto statement per artefact, and the independent verifier accepts them."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest
from test_verify_artifacts import Release

from support import ROOT

WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


class Loaded:
    @staticmethod
    def script(name: str) -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            name, ROOT / "scripts" / "release" / f"{name}.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class TestTheWriter:
    writer = Loaded.script("write_release_records").ReleaseRecords
    verifier = Loaded.script("verify_artifacts").ArtifactVerifier
    SOURCE: ClassVar[dict[str, str]] = {
        "repository": "owner/cordon",
        "commit": "a" * 40,
        "run": "https://example.invalid/run/1",
    }

    def release(self, tmp_path: Path) -> Path:
        built = tmp_path / "built"
        built.mkdir()
        files = Release.build(built)
        shipped = tmp_path / "shipped"
        shipped.mkdir()
        records = tmp_path / "records"
        self.writer.write(records, files, self.SOURCE)
        for path in [*files, *records.iterdir()]:
            shutil.copy(path, shipped / path.name)
        return shipped

    def test_what_it_writes_is_accepted_by_the_independent_verifier(self, tmp_path: Path) -> None:
        assert self.verifier.problems(self.release(tmp_path)) == []

    def test_each_statement_names_its_artefact_and_where_it_was_built(self, tmp_path: Path) -> None:
        shipped = self.release(tmp_path)
        statement = json.loads(
            (shipped / "cordon-1.0.vsix.intoto.json").read_text(encoding="utf-8")
        )
        assert (
            statement["subject"][0]["name"] == "cordon-1.0.vsix"
            and statement["predicate"] == self.SOURCE
        )
        assert statement["_type"] == "https://in-toto.io/Statement/v1"

    def test_a_flipped_byte_after_writing_is_refused(self, tmp_path: Path) -> None:
        shipped = self.release(tmp_path)
        wheel = shipped / "cordon_scanner-1.0-py3-none-any.whl"
        data = bytearray(wheel.read_bytes())
        data[len(data) // 2] ^= 1
        wheel.write_bytes(bytes(data))
        assert any("digest differs" in line for line in self.verifier.problems(shipped))

    def test_two_artefacts_with_one_name_are_refused(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        one, two = tmp_path / "a" / "x.whl", tmp_path / "b" / "x.whl"
        one.write_bytes(b"1")
        two.write_bytes(b"2")
        with pytest.raises(ValueError):
            self.writer.write(tmp_path / "out", [one, two], self.SOURCE)


class TestTheWorkflowWritesThem:
    text = WORKFLOW.read_text(encoding="utf-8")

    def test_a_step_writes_the_records_for_the_wheel_sdist_and_vsix(self) -> None:
        step = self.text.split("Write the sums and a statement for each artefact", 1)[1].split(
            "- name:", 1
        )[0]
        assert "scripts/release/write_release_records.py artefacts/records" in step
        assert all(
            part in step
            for part in ("artefacts/dist/*.whl", "artefacts/dist/*.tar.gz", "artefacts/*.vsix")
        )
        assert '--commit "$GITHUB_SHA"' in step

    def test_the_step_comes_after_the_vsix_is_built_and_before_the_release_is_made(self) -> None:
        written = self.text.index("Write the sums and a statement for each artefact")
        assert (
            self.text.index("vsce@3.6.0 package") < written < self.text.index("gh release create")
        )

    def test_the_release_page_carries_the_records(self) -> None:
        create = self.text.split("gh release create", 1)[1].split("||", 1)[0]
        assert "artefacts/records/*" in create

    def test_the_live_signature_check_is_named_not_claimed(self) -> None:
        assert "gh attestation verify" in self.text
