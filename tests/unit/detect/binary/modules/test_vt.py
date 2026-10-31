"""The `vt` module (modules.reports.vt): its schema regenerated from YARA-X's .proto files is the file
committed, the metadata it reads fits the declaration, and a ruleset matching files is refused the
fields YARA-X refuses there. Its answers against YARA-X's own vt (through the reference harness) are
held by the R10 comparison."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from cordon_scanner.detect.binary.modules.reports.vt import Vt, VtData, VtSchema
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from support import ROOT

GENERATED = ROOT / "src" / "cordon_scanner" / "detect" / "data" / "vt-schema.json"

META = {
    "meta": {
        "sha256": "ABCDEF00",
        "fileType": "PE_EXE",
        "fileSize": "1024",
        "tags": ["peexe", "signed"],
        "firstSubmissionDate": "1767323045",
        "exiftool": {"CompanyName": "x"},
    }
}


class TestTheGeneratedSchema:
    def test_regenerating_it_gives_the_committed_file(self, tmp_path) -> None:
        out = tmp_path / "vt-schema.json"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "reference" / "vt_schema.py"),
             str(ROOT / "tests" / "unit" / "data" / "vt_protos"), str(out)],
            check=True, capture_output=True,
        )  # fmt: skip
        assert out.read_text(encoding="utf-8") == GENERATED.read_text(encoding="utf-8")

    def test_the_constants_fit_the_declaration(self) -> None:
        assert Data.conforms(Vt.schema(), dict(Vt.CONSTANTS)) == []


class TestTheMetadata:
    def test_livehunt_json_is_read_under_yara_names(self) -> None:
        data = VtData.message(VtSchema.ROOT, META)
        meta = data["metadata"]
        assert meta["sha256"] == b"abcdef00"  # (yara.field_options) lowercase
        assert meta["file_size"] == 1024  # int64 as JSON text
        assert meta["tags"] == {0: b"peexe", 1: b"signed"}
        assert meta["first_submission_date"] == 1767323045
        assert meta["exiftool"] == {b"CompanyName": b"x"}
        assert Data.conforms(Vt.schema(), {**Vt.CONSTANTS, **data}) == []

    def test_a_rule_reads_the_metadata(self) -> None:
        module = Vt.module(json.dumps(META).encode())
        rules = Rules.compile(
            'import "vt" rule r { condition: vt.metadata.file_size == 1024 '
            'and vt.metadata.tags[1] == "signed" }'
        )
        assert rules.match(b"x", given={"vt": module})

    def test_without_metadata_every_field_is_undefined(self) -> None:
        rules = Rules.compile('import "vt" rule r { condition: not defined vt.metadata.sha256 }')
        assert rules.match(b"x")

    def test_a_value_of_the_wrong_kind_is_no_value(self) -> None:
        data = VtData.message(VtSchema.ROOT, {"meta": {"fileSize": "not a number"}})
        assert "file_size" not in data["metadata"]

    def test_metadata_that_is_not_an_object_is_refused(self) -> None:
        with pytest.raises(ValueError, match="vt metadata"):
            Vt.module(b"[1, 2]")


class TestWhatAFileRulesetMayRead:
    def test_vt_net_is_refused_as_yara_x_refuses_it_for_files(self) -> None:
        with pytest.raises(RuleError):
            Rules.compile('import "vt" rule r { condition: defined vt.net.domain.raw }')
