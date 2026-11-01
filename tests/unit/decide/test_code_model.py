"""The code model in the scanner (release item 47; notes/47-learned-code-model.md, its integration and
the outer-layer review). Weights are built here from an inert fixture's own buckets, so the test does
not depend on the shipped file: what it checks is the plumbing, the reach rule and the guards."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.javascript.code_model import CodeFeatures, FileScoreRecord
from cordon_scanner.decide.code_model import CodePackageStep
from cordon_scanner.detect.code.code_model_scores import MODEL_RULE, UNAVAILABLE, CodeModelScores
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.sarif import SarifReporter

FIXTURE = (
    "const os = require('os');\n"
    "const https = require('https');\n"
    "module.exports = function report() {\n"
    "  return [os.hostname(), os.platform(), JSON.stringify(process.env.HOME)].join(':');\n"
    "};\n"
)


class CodeModelKit:
    @staticmethod
    def weights(tmp_path: Path, *, fmt: int = 1, features: str | None = None) -> Path:
        buckets = CodeFeatures.buckets(FIXTURE)
        data = {
            "format": fmt,
            "features": features or CodeFeatures.vocabulary_hash(),
            "bias": -2.0,
            "weights": {str(b): 0.5 for b in buckets},
            "trained": "test",
        }
        path = tmp_path / "code_model.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    @staticmethod
    def scanner(weights: Path | None) -> Scanner:
        base = Scanner(Config.default().with_overrides(use_cache=False))
        detectors = [
            d if getattr(d, "id", "") != "code-model" else CodeModelScores(weights_path=weights)
            for d in base._engine.detectors
        ]
        return Scanner(Config.default().with_overrides(use_cache=False), detectors=detectors)

    @staticmethod
    def package(root: Path, main: str = "index.js", spare: bool = False) -> Path:
        """A published package as it arrives: a .tgz with its files under package/."""
        files = {
            "package/package.json": json.dumps({"name": "x", "version": "1.0.0", "main": main})
        }
        if spare:
            files[f"package/{main}"] = "module.exports = 1;\n"
            files["package/lib/spare.js"] = FIXTURE
        else:
            files[f"package/{main}"] = FIXTURE
        root.mkdir(parents=True, exist_ok=True)
        target = root / "x-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return target

    @staticmethod
    def rules(result: Any) -> list[str]:
        return [f.rule_id for f in result.findings]


class TestReachedCodeIsScored:
    def test_a_reached_file_with_the_learned_shape_is_reported_at_that_file(self, tmp_path) -> None:
        result = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(
            CodeModelKit.package(tmp_path / "p")
        )
        found = [f for f in result.findings if f.rule_id == MODEL_RULE]
        assert len(found) == 1, CodeModelKit.rules(result)
        assert found[0].location.path.endswith("index.js")

    def test_the_same_code_in_a_file_nothing_reaches_is_not_scored(self, tmp_path) -> None:
        target = CodeModelKit.package(tmp_path / "p", spare=True)
        result = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(target)
        assert MODEL_RULE not in CodeModelKit.rules(result)


class TestTheOperatingPoint:
    def test_block_at_raises_the_finding_to_high(self, tmp_path) -> None:
        base = CodeModelKit.scanner(CodeModelKit.weights(tmp_path))
        config = Config.default().with_overrides(use_cache=False, code_model_block_at=0.5)
        scanner = Scanner(config, detectors=list(base._engine.detectors))
        found = [
            f
            for f in scanner.scan(CodeModelKit.package(tmp_path / "p")).findings
            if f.rule_id == MODEL_RULE
        ]
        assert [f.severity.name for f in found] == ["HIGH"]

    def test_by_default_it_reports_below_the_gate(self, tmp_path) -> None:
        result = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(
            CodeModelKit.package(tmp_path / "p")
        )
        assert [f.severity.name for f in result.findings if f.rule_id == MODEL_RULE] == ["MEDIUM"]


class TestWeights:
    def test_a_build_without_the_weights_says_nothing(self, tmp_path) -> None:
        result = CodeModelKit.scanner(tmp_path / "absent.json.gz").scan(
            CodeModelKit.package(tmp_path / "p")
        )
        assert not {MODEL_RULE, UNAVAILABLE} & set(CodeModelKit.rules(result))

    @pytest.mark.parametrize("damage", ["not gzip", "other features", "other format"])
    def test_damaged_or_mismatched_weights_give_one_note(self, tmp_path, damage: str) -> None:
        if damage == "not gzip":
            path = tmp_path / "w.json.gz"
            path.write_bytes(b"not a model")
        elif damage == "other features":
            path = CodeModelKit.weights(tmp_path, features="0000000000000000")
        else:
            path = CodeModelKit.weights(tmp_path, fmt=99)
        result = CodeModelKit.scanner(path).scan(CodeModelKit.package(tmp_path / "p"))
        assert CodeModelKit.rules(result).count(UNAVAILABLE) == 1
        assert MODEL_RULE not in CodeModelKit.rules(result)

    def test_one_scan_with_weights_then_one_without_shares_nothing(self, tmp_path) -> None:
        target = CodeModelKit.package(tmp_path / "p")
        first = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(target)
        second = CodeModelKit.scanner(tmp_path / "absent.json.gz").scan(target)
        assert MODEL_RULE in CodeModelKit.rules(first)
        assert MODEL_RULE not in CodeModelKit.rules(second)


class TestTheRecordsNeverReachAReport:
    def test_no_internal_record_in_the_result_json_or_sarif(self, tmp_path) -> None:
        result = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(
            CodeModelKit.package(tmp_path / "p")
        )
        assert not [r for r in CodeModelKit.rules(result) if r.startswith("INTERNAL.")]
        assert "INTERNAL." not in json.dumps(result.to_dict())
        sarif = b"".join(SarifReporter().render(result, ReportOptions(color=False))).decode()
        assert "INTERNAL." not in sarif

    def test_nor_when_the_package_step_raises(self, tmp_path, monkeypatch) -> None:
        def broken(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("step broke")

        monkeypatch.setattr(CodePackageStep, "decide", broken)
        result = CodeModelKit.scanner(CodeModelKit.weights(tmp_path)).scan(
            CodeModelKit.package(tmp_path / "p")
        )
        rules = CodeModelKit.rules(result)
        assert not [r for r in rules if r.startswith("INTERNAL.")]
        assert UNAVAILABLE in rules and MODEL_RULE not in rules

    def test_the_record_is_info_operational_and_never_touches_the_gate(self, tmp_path) -> None:
        target = CodeModelKit.package(tmp_path / "p")
        without = CodeModelKit.scanner(tmp_path / "absent.json.gz").scan(target)
        detector = CodeModelScores(weights_path=CodeModelKit.weights(tmp_path))
        record = detector.record("p/index.js", 0.5, [])
        assert record.severity.name == "INFO" and record.category.name == "OPERATIONAL"
        assert not record.always_report
        assert without.content_complete


class TestTheRecordFormat:
    def test_a_record_of_another_version_is_refused_and_dropped_on_the_cache_read_path(
        self,
    ) -> None:
        detector = CodeModelScores(weights_path=Path("/nonexistent"))
        current = detector.record("a.js", 0.97, ["os>hostname"])
        old = replace(current, message="v0 0.97")
        assert FileScoreRecord.decode(current.message) == (0.97, ["os>hostname"])
        assert FileScoreRecord.decode(old.message) is None
        assert FileScoreRecord.current((current, old)) == (current,)
