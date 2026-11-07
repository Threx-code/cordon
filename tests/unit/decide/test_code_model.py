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
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.javascript.code_model import (
    CodeFeatures,
    CodeModelWeights,
    FileScoreRecord,
)
from cordon_scanner.decide.code_model import CodeModelPass, CodePackageStep
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.code_model_scores import MODEL_RULE, UNAVAILABLE, CodeModelScores
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.sarif import SarifReporter
from support import requires_forked_workers

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
    @requires_forked_workers
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
    @requires_forked_workers
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

    def test_by_default_it_blocks_at_the_shipped_point_and_says_nothing_below(self) -> None:
        def record(score: float) -> Any:
            return SimpleNamespace(
                rule_id=FileScoreRecord.RULE,
                message=FileScoreRecord.encode(score, []),
                location=SimpleNamespace(path="package/index.js"),
            )

        def made(path, score, carriers, blocking):
            return ("HIGH" if blocking else "MEDIUM", round(score, 4))

        at = CodePackageStep.BLOCK_AT
        assert at is not None and at == CodePackageStep.REPORT_AT
        assert CodePackageStep.decide([record(at)], made)[1] == ("HIGH", at)
        assert CodePackageStep.decide([record(at - 0.001)], made)[1] is None

    def test_the_shipped_weights_load_for_the_shipped_features(self) -> None:
        assert CodeModelWeights.load() is not None


class TestWeights:
    def test_a_build_without_the_weights_says_nothing(self, tmp_path) -> None:
        result = CodeModelKit.scanner(tmp_path / "absent.json.gz").scan(
            CodeModelKit.package(tmp_path / "p")
        )
        assert not {MODEL_RULE, UNAVAILABLE} & set(CodeModelKit.rules(result))

    @requires_forked_workers  # a spawned worker builds its own detector, not this test's
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

    def test_a_reached_file_with_damaged_weights_gets_the_note(self, tmp_path) -> None:
        """The worker's side, on every platform: the file that needed the model says it was not
        scored."""
        path = tmp_path / "w.json.gz"
        path.write_bytes(b"not a model")
        detector = CodeModelScores(weights_path=path)
        unit = FileUnit(
            content=FileContent.from_bytes("p/index.js", FIXTURE.encode()), language="javascript"
        )
        ctx = SimpleNamespace(
            install_hook_paths=frozenset(),
            import_entry_paths=frozenset({"p/index.js"}),
            library_closure_paths=frozenset(),
        )
        assert [f.rule_id for f in detector.inspect(unit, ctx)] == [UNAVAILABLE]

    def test_the_parent_keeps_one_note_a_scan(self, tmp_path) -> None:
        detector = CodeModelScores(weights_path=tmp_path / "absent.json.gz")
        notes = [
            detector.operational(path=f"p/{name}.js", rule_id=UNAVAILABLE, message="damaged")
            for name in ("a", "b", "c")
        ]
        engine = SimpleNamespace(detectors=(detector,), config=Config.default())
        kept, extra = CodeModelPass.decide(engine, list(notes), SimpleNamespace())
        assert kept == []
        assert [(f.rule_id, f.location.path) for f in extra] == [(UNAVAILABLE, ".")]
        assert detector.wanted is True

    def test_building_the_detector_reads_nothing(self, tmp_path) -> None:
        path = tmp_path / "w.json.gz"
        path.write_bytes(b"not a model")
        detector = CodeModelScores(weights_path=path)
        assert detector.unavailable is None

    def test_a_scan_that_reaches_no_javascript_never_reads_the_weights(self, tmp_path) -> None:
        # Release item 17: 0.1 s of every scan went on weights a Python package never uses.
        path = tmp_path / "w.json.gz"
        path.write_bytes(b"not a model")
        root = tmp_path / "py"
        root.mkdir()
        (root / "setup.py").write_text(
            "from setuptools import setup\nsetup(name='x')\n", encoding="utf-8"
        )
        result = CodeModelKit.scanner(path).scan(root)
        assert UNAVAILABLE not in CodeModelKit.rules(result)

    @requires_forked_workers
    def test_a_long_running_scanner_reads_them_once_before_its_next_scan(self, tmp_path) -> None:
        scanner = CodeModelKit.scanner(CodeModelKit.weights(tmp_path))
        detector = next(d for d in scanner._engine.detectors if d.id == "code-model")
        target = CodeModelKit.package(tmp_path / "p")
        first = scanner.scan(target)
        assert detector.loaded is False  # the workers read them; the one-scan CLI pays no more
        second = scanner.scan(target)
        assert detector.loaded is True  # held before the template, so every later worker has them
        assert MODEL_RULE in CodeModelKit.rules(first)
        assert MODEL_RULE in CodeModelKit.rules(second)

    @requires_forked_workers
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

    @pytest.mark.parametrize(
        "message",
        [
            "v1 score=0.9700 ngrams=" + "a" * 600,
            "v1 score=0.9700 ngrams=a|b|c|d",
            "v1 score=9.9999 ngrams=a",
            "v1 score=0.97 ngrams=a",
        ],
        ids=["too-long", "too-many-carriers", "score-past-one", "malformed"],
    )
    def test_an_oversized_or_malformed_record_is_refused(self, message: str) -> None:
        assert FileScoreRecord.decode(message) is None

    def test_what_the_encoder_writes_always_decodes(self) -> None:
        message = FileScoreRecord.encode(0.5, ["x" * 500, "b", "c", "d"])
        decoded = FileScoreRecord.decode(message)
        assert decoded is not None and len(decoded[1]) == FileScoreRecord.MAX_CARRIERS


class TestNoSizeEscapesTheModel:
    """No cap a file's size can defeat (the owner's no-caps rule; cordon-47, 2 Nov): a file is scored
    window by window, and its score is its highest window's."""

    @staticmethod
    def best(path: Path, text: str) -> float:
        weights = CodeModelWeights.load(path)
        assert weights is not None
        return max(weights.score(buckets) for buckets, _names in CodeFeatures.windows(text))

    def test_the_shape_after_padding_past_the_token_window_is_scored(self, tmp_path) -> None:
        path = CodeModelKit.weights(tmp_path)
        padded = "a;\n" * 210_000 + FIXTURE  # 420,000 tokens before the learned shape
        weights = CodeModelWeights.load(path)
        assert weights is not None
        assert weights.score(CodeFeatures.buckets(padded)) < 0.2  # the first window alone misses it
        assert self.best(path, padded) > 0.9

    def test_a_file_past_two_megabytes_is_scored(self, tmp_path) -> None:
        path = CodeModelKit.weights(tmp_path)
        large = "/*" + "x" * 2_100_000 + "*/\n" + FIXTURE
        assert len(large) > CodeFeatures.CHUNK
        assert self.best(path, large) > 0.9

    def test_a_file_within_one_window_scores_as_trained(self, tmp_path) -> None:
        path = CodeModelKit.weights(tmp_path)
        weights = CodeModelWeights.load(path)
        assert weights is not None
        assert self.best(path, FIXTURE) == weights.score(CodeFeatures.buckets(FIXTURE))
