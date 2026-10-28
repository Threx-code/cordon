"""A package whose payload is in a dependency it declares (`cli/dependency_payload.py`)."""

from __future__ import annotations

import argparse
import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

import cordon_scanner
from cordon_scanner.cli.dependency_payload import RULE_ID, DependencyPayload, NpmRange
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.foundation.results import ScanResult


class DependencyKit:
    @staticmethod
    def archive(path: Path, manifest: dict) -> Path:
        data = json.dumps(manifest).encode()
        with tarfile.open(path, "w:gz") as tar:
            entry = tarfile.TarInfo("package/package.json")
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
        return path

    @staticmethod
    def finding(rule_id: str):
        base = OperationalFinding.build(
            path="x.tgz!package/index.js",
            rule_id=rule_id,
            message="m",
            remediation="r",
            category=Category.MALICIOUS,
            severity=Severity.CRITICAL,
        )
        return replace(base, confidence=Confidence.HIGH, always_report=False, detector="capability")

    @staticmethod
    def args(store: Path) -> argparse.Namespace:
        return argparse.Namespace(
            online=False, offline=True, dependency_store=str(store), quiet=True
        )


class TestNpmRanges:
    @pytest.mark.parametrize(
        ("spec", "accepted", "refused"),
        [
            ("^1.2.3", "1.9.0", "2.0.0"),
            ("^0.2.3", "0.2.9", "0.3.0"),
            ("~1.2.3", "1.2.9", "1.3.0"),
            ("1.x", "1.4.0", "2.0.0"),
            (">=1.0.0 <2.0.0", "1.5.0", "2.0.0"),
            ("1.0.0 - 1.2", "1.2.7", "1.3.0"),
            ("^1.0.0 || ^3.0.0", "3.1.0", "2.0.0"),
            ("1.2.3", "1.2.3", "1.2.4"),
            ("*", "4.0.0", "4.1.0-beta.1"),
        ],
    )
    def test_a_range_accepts_what_npm_would_and_no_more(self, spec, accepted, refused):
        assert NpmRange.satisfies(accepted, spec) is True
        assert NpmRange.satisfies(refused, spec) is False

    @pytest.mark.parametrize(
        "spec", ["git+https://example.test/a.git", "file:../a", "npm:other@1", "user/repo#main"]
    )
    def test_what_is_not_a_registry_range_is_not_resolved(self, spec):
        assert NpmRange.satisfies("1.0.0", spec) is None


class TestResolution:
    def test_the_declared_dependencies_come_from_the_archives_own_manifest(self, tmp_path):
        target = DependencyKit.archive(
            tmp_path / "v.tgz",
            {
                "name": "v",
                "dependencies": {"a": "^1.0.0"},
                "optionalDependencies": {"b": "2"},
                "devDependencies": {"c": "1"},
            },
        )
        assert DependencyPayload.declared(target) == {"a": "^1.0.0", "b": "2"}

    def test_the_highest_held_version_the_range_accepts_is_chosen(self, tmp_path):
        (tmp_path / "npm").mkdir()
        for version in ("1.0.0", "1.4.0", "2.0.0"):
            (tmp_path / "npm" / f"@s_a@{version}.tgz").write_bytes(b"")
        found = DependencyPayload.from_store(tmp_path, "@s/a", "^1.0.0")
        assert found is not None and found.version == "1.4.0"
        assert DependencyPayload.from_store(tmp_path, "@s/a", "^3.0.0") is None


class TestTheVerdict:
    @pytest.fixture
    def store(self, tmp_path):
        (tmp_path / "store" / "npm").mkdir(parents=True)
        DependencyKit.archive(
            tmp_path / "store" / "npm" / "payload@1.0.0.tgz",
            {"name": "payload", "version": "1.0.0"},
        )
        DependencyKit.archive(
            tmp_path / "store" / "npm" / "labelled@1.0.0.tgz",
            {"name": "labelled", "version": "1.0.0"},
        )
        return tmp_path / "store"

    def _scan(self, monkeypatch, tmp_path, store, dependencies):
        verdicts = {
            "payload@1.0.0.tgz": "MALWARE.DROPPER.001",
            "labelled@1.0.0.tgz": "MALWARE.PACKAGE.KNOWN.001",
        }

        def scan(self, target):
            rule = verdicts.get(Path(target).name)
            return ScanResult(findings=(DependencyKit.finding(rule),) if rule else ())

        monkeypatch.setattr(cordon_scanner.Scanner, "scan", scan)
        target = DependencyKit.archive(
            tmp_path / "vehicle.tgz", {"name": "vehicle", "dependencies": dependencies}
        )
        return DependencyPayload.applied(
            DependencyKit.args(store), target, ScanResult(), Config.default(), None
        )

    def test_a_dependency_blocked_by_its_own_content_blocks_the_package_that_declares_it(
        self, monkeypatch, tmp_path, store
    ):
        result = self._scan(monkeypatch, tmp_path, store, {"payload": "^1.0.0"})
        added = [f for f in result.findings if f.rule_id == RULE_ID]
        assert (
            len(added) == 1
            and added[0].severity is Severity.CRITICAL
            and "payload" in added[0].message
        )

    def test_a_dependency_flagged_only_by_a_label_does_not(self, monkeypatch, tmp_path, store):
        result = self._scan(monkeypatch, tmp_path, store, {"labelled": "1.0.0"})
        assert not any(f.rule_id == RULE_ID for f in result.findings)

    def test_a_dependency_only_suspicious_by_a_heuristic_does_not(
        self, monkeypatch, tmp_path, store
    ):
        def scan(self, target):
            finding = replace(
                DependencyKit.finding("SUSPECT.INTENT.UNEXPLAINED_EFFECT.001"),
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
            )
            return ScanResult(findings=(finding,))

        monkeypatch.setattr(cordon_scanner.Scanner, "scan", scan)
        target = DependencyKit.archive(
            tmp_path / "vehicle.tgz", {"name": "vehicle", "dependencies": {"payload": "1"}}
        )
        result = DependencyPayload.applied(
            DependencyKit.args(store), target, ScanResult(), Config.default(), None
        )
        assert result.findings == ()

    def test_an_unresolvable_dependency_is_skipped(self, monkeypatch, tmp_path, store):
        result = self._scan(monkeypatch, tmp_path, store, {"absent": "^1.0.0", "payload": "^9.0.0"})
        assert result.findings == ()

    def test_nothing_is_resolved_without_a_store_or_online(self, monkeypatch, tmp_path, store):
        target = DependencyKit.archive(
            tmp_path / "vehicle.tgz", {"name": "vehicle", "dependencies": {"payload": "1"}}
        )
        args = argparse.Namespace(online=False, offline=True, dependency_store=None, quiet=True)
        assert (
            DependencyPayload.applied(args, target, ScanResult(), Config.default(), None).findings
            == ()
        )
