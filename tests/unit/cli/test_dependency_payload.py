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
from cordon_scanner.cli.dependency_payload import RULE_ID, DependencyPayload, EcosystemDependencies
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.foundation.results import OperationalFinding, ScanResult


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


class TestNpmRangesThroughTheSharedPath:
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
        assert EcosystemDependencies.admitted("npm", spec, [accepted, refused]) == [accepted]

    @pytest.mark.parametrize(
        "spec", ["git+https://example.test/a.git", "file:../a", "npm:other@1", "user/repo#main"]
    )
    def test_what_is_not_a_registry_range_is_not_resolved(self, spec):
        assert EcosystemDependencies.admitted("npm", spec, ["1.0.0"]) == []


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
        assert DependencyPayload.declared(target) == ("npm", {"a": "^1.0.0", "b": "2"})

    def test_the_highest_held_version_the_range_accepts_is_chosen(self, tmp_path):
        (tmp_path / "npm").mkdir()
        for version in ("1.0.0", "1.4.0", "2.0.0"):
            (tmp_path / "npm" / f"@s_a@{version}.tgz").write_bytes(b"")
        found = EcosystemDependencies.resolve("npm", "@s/a", "^1.0.0", tmp_path, tmp_path)
        assert found is not None and found.version == "1.4.0"
        assert EcosystemDependencies.resolve("npm", "@s/a", "^3.0.0", tmp_path, tmp_path) is None

    def test_a_store_named_with_a_dash_is_read_too(self, tmp_path):
        (tmp_path / "npm").mkdir()
        (tmp_path / "npm" / "a-b-1.2.0.tgz").write_bytes(b"")
        found = EcosystemDependencies.resolve("npm", "a-b", "^1.0.0", tmp_path, tmp_path)
        assert found is not None and found.version == "1.2.0"


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


class TestAnUnreadDependency:
    """A dependency whose own content left part of it unread makes the package that declares it
    incomplete by that content, so the gate blocks it as it would the package's own unread file."""

    GAP = ("OPERATIONAL.ARCHIVE.MEMBER_REJECTED", "payload@1.0.0.tgz!package/inner.tgz")

    def test_its_gap_is_the_vehicle_s_and_blocks(self, monkeypatch, tmp_path):
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.foundation.errors import ExitCode

        (tmp_path / "store" / "npm").mkdir(parents=True)
        DependencyKit.archive(
            tmp_path / "store" / "npm" / "payload@1.0.0.tgz",
            {"name": "payload", "version": "1.0.0"},
        )

        def scan(self, target):
            return ScanResult(complete=False, content_complete=False, content_gaps=(self_gap,))

        self_gap = self.GAP
        monkeypatch.setattr(cordon_scanner.Scanner, "scan", scan)
        target = DependencyKit.archive(
            tmp_path / "vehicle.tgz", {"name": "vehicle", "dependencies": {"payload": "^1.0.0"}}
        )
        result = DependencyPayload.applied(
            DependencyKit.args(tmp_path / "store"), target, ScanResult(), Config.default(), None
        )
        assert result.content_gaps == (self.GAP,) and not result.complete
        assert PolicyGate.evaluate(result, Config.default().policy).exit_code is ExitCode.INCOMPLETE
        assert [(f.rule_id, f.location.path) for f in result.findings] == [self.GAP]


class TestEveryEcosystem:
    """A vehicle in any ecosystem: its declared dependencies are those the scan read from its own
    manifest, each range is read in the ecosystem's own syntax, and the payload blocks the vehicle."""

    @staticmethod
    def declared(ecosystem: str, name: str, spec: str, scope=None):
        from cordon_scanner.foundation.models import Scope
        from cordon_scanner.foundation.results import Dependency

        return Dependency(
            purl=f"pkg:{ecosystem}/{name}",
            ecosystem=ecosystem,
            name=name,
            version=None,
            direct=True,
            scope=scope or Scope.RUNTIME,
            declared_spec=spec,
            declared_in="vehicle-1.0.0.crate!vehicle-1.0.0/Cargo.toml",
        )

    def _scan(self, monkeypatch, tmp_path, dependencies, held):
        store = tmp_path / "store" / "cargo"
        store.mkdir(parents=True)
        for filename in held:
            (store / filename).write_bytes(b"crate")

        def scan(self, target):
            bad = Path(target).name == "payload@1.4.0.crate"
            return ScanResult(
                findings=(DependencyKit.finding("MALWARE.DROPPER.001"),) if bad else ()
            )

        monkeypatch.setattr(cordon_scanner.Scanner, "scan", scan)
        target = tmp_path / "vehicle-1.0.0.crate"
        target.write_bytes(b"crate")
        return DependencyPayload.applied(
            DependencyKit.args(tmp_path / "store"),
            target,
            ScanResult(dependencies=tuple(dependencies)),
            Config.default(),
            None,
        )

    def test_a_crate_whose_dependency_carries_the_payload_is_blocked(self, monkeypatch, tmp_path):
        # Cargo reads the bare `1.2` as `^1.2`, so 1.4.0 is what an install resolves to.
        result = self._scan(
            monkeypatch,
            tmp_path,
            [self.declared("cargo", "payload", "1.2")],
            ["payload@1.2.0.crate", "payload@1.4.0.crate", "payload@2.0.0.crate"],
        )
        added = [f for f in result.findings if f.rule_id == RULE_ID]
        assert len(added) == 1 and "payload" in added[0].message

    def test_a_range_that_does_not_admit_the_payload_release_is_not_blocked(
        self, monkeypatch, tmp_path
    ):
        result = self._scan(
            monkeypatch,
            tmp_path,
            [self.declared("cargo", "payload", "=1.2.0")],
            ["payload@1.2.0.crate", "payload@1.4.0.crate"],
        )
        assert not any(f.rule_id == RULE_ID for f in result.findings)

    def test_a_development_dependency_is_not_followed(self, monkeypatch, tmp_path):
        from cordon_scanner.foundation.models import Scope

        result = self._scan(
            monkeypatch,
            tmp_path,
            [self.declared("cargo", "payload", "1.2", Scope.DEV)],
            ["payload@1.4.0.crate"],
        )
        assert not any(f.rule_id == RULE_ID for f in result.findings)

    def test_a_minimum_only_ecosystem_resolves_the_named_version(self) -> None:
        from cordon_scanner.cli.dependency_payload import EcosystemDependencies

        assert EcosystemDependencies.admitted("gomod", "v1.2.0", ["v1.2.0", "v1.9.0"]) == ["v1.2.0"]
        assert EcosystemDependencies.admitted("cargo", "1.2", ["1.2.0", "1.9.0", "2.0.0"]) == [
            "1.2.0",
            "1.9.0",
        ]
