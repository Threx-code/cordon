"""A vendored `.vsix` against what Open VSX signed (`OpenVsxSignature.compare`, `ReleaseChecks.extension_not_as_signed`).

`openvsx/java-pack.vsix` is vscjava.vscode-java-pack 0.31.2 as Open VSX served it, with its `.sigzip`. The registry is stood in
by those two files; what is tested is each way a copy in hand can differ from the signed package, and what each is called."""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import replace

import pytest

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.intel.provenance.releases.openvsx_signature import OpenVsxSignature
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "openvsx"
PACKAGE = (DATA / "java-pack.vsix").read_bytes()
SIGZIP = (DATA / "java-pack.sigzip").read_bytes()
NAME, VERSION = "vscjava.vscode-java-pack", "0.31.2"
KEY = "14ccb407-4e79-41ed-be5a-6d608325c45a"


class Registry:
    """Open VSX, as the two real files."""

    @staticmethod
    def serve(monkeypatch: pytest.MonkeyPatch, package: bytes = PACKAGE) -> None:
        monkeypatch.setattr(
            OpenVsxSignature,
            "_fetched",
            classmethod(lambda cls, name, version: (package, SIGZIP, KEY)),
        )


class Copies:
    """The extension in hand: every file of the real package, as a member name -> bytes."""

    @staticmethod
    def of(package: bytes = PACKAGE) -> dict[str, bytes]:
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            return {i.filename: archive.read(i) for i in archive.infolist() if not i.is_dir()}

    @staticmethod
    def digests(files: dict[str, bytes]) -> dict[str, str]:
        return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}

    @staticmethod
    def units(files: dict[str, bytes], archive: str = "vendor/java-pack.vsix") -> list[FileUnit]:
        return [
            FileUnit(content=FileContent.from_bytes(f"{archive}!{name}", data), language=None)
            for name, data in files.items()
        ]


class TestTheComparison:
    def test_the_real_copy_is_as_signed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Registry.serve(monkeypatch)
        found = OpenVsxSignature.compare(NAME, VERSION, Copies.digests(Copies.of()))
        assert found.outcome == "verified", found.detail

    def test_a_changed_file_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Registry.serve(monkeypatch)
        files = Copies.of()
        target = next(n for n in files if n.endswith("package.json"))
        files[target] += b"\n// patched"
        found = OpenVsxSignature.compare(NAME, VERSION, Copies.digests(files))
        assert found.outcome == "invalid" and f"{target} (changed)" in found.detail

    def test_an_added_file_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Registry.serve(monkeypatch)
        files = {**Copies.of(), "extension/dist/payload.js": b"steal()"}
        found = OpenVsxSignature.compare(NAME, VERSION, Copies.digests(files))
        assert (
            found.outcome == "invalid"
            and "extension/dist/payload.js (not in the signed package)" in found.detail
        )

    def test_a_copy_with_files_left_out_is_not_a_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch)
        files = Copies.of()
        files.pop(next(iter(files)))
        assert OpenVsxSignature.compare(NAME, VERSION, Copies.digests(files)).outcome == "verified"

    def test_a_registry_package_that_does_not_verify_is_not_a_standard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = bytearray(PACKAGE)
        raw[5000] ^= 1
        Registry.serve(monkeypatch, bytes(raw))
        found = OpenVsxSignature.compare(NAME, VERSION, Copies.digests(Copies.of()))
        assert found.outcome == "invalid" and "signature" in found.detail

    @pytest.mark.parametrize("outcome", ["absent", "unverifiable"])
    def test_a_registry_that_gives_no_signed_package_is_passed_through(
        self, monkeypatch: pytest.MonkeyPatch, outcome: str
    ) -> None:
        from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck

        monkeypatch.setattr(
            OpenVsxSignature,
            "_fetched",
            classmethod(lambda cls, name, version: ModuleCheck(outcome, "no")),
        )
        assert OpenVsxSignature.compare(NAME, VERSION, {}).outcome == outcome


class TestTheReleaseCheck:
    @staticmethod
    def context(offline: bool) -> ScanContext:
        config = replace(Config.default(), offline=offline)
        return ScanContext(config=config, rules=RuleSet(RuleLoader.load_builtin()))

    def test_a_vendored_copy_that_differs_is_a_critical_provenance_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch)
        files = Copies.of()
        target = next(n for n in files if n.endswith("extension/package.json"))
        files[target] = files[target].replace(b'"version": "0.31.2"', b'"version":  "0.31.2"')
        found = ReleaseChecks.extension_not_as_signed(
            Copies.units(files), self.context(offline=False)
        )
        assert [f.rule_id for f in found] == ["VULNERABLE.PROVENANCE.INVALID.001"]
        assert "changed" in found[0].message and found[0].location.path.endswith("extension/package.json")

    def test_the_real_copy_is_no_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Registry.serve(monkeypatch)
        assert (
            ReleaseChecks.extension_not_as_signed(
                Copies.units(Copies.of()), self.context(offline=False)
            )
            == []
        )

    def test_offline_nothing_is_asked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            OpenVsxSignature,
            "_fetched",
            classmethod(lambda cls, name, version: pytest.fail("asked offline")),
        )
        files = {**Copies.of(), "extension/x.js": b"x"}
        assert (
            ReleaseChecks.extension_not_as_signed(Copies.units(files), self.context(offline=True))
            == []
        )

    def test_a_manifest_outside_an_archive_is_not_a_vendored_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch)
        files = {"extension/package.json": Copies.of()["extension/package.json"]}
        units = [
            FileUnit(content=FileContent.from_bytes(n, d), language=None) for n, d in files.items()
        ]
        assert ReleaseChecks.extension_not_as_signed(units, self.context(offline=False)) == []
