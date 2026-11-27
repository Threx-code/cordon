"""Installed extensions against what Open VSX signed (`InstalledExtensions`, `DeviceInventory.collect(verify_extensions=True)`).

The installed folders are made from the real vscjava.vscode-java-pack 0.31.2 package (`intel/provenance/openvsx/java-pack.vsix`)
the way an editor unpacks one; the registry is stood in by the same package and its real signature."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from cordon_scanner.cloud.device import DeviceInventory
from cordon_scanner.intel.provenance.releases.openvsx_signature import OpenVsxSignature
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "openvsx"
PACKAGE = (DATA / "java-pack.vsix").read_bytes()
SIGZIP = (DATA / "java-pack.sigzip").read_bytes()
KEY = "14ccb407-4e79-41ed-be5a-6d608325c45a"
FOLDER = "vscjava.vscode-java-pack-0.31.2"


class Machine:
    @staticmethod
    def unpack(home: Path, editor_directory: str) -> Path:
        """The package unpacked as an editor does: `extension/` at the folder's root, the manifest as `.vsixmanifest`."""
        folder = home / editor_directory / FOLDER
        with zipfile.ZipFile(io.BytesIO(PACKAGE)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.filename.startswith("extension/"):
                    target = folder / info.filename[len("extension/") :]
                elif info.filename == "extension.vsixmanifest":
                    target = folder / ".vsixmanifest"
                else:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
        return folder

    @staticmethod
    def registry(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        asked: list[tuple[str, str]] = []

        def fetched(cls, name, version):
            asked.append((name, version))
            return PACKAGE, SIGZIP, KEY

        monkeypatch.setattr(OpenVsxSignature, "_fetched", classmethod(fetched))
        return asked


class TestInstalledExtensions:
    def findings(self, home: Path) -> list[dict]:
        report = DeviceInventory.collect(home, verify_extensions=True)
        return [
            f for f in report["findings"] if f["rule_id"] == "VULNERABLE.PROVENANCE.INVALID.001"
        ]

    def test_an_untouched_folder_is_as_signed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Machine.unpack(tmp_path, ".vscode-oss/extensions")
        asked = Machine.registry(monkeypatch)
        assert self.findings(tmp_path) == []
        assert asked == [("vscjava.vscode-java-pack", "0.31.2")]

    def test_a_changed_file_is_a_critical_finding_naming_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Machine.unpack(tmp_path, ".vscode-oss/extensions")
        Machine.registry(monkeypatch)
        (folder / "package.json").write_bytes((folder / "package.json").read_bytes() + b"\n")
        found = self.findings(tmp_path)
        assert len(found) == 1 and found[0]["severity"] == "critical"
        assert "extension/package.json (changed)" in found[0]["message"]
        assert found[0]["path"] == "extensions/vscodium:vscjava.vscode-java-pack@0.31.2"

    def test_a_file_the_package_never_had_is_not_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Machine.unpack(tmp_path, ".cursor/extensions")
        Machine.registry(monkeypatch)
        (folder / "jre").mkdir()
        (folder / "jre" / "downloaded-on-first-use.bin").write_bytes(b"\0" * 64)
        assert self.findings(tmp_path) == []

    def test_an_editor_that_installs_from_the_marketplace_is_not_asked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Machine.unpack(tmp_path, ".vscode/extensions")
        (folder / "package.json").write_bytes(
            b'{"publisher":"vscjava","name":"vscode-java-pack","version":"0.31.2"}'
        )
        asked = Machine.registry(monkeypatch)
        assert self.findings(tmp_path) == [] and asked == []

    def test_the_default_inventory_asks_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Machine.unpack(tmp_path, ".vscode-oss/extensions")
        monkeypatch.setattr(
            OpenVsxSignature,
            "_fetched",
            classmethod(lambda cls, n, v: pytest.fail("asked a registry")),
        )
        report = DeviceInventory.collect(tmp_path)
        assert report["inventory"]["installed_extensions"][0]["id"] == "vscjava.vscode-java-pack"

    def test_the_payload_never_carries_the_folder(self, tmp_path: Path) -> None:
        Machine.unpack(tmp_path, ".vscode-oss/extensions")
        assert str(tmp_path) not in str(
            DeviceInventory.collect(tmp_path)["inventory"]["installed_extensions"]
        )
