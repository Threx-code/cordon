"""Installed extensions against what Open VSX signed (`InstalledExtensions`, `DeviceInventory.collect(verify_extensions=True)`).

The installed folders are made from the real vscjava.vscode-java-pack 0.31.2 package (`intel/provenance/openvsx/java-pack.vsix`)
the way an editor unpacks one; the registry is stood in by the same package and its real signature."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from cordon_scanner.cloud.device import DeviceInventory
from cordon_scanner.cloud.extension_integrity import InstalledExtensions
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

    def added(self, home: Path) -> list[dict]:
        report = DeviceInventory.collect(home, verify_extensions=True)
        return [
            f for f in report["findings"] if f["rule_id"] == InstalledExtensions.ADDED_CODE_RULE
        ]

    def test_an_added_data_or_cache_file_is_not_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Machine.unpack(tmp_path, ".cursor/extensions")
        Machine.registry(monkeypatch)
        (folder / "jre").mkdir()
        (folder / "jre" / "downloaded-on-first-use.bin").write_bytes(b"\0" * 64)
        (folder / "cache.json").write_bytes(b"{}")
        (folder / "notes.txt").write_bytes(b"x")
        assert self.findings(tmp_path) == [] and self.added(tmp_path) == []

    @pytest.mark.parametrize("suffix", sorted(InstalledExtensions.CODE_KINDS))
    def test_an_added_file_of_each_code_kind_is_suspect_at_medium(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
    ) -> None:
        folder = Machine.unpack(tmp_path, ".cursor/extensions")
        Machine.registry(monkeypatch)
        (folder / f"zzdropped{suffix}").write_bytes(b"\0\1")
        assert self.findings(tmp_path) == []
        found = self.added(tmp_path)
        assert len(found) == 1 and found[0]["severity"] == "medium"
        assert f"zzdropped{suffix}" in found[0]["message"]
        assert found[0]["path"] == "extensions/cursor:vscjava.vscode-java-pack@0.31.2"

    def test_the_code_kinds_are_exactly_the_ruled_ones(self) -> None:
        assert set(InstalledExtensions.CODE_KINDS) == {
            ".js",
            ".mjs",
            ".cjs",
            ".node",
            ".wasm",
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".sh",
            ".ps1",
            ".py",
        }

    def test_an_added_script_a_signed_file_names_is_critical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        signed = io.BytesIO()
        with zipfile.ZipFile(signed, "w") as archive:
            archive.writestr("extension/out/main.js", 'require("./helper");')
            archive.writestr("extension/package.json", '{"main":"./out/main"}')
        package = signed.getvalue()
        members = OpenVsxSignature.signed_members(package)
        monkeypatch.setattr(
            OpenVsxSignature, "signed_package", classmethod(lambda cls, n, v: (package, members))
        )
        folder = tmp_path / ".vscode-oss" / "extensions" / FOLDER
        (folder / "out").mkdir(parents=True)
        (folder / "package.json").write_bytes(b'{"main":"./out/main"}')
        (folder / "out" / "main.js").write_bytes(b'require("./helper");')
        (folder / "out" / "helper.js").write_bytes(b"steal()")
        (folder / "out" / "unrelated.js").write_bytes(b"x")
        found = self.findings(tmp_path)
        assert len(found) == 1 and found[0]["severity"] == "critical"
        assert (
            "extension/out/helper.js (script not in the signed package, named by a signed file)"
            in found[0]["message"]
        )
        assert "unrelated" not in found[0]["message"]

    def test_an_added_script_no_signed_file_names_is_suspect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        signed = io.BytesIO()
        with zipfile.ZipFile(signed, "w") as archive:
            archive.writestr("extension/out/main.js", "1")
        package = signed.getvalue()
        members = OpenVsxSignature.signed_members(package)
        monkeypatch.setattr(
            OpenVsxSignature, "signed_package", classmethod(lambda cls, n, v: (package, members))
        )
        folder = tmp_path / ".cursor" / "extensions" / FOLDER
        (folder / "out").mkdir(parents=True)
        (folder / "package.json").write_bytes(b'{"publisher":"a","name":"b","version":"1"}')
        (folder / "out" / "main.js").write_bytes(b"1")
        (folder / "out" / "dropped.node").write_bytes(b"x")
        assert self.findings(tmp_path) == []
        assert [f["severity"] for f in self.added(tmp_path)] == ["medium"]

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

    def test_a_marketplace_folder_is_counted_and_named_not_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Machine.unpack(tmp_path, ".vscode/extensions")
        (folder / "package.json").write_bytes(
            b'{"publisher":"vscjava","name":"vscode-java-pack","version":"0.31.2"}'
        )
        Machine.registry(monkeypatch)
        left = DeviceInventory.collect(tmp_path, verify_extensions=True)["inventory"]
        assert left["extensions_not_verified"] == [
            {
                "editor": "vscode",
                "id": "vscjava.vscode-java-pack",
                "version": "0.31.2",
                "reason": "not verified: installed from the Visual Studio Marketplace",
            }
        ]
        assert "extensions_not_verified" not in DeviceInventory.collect(tmp_path)["inventory"]

    def test_an_open_vsx_editors_folder_is_not_listed_as_unverified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Machine.unpack(tmp_path, ".vscode-oss/extensions")
        Machine.registry(monkeypatch)
        report = DeviceInventory.collect(tmp_path, verify_extensions=True)
        assert report["inventory"]["extensions_not_verified"] == []


class TestTheFlag:
    def test_inventory_and_report_take_the_opt_in_flag_off_by_default(self) -> None:
        import argparse

        from cordon_scanner.cli.commands.agent import AgentCommand

        root = argparse.ArgumentParser()
        AgentCommand.add_parser(root.add_subparsers())
        for command in ("inventory", "report"):
            assert root.parse_args(["agent", command]).verify_extensions is False
            assert (
                root.parse_args(["agent", command, "--verify-extensions"]).verify_extensions is True
            )
        assert "open-vsx.org about each installed extension" in AgentCommand.VERIFY_HELP

    def test_the_flag_reaches_the_collection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse

        from cordon_scanner.cli.commands.agent import AgentCommand

        seen: list[bool] = []

        def collect(home=None, collection=None, *, verify_extensions=False):
            seen.append(verify_extensions)
            return {"inventory": {}, "findings": []}

        monkeypatch.setattr(DeviceInventory, "collect", staticmethod(collect))
        for flag in (False, True):
            AgentCommand.run(
                argparse.Namespace(
                    agent_command="inventory", signed=False, url=None, verify_extensions=flag
                )
            )
        assert seen == [False, True]


class TestFilesAreHashedAChunkAtATime:
    def test_a_file_larger_than_a_chunk_has_the_hash_of_all_its_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        body = bytes(range(256)) * 40  # 10,240 bytes
        target = tmp_path / "big.bin"
        target.write_bytes(body)
        monkeypatch.setattr(InstalledExtensions, "CHUNK", 1000)
        assert InstalledExtensions.digest(target) == hashlib.sha256(body).hexdigest()

    def test_no_read_takes_a_whole_file_at_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "x.bin"
        target.write_bytes(b"0" * 5000)
        monkeypatch.setattr(InstalledExtensions, "CHUNK", 1000)
        sizes: list[int] = []
        real = Path.open

        def spy(self: Path, *args: object, **kwargs: object):
            handle = real(self, *args, **kwargs)
            read = handle.read
            handle.read = lambda n=-1: (sizes.append(n), read(n))[1]  # type: ignore[method-assign]
            return handle

        monkeypatch.setattr(Path, "open", spy)
        InstalledExtensions.digest(target)
        assert sizes and all(0 < n <= 1000 for n in sizes)
