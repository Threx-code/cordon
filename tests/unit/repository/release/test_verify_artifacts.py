"""BP-15-14: an independent verifier accepts each shipped artifact (wheel, sdist, vsix) and refuses a modified one."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from support import ROOT


class Loaded:
    @staticmethod
    def verifier() -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            "verify_artifacts", ROOT / "scripts" / "release" / "verify_artifacts.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class Release:
    """A release directory built here: a wheel and a vsix (zips), an sdist (a gzip tar), SHA256SUMS and one statement each."""

    @staticmethod
    def zipped(path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)

    @classmethod
    def build(cls, directory: Path) -> list[Path]:
        wheel, vsix, sdist = (
            directory / "cordon_scanner-1.0-py3-none-any.whl",
            directory / "cordon-1.0.vsix",
            directory / "cordon_scanner-1.0.tar.gz",
        )
        cls.zipped(wheel, {"cordon_scanner/__init__.py": b"x = 1\n" * 50})
        cls.zipped(vsix, {"extension/package.json": b'{"name":"cordon"}' * 20})
        with tarfile.open(sdist, "w:gz") as archive:
            data = b"print(1)\n" * 40
            info = tarfile.TarInfo("cordon_scanner-1.0/setup.py")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        cls.attest(directory, [wheel, vsix, sdist])
        return [wheel, vsix, sdist]

    @staticmethod
    def attest(directory: Path, artifacts: list[Path]) -> None:
        lines = []
        for path in artifacts:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.name}")
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": path.name, "digest": {"sha256": digest}}],
                "predicateType": "https://slsa.dev/provenance/v1",
            }
            (directory / (path.name + ".intoto.json")).write_text(
                json.dumps(statement), encoding="utf-8"
            )
        (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestTheVerifier:
    verifier = Loaded.verifier().ArtifactVerifier

    def test_it_accepts_the_wheel_the_sdist_and_the_vsix(self, tmp_path: Path) -> None:
        Release.build(tmp_path)
        assert self.verifier.problems(tmp_path) == []

    @pytest.mark.parametrize("index", [0, 1, 2], ids=["wheel", "vsix", "sdist"])
    def test_it_refuses_an_artifact_with_one_byte_flipped(self, tmp_path: Path, index: int) -> None:
        artifact = Release.build(tmp_path)[index]
        data = bytearray(artifact.read_bytes())
        data[len(data) // 2] ^= 0x01
        artifact.write_bytes(bytes(data))
        found = self.verifier.problems(tmp_path)
        assert any(artifact.name in line and "digest differs" in line for line in found)
        assert any(artifact.name in line and "different bytes" in line for line in found)

    def test_a_statement_about_other_bytes_is_refused_even_when_the_sums_were_regenerated(
        self, tmp_path: Path
    ) -> None:
        wheel = Release.build(tmp_path)[0]
        wheel.write_bytes(wheel.read_bytes() + b"\x00")
        Release.attest(tmp_path, [wheel])
        (tmp_path / "SHA256SUMS").write_text(
            f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}\n", encoding="utf-8"
        )
        stale = json.loads((tmp_path / (wheel.name + ".intoto.json")).read_text(encoding="utf-8"))
        stale["subject"][0]["digest"]["sha256"] = "0" * 64
        (tmp_path / (wheel.name + ".intoto.json")).write_text(json.dumps(stale), encoding="utf-8")
        found = self.verifier.problems(tmp_path)
        assert any("different bytes" in line for line in found) and any(
            "not in SHA256SUMS" in line for line in found
        )

    def test_a_missing_statement_or_sums_entry_and_an_unopenable_file_are_refused(
        self, tmp_path: Path
    ) -> None:
        wheel, vsix, _ = Release.build(tmp_path)
        (tmp_path / (wheel.name + ".intoto.json")).unlink()
        vsix.write_bytes(b"not a zip")
        found = "\n".join(self.verifier.problems(tmp_path))
        assert (
            f"{wheel.name}: no statement" in found
            and f"{vsix.name}: does not open as a zip" in found
        )

    def test_an_empty_directory_is_not_a_release(self, tmp_path: Path) -> None:
        assert self.verifier.problems(tmp_path) == ["no artifact to verify"]

    def test_it_shares_no_code_with_the_scanner(self) -> None:
        text = (ROOT / "scripts" / "release" / "verify_artifacts.py").read_text(encoding="utf-8")
        assert "cordon_scanner import" not in text and "from cordon_scanner" not in text
