"""An Open VSX extension's package signature (`releases/openvsx_signature`), on a real extension.

`openvsx/path-intellisense.{vsix,sigzip}` are what Open VSX served for christian-kohler.path-intellisense 2.8.0 on 2026-11-26.
What is tested is each way the package, the signature, the manifest or the key can be wrong, and what each is called."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.provenance.releases.openvsx_signature import OpenVsxSignature
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "openvsx"
PACKAGE = (DATA / "path-intellisense.vsix").read_bytes()
SIGZIP = (DATA / "path-intellisense.sigzip").read_bytes()
KEY = "14ccb407-4e79-41ed-be5a-6d608325c45a"


class Sigzip:
    @staticmethod
    def members() -> dict[str, bytes]:
        with zipfile.ZipFile(io.BytesIO(SIGZIP)) as archive:
            return {info.filename: archive.read(info.filename) for info in archive.infolist()}

    @classmethod
    def build(cls, **changes: bytes | None) -> bytes:
        members = {**cls.members(), **changes}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in members.items():
                if data is not None:
                    archive.writestr(name, data)
        return buffer.getvalue()


class TestARealExtension:
    def test_the_package_open_vsx_signed_verifies(self) -> None:
        found = OpenVsxSignature.verify(PACKAGE, SIGZIP, KEY)
        assert found.outcome == "verified", found.detail

    def test_a_changed_byte_in_the_package_fails_the_signature(self) -> None:
        raw = bytearray(PACKAGE)
        raw[1000] ^= 1
        found = OpenVsxSignature.verify(bytes(raw), SIGZIP, KEY)
        assert found.outcome == "invalid" and "does not verify" in found.detail

    def test_a_changed_signature_byte_fails(self) -> None:
        signature = bytearray(Sigzip.members()[".signature.sig"])
        signature[5] ^= 1
        assert (
            OpenVsxSignature.verify(
                PACKAGE, Sigzip.build(**{".signature.sig": bytes(signature)}), KEY
            ).outcome
            == "invalid"
        )

    def test_a_signature_of_the_wrong_length_fails(self) -> None:
        found = OpenVsxSignature.verify(
            PACKAGE, Sigzip.build(**{".signature.sig": b"\0" * 63}), KEY
        )
        assert found.outcome == "invalid"

    def test_a_missing_signature_entry_is_refused(self) -> None:
        assert (
            OpenVsxSignature.verify(PACKAGE, Sigzip.build(**{".signature.sig": None}), KEY).outcome
            == "invalid"
        )

    def test_a_manifest_that_is_not_this_packages_is_refused(self) -> None:
        manifest = json.loads(Sigzip.members()[".signature.manifest"])
        manifest["package"]["size"] += 1
        found = OpenVsxSignature.verify(
            PACKAGE, Sigzip.build(**{".signature.manifest": json.dumps(manifest).encode()}), KEY
        )
        assert found.outcome == "invalid" and "manifest" in found.detail

    @pytest.mark.parametrize(
        "manifest", [b"", b"{}", b"not json", b'{"package":{"size":1,"digests":{"sha256":"!!"}}}']
    )
    def test_a_manifest_that_does_not_state_the_package_is_refused(self, manifest: bytes) -> None:
        assert (
            OpenVsxSignature.verify(
                PACKAGE, Sigzip.build(**{".signature.manifest": manifest}), KEY
            ).outcome
            == "invalid"
        )

    @pytest.mark.parametrize("key", [None, "", "00000000-0000-0000-0000-000000000000"])
    def test_a_key_that_is_not_pinned_is_unverifiable(self, key: str | None) -> None:
        assert OpenVsxSignature.verify(PACKAGE, SIGZIP, key).outcome == "unverifiable"

    @pytest.mark.parametrize("junk", [b"", b"not a zip", b"PK\x05\x06" + b"\0" * 18])
    def test_something_that_is_not_a_signature_archive_is_refused(self, junk: bytes) -> None:
        assert OpenVsxSignature.verify(PACKAGE, junk, KEY).outcome == "invalid"

    def test_the_key_id_is_the_last_segment_of_the_registrys_link(self) -> None:
        assert OpenVsxSignature.key_id(f"https://open-vsx.org/api/-/public-key/{KEY}") == KEY
        assert OpenVsxSignature.key_id("https://open-vsx.org/api/-/public-key/../x") is None
        assert OpenVsxSignature.key_id(None) is None


class TestAskingOpenVsx:
    @staticmethod
    def serve(
        monkeypatch: pytest.MonkeyPatch, files: dict[str, Any] | Exception, sigzip: bytes = SIGZIP
    ) -> list[str]:
        from cordon_scanner.intel.base import PackageArchive
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
        from cordon_scanner.intel.registries.openvsx import OpenVsx
        from cordon_scanner.intel.registries.registry_request import RegistryRequest

        asked: list[str] = []

        def archive(ecosystem: str, name: str, version: str | None) -> PackageArchive:
            asked.append(f"archive {name} {version}")
            return PackageArchive(ecosystem, name, str(version), "x.vsix", PACKAGE)

        def document(url: str) -> dict[str, Any]:
            asked.append(url)
            if isinstance(files, Exception):
                raise files
            return {"files": files}

        def fetch(url: str, allow: Any, **more: Any) -> bytes:
            asked.append(url)
            return sigzip

        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(archive))
        monkeypatch.setattr(OpenVsx, "_json", staticmethod(document))
        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(fetch))
        return asked

    LINKS: ClassVar[dict[str, str]] = {
        "signature": "https://open-vsx.org/api/christian-kohler/path-intellisense/2.8.0/file/x.sigzip",
        "publicKey": f"https://open-vsx.org/api/-/public-key/{KEY}",
    }

    def test_the_signature_is_read_from_the_file_host_and_checked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.serve(monkeypatch, self.LINKS)
        found = OpenVsxSignature.check("christian-kohler.path-intellisense", "2.8.0", None)
        assert found.outcome == "verified", found.detail
        assert (
            asked[-1]
            == "https://openvsx.eclipsecontent.org/christian-kohler/path-intellisense/2.8.0/x.sigzip"
        )

    def test_a_release_with_no_signature_link_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(monkeypatch, {"publicKey": self.LINKS["publicKey"]})
        assert (
            OpenVsxSignature.check("christian-kohler.path-intellisense", "2.8.0", None).outcome
            == "absent"
        )

    def test_a_registry_that_cannot_be_asked_is_unverifiable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(monkeypatch, OSError("unreachable"))
        assert (
            OpenVsxSignature.check("christian-kohler.path-intellisense", "2.8.0", None).outcome
            == "unverifiable"
        )

    @pytest.mark.parametrize(("name", "version"), [("", "1"), ("a.b", "")])
    def test_no_name_or_version_is_absent(self, name: str, version: str) -> None:
        assert OpenVsxSignature.check(name, version, None).outcome == "absent"
