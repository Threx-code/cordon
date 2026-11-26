"""A NuGet package's repository signature (`intel/provenance/nuget_signature`), on real packages from nuget.org.

`isexternalinit.1.0.3.nupkg` is signed by nuget.org alone; `microsoft.netcore.targets.5.0.0.nupkg` is signed by its author
(Microsoft) and counter-signed by nuget.org. Both were downloaded from api.nuget.org on 2026-11-26. Their certificates have
long expired or will: what dates each signature is the time-stamp inside it. What is tested is each way the package, the
signature or the stamp can be wrong, and what each is called."""

from __future__ import annotations

import datetime as dt

import pytest

from cordon_scanner.intel.provenance.releases.nuget_signature import NuGetSignature, ZipLayout
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "nuget"
REPOSITORY_ONLY = (DATA / "isexternalinit.1.0.3.nupkg").read_bytes()
AUTHOR_AND_REPOSITORY = (DATA / "microsoft.netcore.targets.5.0.0.nupkg").read_bytes()


class Archive:
    @staticmethod
    def flip(data: bytes, at: int) -> bytes:
        out = bytearray(data)
        out[at] ^= 1
        return bytes(out)

    @staticmethod
    def first_entry_body(data: bytes) -> int:
        layout = ZipLayout(data)
        local = layout.starts[0]
        name, extra = (
            int.from_bytes(data[local + 26 : local + 28], "little"),
            int.from_bytes(data[local + 28 : local + 30], "little"),
        )
        return local + 30 + name + extra + 1


class TestRealPackages:
    def test_a_package_signed_by_nuget_org_alone_verifies(self) -> None:
        found = NuGetSignature.verify(REPOSITORY_ONLY)
        assert found.outcome == "verified", found.detail

    def test_an_authors_package_verifies_by_the_repositorys_counter_signature(self) -> None:
        found = NuGetSignature.verify(AUTHOR_AND_REPOSITORY)
        assert found.outcome == "verified", found.detail

    def test_the_stated_hash_is_the_archives_with_the_signature_cut_out(self) -> None:
        layout = ZipLayout(REPOSITORY_ONLY)
        assert layout.signature[3] == b".signature.p7s" and len(layout.package_hash("sha256")) == 32

    def test_the_two_pinned_roots_are_the_ones_digicert_published(self) -> None:
        names = sorted(root.subject for root in NuGetSignature.roots())
        assert (
            len(names) == 3
            and sum(b"DigiCert" in name for name in names) == 2
            and sum(b"VeriSign Universal" in name for name in names) == 1
        )


class TestWhatCannotBeTrusted:
    @pytest.mark.parametrize("package", [REPOSITORY_ONLY, AUTHOR_AND_REPOSITORY])
    def test_a_changed_byte_in_a_file_fails_the_hash(self, package: bytes) -> None:
        found = NuGetSignature.verify(Archive.flip(package, Archive.first_entry_body(package)))
        assert found.outcome == "invalid" and "its hash differs" in found.detail

    @pytest.mark.parametrize("package", [REPOSITORY_ONLY, AUTHOR_AND_REPOSITORY])
    def test_a_changed_byte_in_a_signature_or_its_time_stamp_is_refused(
        self, package: bytes
    ) -> None:
        from cordon_scanner.foundation.signatures.der import Der
        from cordon_scanner.intel.provenance.releases.cms import Cms

        layout = ZipLayout(package)
        local = layout.signature[2]
        name = int.from_bytes(package[local + 26 : local + 28], "little")
        extra = int.from_bytes(package[local + 28 : local + 30], "little")
        start = local + 30 + name + extra
        body = layout.signature_bytes()
        signature = Cms.parse(Der.parse(body)).signers[0].signature
        for inside in (body.index(signature) + 5, len(body) - 40):
            found = NuGetSignature.verify(Archive.flip(package, start + inside))
            assert found.outcome == "invalid", found.detail

    def test_an_archive_with_no_signature_is_absent(self) -> None:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "x")
        assert NuGetSignature.verify(buffer.getvalue()).outcome == "absent"

    @pytest.mark.parametrize("junk", [b"", b"PK\x05\x06" + b"\0" * 18, b"not a zip" * 20])
    def test_something_that_is_not_a_package_is_not_verified(self, junk: bytes) -> None:
        assert NuGetSignature.verify(junk).outcome in ("invalid", "absent")

    def test_a_signature_made_by_anyone_but_the_repository_is_not_taken_for_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(NuGetSignature, "REPOSITORY", "Somebody Else")
        assert NuGetSignature.verify(REPOSITORY_ONLY).outcome == "unverifiable"

    def test_no_pinned_root_means_no_chain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(NuGetSignature, "_roots", ())
        found = NuGetSignature.verify(REPOSITORY_ONLY)
        assert found.outcome == "invalid" and "pinned time-stamping authority" in found.detail

    def test_a_time_stamp_signed_by_no_pinned_authority_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        roots = NuGetSignature.roots()
        monkeypatch.setattr(NuGetSignature, "_roots", roots[:2])
        # The stamp's authority chains to the VeriSign root, which is the one left out.
        found = NuGetSignature.verify(REPOSITORY_ONLY)
        assert found.outcome == "invalid", found.detail

    def test_a_signature_checked_after_the_certificate_expired_but_stamped_before_still_verifies(
        self,
    ) -> None:
        late = dt.datetime(2040, 1, 1, tzinfo=dt.UTC)
        assert NuGetSignature.verify(REPOSITORY_ONLY, late).outcome == "verified"


class TestAskingForAPackage:
    def stand_in(
        self, monkeypatch: pytest.MonkeyPatch, data: bytes | Exception
    ) -> list[tuple[str, str, str]]:
        from cordon_scanner.intel.base import PackageArchive
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        asked: list[tuple[str, str, str]] = []

        def package_archive(ecosystem: str, name: str, version: str | None) -> PackageArchive:
            asked.append((ecosystem, name, str(version)))
            if isinstance(data, Exception):
                raise data
            return PackageArchive(ecosystem, name, str(version), "x.nupkg", data)

        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(package_archive))
        return asked

    def test_the_archive_is_the_one_the_verified_layer_returns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.stand_in(monkeypatch, REPOSITORY_ONLY)
        assert NuGetSignature.check("IsExternalInit", "1.0.3", None).outcome == "verified"
        assert asked == [("nuget", "IsExternalInit", "1.0.3")]

    def test_an_archive_that_cannot_be_fetched_is_unverifiable_not_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registry import RegistryError

        self.stand_in(monkeypatch, RegistryError("unreachable"))
        assert NuGetSignature.check("a", "1", None).outcome == "unverifiable"

    @pytest.mark.parametrize(("name", "version"), [("", "1"), ("a", "")])
    def test_no_name_or_version_is_absent(self, name: str, version: str) -> None:
        assert NuGetSignature.check(name, version, None).outcome == "absent"
