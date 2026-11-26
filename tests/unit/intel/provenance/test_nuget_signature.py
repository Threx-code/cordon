"""A NuGet package's repository signature (`intel/provenance/nuget_signature`), on real packages from nuget.org.

`isexternalinit.1.0.3.nupkg` is signed by nuget.org alone; `microsoft.netcore.targets.5.0.0.nupkg` is signed by its author
(Microsoft) and counter-signed by nuget.org. Both were downloaded from api.nuget.org on 2026-11-26. Their certificates have
long expired or will: what dates each signature is the time-stamp inside it. What is tested is each way the package, the
signature or the stamp can be wrong, and what each is called."""

from __future__ import annotations

import datetime as dt

import pytest

from cordon_scanner.intel.provenance.releases.nuget_signature import NuGetSignature, ZipLayout
from cordon_scanner.intel.provenance.releases.revocation import Crl, Revocation
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


class Fetching:
    CRL = (DATA / "crl" / "codesigning-ca1.crl").read_bytes()
    SIGNATURE = (DATA / "crl" / "serilog-4.2.0.signature.p7s").read_bytes()
    #: The day the list was captured; it is current from the 25th to 2 December 2026.
    NOW = dt.datetime(2026, 11, 26, tzinfo=dt.UTC)

    @staticmethod
    def refuse(url: str) -> bytes:
        raise OSError("unreachable")

    @classmethod
    def serving(cls, data: bytes | None = None):
        asked: list[str] = []

        def fetch(url: str) -> bytes:
            asked.append(url)
            return cls.CRL if data is None else data

        fetch.asked = asked  # type: ignore[attr-defined]
        return fetch

    @classmethod
    def certificates(cls):
        from cordon_scanner.foundation.signatures.der import Der
        from cordon_scanner.intel.provenance.releases.cms import Cms

        pool = Cms.parse(Der.parse(cls.SIGNATURE)).certificates
        signing = next(c for c in pool if b"NuGet.org Repository" in c.subject)
        issuer = next(c for c in pool if c.subject == signing.issuer)
        return signing, issuer


class TestRevocation:
    @pytest.fixture(autouse=True)
    def fresh(self) -> None:
        Revocation._cache.clear()

    def test_the_signing_certificate_names_its_issuers_list(self) -> None:
        signing, _ = Fetching.certificates()
        assert Revocation.urls(signing)[0].startswith(
            "http://crl3.digicert.com/DigiCertTrustedG4CodeSigning"
        )

    def test_a_certificate_the_issuer_has_not_revoked_is_checked(self) -> None:
        signing, issuer = Fetching.certificates()
        fetch = Fetching.serving()
        assert Revocation.status(signing, issuer, fetch, Fetching.NOW) == "checked"
        assert fetch.asked == Revocation.urls(signing)[:1]

    def test_a_list_is_asked_for_once_until_its_next_update(self) -> None:
        signing, issuer = Fetching.certificates()
        fetch = Fetching.serving()
        Revocation.status(signing, issuer, fetch, Fetching.NOW)
        Revocation.status(signing, issuer, fetch, Fetching.NOW + dt.timedelta(days=3))
        assert len(fetch.asked) == 1

    def test_a_serial_the_real_list_names_is_revoked(self) -> None:
        import dataclasses

        signing, issuer = Fetching.certificates()
        crl = Crl.parse(Fetching.CRL)
        assert 0x05EC0DFCB430D94599C493D1FC5B30A2 in crl.revoked and len(crl.revoked) > 4000
        revoked = dataclasses.replace(signing, serial=0x05EC0DFCB430D94599C493D1FC5B30A2)
        assert Revocation.status(revoked, issuer, Fetching.serving(), Fetching.NOW) == "revoked"

    def test_without_a_fetcher_it_says_it_was_not_consulted(self) -> None:
        signing, issuer = Fetching.certificates()
        assert Revocation.status(signing, issuer, None, Fetching.NOW) == "not consulted"

    def test_a_list_that_cannot_be_had_is_named_unavailable(self) -> None:
        signing, issuer = Fetching.certificates()
        found = Revocation.status(signing, issuer, Fetching.refuse, Fetching.NOW)
        assert found.startswith("unavailable: ")

    def test_a_list_past_its_next_update_is_not_trusted(self) -> None:
        signing, issuer = Fetching.certificates()
        late = Fetching.NOW + dt.timedelta(days=30)
        assert "not current" in Revocation.status(signing, issuer, Fetching.serving(), late)

    def test_a_list_changed_after_it_was_signed_is_refused(self) -> None:
        signing, issuer = Fetching.certificates()
        found = Revocation.status(
            signing, issuer, Fetching.serving(Archive.flip(Fetching.CRL, 3000)), Fetching.NOW
        )
        assert found.startswith("unavailable: ") and "signature" in found

    def test_a_list_of_another_issuer_is_refused(self) -> None:
        signing, _ = Fetching.certificates()
        found = Revocation.status(signing, signing, Fetching.serving(), Fetching.NOW)
        assert "not the issuer's" in found

    @pytest.mark.parametrize("junk", [b"", b"x" * 40, b"\x30\x03\x02\x01\x00"])
    def test_something_that_is_not_a_list_is_unavailable_not_a_crash(self, junk: bytes) -> None:
        signing, issuer = Fetching.certificates()
        assert Revocation.status(signing, issuer, Fetching.serving(junk), Fetching.NOW).startswith(
            "unavailable: "
        )

    def test_a_revoked_certificate_refuses_the_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Revocation, "status", classmethod(lambda cls, *a: "revoked"))
        found = NuGetSignature.verify(REPOSITORY_ONLY, fetcher=Fetching.refuse)
        assert found.outcome == "invalid" and "revoked" in found.detail

    def test_the_answer_names_what_was_consulted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert NuGetSignature.verify(REPOSITORY_ONLY).detail.endswith("revocation not consulted")
        found = NuGetSignature.verify(REPOSITORY_ONLY, fetcher=Fetching.refuse)
        assert found.outcome == "verified" and "revocation unavailable: " in found.detail


class TestThePublicOnlyConnection:
    def test_a_name_that_resolves_to_a_private_address_is_refused(self) -> None:
        from cordon_scanner.foundation.network.pinned import PinnedHTTPConnection

        with pytest.raises(OSError, match="not a public one"):
            PinnedHTTPConnection("localhost", 80).connect()
