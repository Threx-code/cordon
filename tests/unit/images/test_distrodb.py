"""L4: distribution advisories synced to disk and matched offline."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from cordon_scanner.images.distrodb import DistroDatabase, DistroVersions, Record
from cordon_scanner.images.osv import Query


class TestDpkg:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("1.0", "1.0", 0),
            ("1.0", "1.1", -1),
            ("1.0~rc1", "1.0", -1),  # a tilde sorts before anything, even the end
            ("1.0~~", "1.0~", -1),
            ("1.0+b1", "1.0", 1),
            ("1:0.9", "2.0", 1),  # the epoch dominates
            ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
            ("3.0.11-1~deb12u2", "3.0.11-1", -1),
            ("1.2.13.dfsg-1", "1.2.13.dfsg-1+b1", -1),
            ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1),
            ("10", "9", 1),
            ("1.0a", "1.0", 1),
            ("1.0-1", "1.0-1ubuntu1", -1),
        ],
    )
    @pytest.mark.conformance("x", "x.os-packages")
    def test_debian_policy_ordering(self, a, b, expected) -> None:
        assert DistroVersions.dpkg(a, b) == expected
        assert DistroVersions.dpkg(b, a) == -expected


class TestApk:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("1.2.3-r0", "1.2.3-r1", -1),
            ("1.2.3-r9", "1.2.10-r0", -1),
            ("1.2.3_rc1-r0", "1.2.3-r0", -1),
            ("1.2.3_p1-r0", "1.2.3-r0", 1),
            ("1.2.3a-r0", "1.2.3-r0", 1),
            ("3.3.1-r0", "3.3.1-r0", 0),
            ("1.36.1-r29", "1.36.1-r30", -1),
        ],
    )
    @pytest.mark.conformance("x", "x.os-packages")
    def test_alpine_ordering(self, a, b, expected) -> None:
        assert DistroVersions.apk(a, b) == expected


class TestRecords:
    def test_a_fixed_range(self) -> None:
        record = Record("DSA-1", ((None, "3.0.11-1~deb12u2", None),), (), None, "", (), "")
        assert record.affects("3.0.9-1", DistroVersions.dpkg)
        assert not record.affects("3.0.11-1~deb12u2", DistroVersions.dpkg)
        assert not record.affects("3.0.15-1~deb12u1", DistroVersions.dpkg)

    def test_an_unfixed_range(self) -> None:
        record = Record("CVE-2", (("0", None, None),), (), None, "", (), "")
        assert record.affects("1.0-1", DistroVersions.dpkg)


class TestSyncAndMatch:
    RAW: ClassVar[dict[str, Any]] = {
        "id": "DEBIAN-CVE-2024-0001",
        "aliases": [],
        "upstream": ["CVE-2024-0001"],
        "summary": "a flaw",
        "affected": [
            {
                "package": {"ecosystem": "Debian:12", "name": "openssl"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"}],
                    }
                ],
            },
            {
                "package": {"ecosystem": "Debian:11", "name": "openssl"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.1.1w-0+deb11u2"}],
                    }
                ],
            },
        ],
    }

    @pytest.fixture
    def synced(self, tmp_path, monkeypatch):
        monkeypatch.setattr(DistroDatabase, "directory", staticmethod(lambda: tmp_path / "os"))
        index: dict = {}
        for ecosystem, name, record in DistroDatabase._record(self.RAW):
            index.setdefault(ecosystem, {}).setdefault(name, []).append(record)
        DistroDatabase._write("debian", index)
        return tmp_path / "os"

    @pytest.mark.conformance("x", "x.os-packages")
    def test_matched_by_release_and_source_package(self, synced) -> None:
        affected, patched = (
            Query("Debian:12", "openssl", "3.0.11-1~deb12u2"),
            Query("Debian:12", "openssl", "3.0.13-1~deb12u1"),
        )
        matches = DistroDatabase.match("Debian:12", [affected, patched])
        [vulnerability] = matches.by_query[affected]
        assert vulnerability.id == "DEBIAN-CVE-2024-0001" and "CVE-2024-0001" in vulnerability.cves
        assert vulnerability.fixed == "3.0.13-1~deb12u1"
        assert matches.by_query[patched] == []

    def test_another_release_s_range_does_not_apply(self, synced) -> None:
        query = Query("Debian:11", "openssl", "1.1.1w-0+deb11u2")
        assert DistroDatabase.match("Debian:11", [query]).by_query[query] == []

    def test_a_family_never_synced_is_none(self, synced) -> None:
        assert (
            DistroDatabase.match("Alpine:v3.19", [Query("Alpine:v3.19", "musl", "1.2.4-r2")])
            is None
        )
        assert DistroDatabase.covers("Debian:12") and not DistroDatabase.covers("Alpine:v3.19")

    def test_an_edited_file_is_refused(self, synced) -> None:
        (synced / "os-debian.json.gz").write_bytes(b"tampered")
        with pytest.raises(ValueError, match="digest"):
            DistroDatabase.match("Debian:12", [Query("Debian:12", "openssl", "1")])
