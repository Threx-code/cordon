"""OS release names, package identities and the package databases on inputs that are cut short or damaged: each is refused by name or skipped (`images/packages.py`)."""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

import pytest

from cordon_scanner.images.packages import (
    DpkgDatabase,
    OsPackage,
    OsRelease,
    RpmDatabase,
)


class TestReleaseNames:
    @pytest.mark.parametrize(
        ("release", "ecosystem"),
        [
            (OsRelease("rhel", "9.3"), "Red Hat"),
            (OsRelease("chainguard", ""), "Chainguard"),
            (OsRelease("wolfi", ""), "Wolfi"),
            (OsRelease("debian", "12"), "Debian:12"),
            (OsRelease("amzn", "2023"), None),
        ],
    )
    def test_each_distribution_is_named_the_way_osv_names_it(
        self, release: OsRelease, ecosystem: str | None
    ) -> None:
        assert release.osv_ecosystem == ecosystem


class TestPackageIdentity:
    def test_an_rpm_with_an_epoch_is_versioned_with_it_and_qualified_by_it(self) -> None:
        package = OsPackage("rpm", "bash", "5.1.8-6.el9", arch="x86_64", epoch="2")
        assert package.advisory_version == "2:5.1.8-6.el9"
        assert "epoch=2" in package.purl(OsRelease("rhel", "9"))

    def test_a_package_without_an_epoch_is_versioned_as_it_is(self) -> None:
        assert OsPackage("rpm", "bash", "5.1.8-6.el9").advisory_version == "5.1.8-6.el9"
        assert OsPackage("apk", "musl", "1.2.4-r2").advisory_version == "1.2.4-r2"


class TestDpkg:
    def test_a_stanza_with_no_name_or_no_version_is_not_a_package(self) -> None:
        data = b"Package: a\nStatus: install ok installed\n\nVersion: 1\nStatus: install ok installed\n"
        assert DpkgDatabase.dpkg(data) == []


class TestRpm:
    def test_a_header_too_short_or_too_long_is_refused(self) -> None:
        with pytest.raises(ValueError, match="outside the reader's limits"):
            RpmDatabase.rpm_header(b"short")

    def test_a_header_entry_that_points_outside_its_data_is_passed_over(self) -> None:
        index = struct.pack(">IIII", 1000, _STRING, 1 << 20, 1)
        blob = struct.pack(">II", 1, 16) + index + b"x" * 16
        assert RpmDatabase.rpm_header(blob) == {}

    def test_a_file_that_is_not_a_berkeley_db_hash_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not a Berkeley DB hash database"):
            RpmDatabase.rpm_bdb_blobs(bytes(512))

    def test_a_page_size_that_is_not_a_power_of_two_is_refused(self) -> None:
        database = bytearray(512)
        struct.pack_into(">I", database, 12, 0x061561)
        struct.pack_into(">I", database, 20, 1000)
        with pytest.raises(ValueError, match="page size"):
            RpmDatabase.rpm_bdb_blobs(bytes(database))

    def test_a_file_that_is_not_an_ndb_or_has_an_impossible_slot_table_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not an NDB package database"):
            RpmDatabase.rpm_ndb_blobs(b"nope" + bytes(40))
        header = bytearray(b"RpmP" + bytes(40))
        struct.pack_into("<I", header, 12, 0)
        with pytest.raises(ValueError, match="slot table size is out of range"):
            RpmDatabase.rpm_ndb_blobs(bytes(header))


_STRING = 6


class _Header:
    """An RPM header blob: the index of (tag, type, offset, count) then the store."""

    STRING, INT32, STRING_ARRAY = 6, 4, 8

    @staticmethod
    def build(entries: list[tuple[int, int, bytes, int]]) -> bytes:
        store = b""
        index = b""
        for tag, kind, payload, items in entries:
            index += struct.pack(">iiii", tag, kind, len(store), items)
            store += payload
        return struct.pack(">II", len(entries), len(store)) + index + store

    @classmethod
    def package(
        cls,
        name: str,
        *,
        epoch: int | None = None,
        files: tuple[str, list[str], list[int]] | None = None,
    ) -> bytes:
        entries = [
            (1000, cls.STRING, name.encode() + b"\x00", 1),
            (1001, cls.STRING, b"1.0\x00", 1),
            (1002, cls.STRING, b"1.el9\x00", 1),
            (1022, cls.STRING, b"x86_64\x00", 1),
        ]
        if epoch is not None:
            entries.append((1003, cls.INT32, struct.pack(">i", epoch), 1))
        if files:
            directory, bases, indexes = files
            entries += [
                (1116, cls.INT32, struct.pack(f">{len(indexes)}i", *indexes), len(indexes)),
                (1117, cls.STRING_ARRAY, b"".join(b.encode() + b"\x00" for b in bases), len(bases)),
                (1118, cls.STRING_ARRAY, directory.encode() + b"\x00", 1),
            ]
        return cls.build(entries)


class TestRpmSqlite:
    def database(self, tmp_path: Path, blobs: list[bytes]) -> bytes:
        path = tmp_path / "rpmdb.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        connection.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in blobs])
        connection.commit()
        connection.close()
        return path.read_bytes()

    def test_packages_are_read_from_a_sqlite_database_with_their_epoch_and_owned_files(
        self, tmp_path: Path
    ) -> None:
        blob = _Header.package("bash", epoch=2, files=("/usr/bin/", ["bash", "sh"], [0, 0]))
        packages = RpmDatabase.rpm_sqlite(self.database(tmp_path, [blob]))
        assert [(p.name, p.epoch) for p in packages] == [("bash", "2")]
        assert RpmDatabase.rpm_owned([blob]) == {"usr/bin/bash", "usr/bin/sh"}

    def test_a_header_whose_index_runs_past_its_end_owns_nothing_and_is_not_an_error(self) -> None:
        blob = struct.pack(">II", 100_000_000, 8) + b"x" * 8
        assert RpmDatabase.rpm_owned([blob]) == set()

    def test_a_dirindexes_entry_that_does_not_fit_and_other_tags_are_passed_over(self) -> None:
        blob = _Header.build(
            [(1000, _Header.STRING, b"a\x00", 1), (1116, _Header.INT32, b"\x00\x00\x00\x00", 1000)]
        )
        assert RpmDatabase.rpm_owned([blob]) == set()


class TestOtherDatabases:
    def test_a_pacman_entry_with_no_name_or_version_is_not_a_package(self) -> None:
        from cordon_scanner.images.packages import PacmanDatabase

        files = {"var/lib/pacman/local/x-1/desc": b"%NAME%\nx\n"}
        assert PacmanDatabase.pacman(files) == []

    def test_the_files_a_pacman_package_owns_leave_out_its_directories(self) -> None:
        from cordon_scanner.images.packages import PacmanDatabase

        files = {"var/lib/pacman/local/x-1/files": b"%FILES%\nusr/\nusr/bin/x\n"}
        assert PacmanDatabase.pacman_owned(files) == {"usr/bin/x"}

    def test_a_portage_directory_that_is_no_package_is_skipped(self) -> None:
        from cordon_scanner.images.packages import PortageDatabase

        files = {"var/db/pkg/sys-apps/not-a-version/RDEPEND": b"x"}
        assert PortageDatabase.portage(files) == []
