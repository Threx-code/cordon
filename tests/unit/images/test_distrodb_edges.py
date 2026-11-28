"""Distribution advisories on the records, versions and files that are rarely met: other families' orderings, odd OSV shapes, a synced export and the refusals when it was changed (`images/distrodb.py`)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.images.distrodb import DistroDatabase, DistroVersions, Record
from cordon_scanner.images.osv import Query
from cordon_scanner.intel.advisories import osv_import


class _Kit:
    @staticmethod
    def record(**over: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "id": "DSA-1",
            "summary": "s",
            "affected": [
                {
                    "package": {"ecosystem": "Debian:12", "name": "openssl"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2"}]}
                    ],
                }
            ],
        }
        return {**base, **over}


class TestOrderings:
    def test_a_dpkg_letter_sorts_by_its_code_and_a_symbol_after_every_letter(self) -> None:
        assert DistroVersions.dpkg("1.0a", "1.0b") < 0
        assert DistroVersions.dpkg("1.0+", "1.0a") > 0

    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [("1.0-1", "1.0-2", -1), ("1:1.0-1", "2.0-1", 1), ("2.0-1", "2.0-1", 0), ("2.0", "2.0-1", -1)],
    )
    def test_rpm_orders_by_epoch_then_version_then_release(self, a: str, b: str, expected: int) -> None:
        assert (DistroVersions.rpm(a, b) > 0) - (DistroVersions.rpm(a, b) < 0) == expected

    def test_each_family_is_compared_by_its_own_rule(self) -> None:
        assert DistroVersions.for_ecosystem("Ubuntu:22.04:LTS") is DistroVersions.dpkg
        assert DistroVersions.for_ecosystem("Wolfi") is DistroVersions.apk
        assert DistroVersions.for_ecosystem("Rocky Linux:9") is DistroVersions.rpm


class TestRecordIntervals:
    def test_a_version_named_outright_is_affected_whatever_the_intervals_say(self) -> None:
        record = Record("X", (("0", "1", None),), ("5.0",), None, "", (), "")
        assert record.affects("5.0", DistroVersions.dpkg)

    def test_a_version_before_the_introduced_one_or_after_the_last_affected_one_is_not_affected(self) -> None:
        record = Record("X", (("2.0", None, "3.0"),), (), None, "", (), "")
        assert not record.affects("1.0", DistroVersions.dpkg)
        assert not record.affects("3.1", DistroVersions.dpkg)
        assert record.affects("2.5", DistroVersions.dpkg)

    def test_a_record_with_no_fixed_interval_has_no_fixed_version(self) -> None:
        assert Record("X", ((None, None, "1"),), (), None, "", (), "").fixed == ""


class TestOsvRecords:
    def test_a_withdrawn_record_or_one_with_no_id_names_nothing(self) -> None:
        assert DistroDatabase._record(_Kit.record(withdrawn="2024-01-01")) == []
        assert DistroDatabase._record(_Kit.record(id="")) == []

    def test_the_ubuntu_rating_and_a_database_severity_are_kept_as_the_rating(self) -> None:
        ubuntu = DistroDatabase._record(_Kit.record(severity=[{"type": "Ubuntu", "score": "High"}]))
        assert ubuntu[0][2][4] == "high"
        specific = DistroDatabase._record(_Kit.record(database_specific={"severity": "Medium"}))
        assert specific[0][2][4] == "medium"

    def test_affected_entries_that_cannot_be_read_are_skipped_and_open_ranges_are_kept(self) -> None:
        affected = [
            "junk",
            {"package": {"ecosystem": "", "name": "x"}},
            {
                "package": {"ecosystem": "Debian:12", "name": "a"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "0"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}]},
                ],
            },
            {"package": {"ecosystem": "Debian:12", "name": "b"}},
        ]
        records = DistroDatabase._record(_Kit.record(affected=affected))
        assert [(e, n) for e, n, _ in records] == [("Debian:12", "a")]
        assert records[0][2][1] == [["1.0", None, "1.5"], ["2.0", None, None]]


class TestSyncedFiles:
    @pytest.fixture
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(DistroDatabase, "directory", staticmethod(lambda: tmp_path / "os"))
        return tmp_path / "os"

    def test_a_downloaded_export_is_indexed_and_the_archive_removed(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def download(url: str, target: Path, *, limit: int) -> None:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("a.json", json.dumps(_Kit.record()))
                archive.writestr("notes.txt", "not a record")
                archive.writestr("bad.json", "{nope")
                archive.writestr("list.json", "[1, 2]")
            target.write_bytes(buffer.getvalue())

        monkeypatch.setattr(osv_import.OsvImport, "_download", staticmethod(download))
        assert DistroDatabase.sync("debian", tmp_dir=tmp_path) == 1
        assert not (tmp_path / "os-debian.zip").exists()
        assert DistroDatabase.covers("Debian:12")
        query = Query("Debian:12", "openssl", "1")
        assert [v.id for v in DistroDatabase.match("Debian:12", [query]).by_query[query]] == ["DSA-1"]

    def test_a_manifest_that_is_not_sealed_by_this_install_is_refused(self, home: Path) -> None:
        DistroDatabase._write("debian", {})
        (home / "os-digests.json").write_text('{"os-debian.json.gz": "x"}', encoding="utf-8")
        with pytest.raises(ValueError, match="not sealed by this install"):
            DistroDatabase.load("debian")

    def test_a_family_never_written_loads_as_nothing_and_a_release_with_no_records_says_so(self, home: Path) -> None:
        assert DistroDatabase.load("debian") is None
        DistroDatabase._write("debian", {"Debian:12": {}})
        query = Query("Debian:11", "x", "1")
        assert DistroDatabase.match("Debian:11", [query]).problems
        assert DistroDatabase.match("Fedora:39", [query]) is None

    def test_a_second_family_written_keeps_the_first_familys_digest(self, home: Path) -> None:
        DistroDatabase._write("debian", {"Debian:12": {}})
        DistroDatabase._write("alpine", {"Alpine:v3.19": {}})
        assert DistroDatabase.load("debian") == {"Debian:12": {}}
        assert DistroDatabase.load("alpine") == {"Alpine:v3.19": {}}

    def test_a_manifest_that_is_not_json_loads_as_nothing(self, home: Path) -> None:
        DistroDatabase._write("debian", {"Debian:12": {}})
        (home / "os-digests.json").write_text("{nope", encoding="utf-8")
        assert DistroDatabase.load("debian") is None

    def test_a_version_the_ordering_cannot_compare_is_not_a_match(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        record = ["DSA-1", [["0", "2", None]], [], None, "", [], ""]
        DistroDatabase._write("debian", {"Debian:12": {"openssl": [record]}})

        def refuses(a: str, b: str) -> int:
            raise ValueError("not comparable")

        monkeypatch.setattr(DistroVersions, "for_ecosystem", staticmethod(lambda eco: refuses))
        query = Query("Debian:12", "openssl", "1")
        assert DistroDatabase.match("Debian:12", [query]).by_query[query] == []

    def test_a_digit_in_a_dpkg_run_orders_as_nothing(self) -> None:
        assert DistroVersions._dpkg_order("7") == 0

    def test_writing_over_a_manifest_that_cannot_be_read_starts_a_fresh_one(self, home: Path) -> None:
        DistroDatabase._write("debian", {"Debian:12": {}})
        (home / "os-digests.json").write_text("{nope", encoding="utf-8")
        DistroDatabase._write("alpine", {"Alpine:v3.19": {}})
        assert DistroDatabase.load("alpine") == {"Alpine:v3.19": {}}
        with pytest.raises(ValueError, match="does not match its recorded digest|digest"):
            DistroDatabase.load("debian")
