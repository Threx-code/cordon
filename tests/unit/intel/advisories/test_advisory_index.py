"""The advisory data read from a sealed SQLite index: the same answers, and nothing unverified.

```
  equivalence   every name in real shipped data: index == in-memory grouping, record for record
  tampering     a changed byte, a forged or missing seal, another file's index -> never opened
  injection     a name is bound as a parameter, never written into SQL
  read-only     a write through the index's connection fails
```
"""

from __future__ import annotations

import json

import pytest

from cordon_scanner.intel.advisories import advisories, shipped
from cordon_scanner.intel.advisories.advisory_index import AdvisoryIndex
from cordon_scanner.intel.advisories.shipped import ShippedAdvisories


class IndexKit:
    @staticmethod
    def isolate(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
        shipped.ShippedAdvisories.reset_caches()

    @staticmethod
    def records() -> list[dict[str, object]]:
        return [
            {
                "id": "MAL-1",
                "name": "Left-Pad",
                "malicious": True,
                "versions": ["1.0.0"],
                "summary": "s",
            },
            {
                "id": "GHSA-2",
                "name": "left-pad",
                "introduced": "0",
                "fixed": "1.3.0",
                "summary": "s",
            },
            {"id": "GHSA-3", "name": "other", "introduced": "0", "fixed": "2.0.0", "summary": "s"},
        ]

    @staticmethod
    def files(digest: str) -> tuple:
        base = AdvisoryIndex.directory() / f"{digest}-v2"
        return base.with_suffix(".sqlite"), base.with_suffix(".seal")


class TestEquivalence:
    @pytest.mark.parametrize("ecosystem", ["cargo", "composer", "rubygems", "hex", "pub", "nuget"])
    def test_every_name_reads_the_same_from_the_index(
        self, ecosystem, monkeypatch, tmp_path
    ) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        verified = shipped.ShippedAdvisories._verified_file(ecosystem)
        if verified is None:
            pytest.skip(f"no shipped {ecosystem} data in this checkout")
        path, digest = verified
        grouped: dict[str, list[dict[str, object]]] = {}
        for raw in shipped.ShippedAdvisories._parse(path):
            grouped.setdefault(str(raw["name"]).lower(), []).append(raw)
        index = AdvisoryIndex.for_file(digest, lambda: shipped.ShippedAdvisories._parse(path))
        assert index is not None
        assert sorted(index.names()) == sorted(grouped)
        for name, expected in grouped.items():
            assert [json.dumps(r, sort_keys=True) for r in index.get(name)] == [
                json.dumps(r, sort_keys=True) for r in expected
            ], name
        assert index.count == sum(len(v) for v in grouped.values())

    def test_the_database_answers_the_same_through_the_index(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        source = shipped.ShippedAdvisories._shipped_raw("cargo")
        if not isinstance(source, advisories.IndexedRecords):
            pytest.skip("no shipped cargo data in this checkout")
        database = ShippedAdvisories.database()
        name = next(iter(source))
        assert len(database.for_package("cargo", name)) >= 1


class TestTampering:
    def test_a_changed_byte_is_never_opened(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        assert AdvisoryIndex.for_file("d" * 64, IndexKit.records) is not None
        database, seal = IndexKit.files("d" * 64)
        body = bytearray(database.read_bytes())
        body[-1] ^= 0xFF
        database.write_bytes(bytes(body))
        assert AdvisoryIndex._verified(database, seal, "d" * 64) is None

    def test_a_tampered_index_is_rebuilt_from_the_verified_source(
        self, monkeypatch, tmp_path
    ) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        AdvisoryIndex.for_file("e" * 64, IndexKit.records)
        database, _ = IndexKit.files("e" * 64)
        database.write_bytes(b"not a database")
        index = AdvisoryIndex.for_file("e" * 64, IndexKit.records)
        assert index is not None and len(index.get("left-pad")) == 2

    def test_a_forged_seal_is_never_trusted(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        AdvisoryIndex.for_file("f" * 64, IndexKit.records)
        database, seal = IndexKit.files("f" * 64)
        document = json.loads(seal.read_text(encoding="utf-8"))
        document["_seal"] = "0" * 64
        seal.write_text(json.dumps(document), encoding="utf-8")
        assert AdvisoryIndex._verified(database, seal, "f" * 64) is None

    def test_a_missing_seal_is_never_trusted(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        AdvisoryIndex.for_file("a" * 64, IndexKit.records)
        database, seal = IndexKit.files("a" * 64)
        seal.unlink()
        assert AdvisoryIndex._verified(database, seal, "a" * 64) is None

    def test_another_files_index_is_not_this_ones(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        AdvisoryIndex.for_file("b" * 64, IndexKit.records)
        database, seal = IndexKit.files("b" * 64)
        assert AdvisoryIndex._verified(database, seal, "c" * 64) is None


class TestQueries:
    def test_a_name_is_data_not_sql(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        index = AdvisoryIndex.for_file("1" * 64, IndexKit.records)
        assert index is not None
        assert index.get("x' OR '1'='1") == ()
        assert index.get("left-pad'; DROP TABLE advisories; --") == ()
        assert len(index.get("left-pad")) == 2

    def test_the_connection_cannot_write(self, monkeypatch, tmp_path) -> None:
        import sqlite3

        IndexKit.isolate(monkeypatch, tmp_path)
        index = AdvisoryIndex.for_file("2" * 64, IndexKit.records)
        assert index is not None
        with pytest.raises(sqlite3.Error):
            index._connection.execute("DELETE FROM advisories")

    def test_withdrawn_and_replaced_records_are_left_out(self, monkeypatch, tmp_path) -> None:
        IndexKit.isolate(monkeypatch, tmp_path)
        index = AdvisoryIndex.for_file("3" * 64, IndexKit.records)
        upsert = {
            "id": "GHSA-9",
            "name": "left-pad",
            "introduced": "0",
            "fixed": "9.0.0",
            "summary": "s",
        }
        records = advisories.IndexedRecords(index, [upsert], frozenset({"MAL-1", "GHSA-9"}))
        assert [r["id"] for r in records["left-pad"]] == ["GHSA-2", "GHSA-9"]
        assert records.record_count == 3
        assert "other" in records and "missing" not in records
