"""The advisory data read from a sealed SQLite index: the same answers, and nothing unverified.

```
  equivalence   every name in real shipped data: index == in-memory grouping, record for record
  tampering     a changed byte, a forged or missing seal, another file's index -> never opened
  injection     a name is bound as a parameter, never written into SQL
  read-only     a write through the index's connection fails
  streaming     the build reads the file element by element (`AdvisoryFiles.stream_records`):
                what `json.load` makes of it, at every window size; non-JSON refused
```
"""

from __future__ import annotations

import gzip
import io
import json
import random
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.advisories import advisories, shipped, shipped_table
from cordon_scanner.intel.advisories.advisories import DATA_DIR, AdvisoryFiles
from cordon_scanner.intel.advisories.advisory_index import AdvisoryIndex
from cordon_scanner.intel.advisories.shipped import ShippedAdvisories
from cordon_scanner.intel.advisories.shipped_table import ShippedTable


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


WINDOWS = (1, 2, 3, 5, 7, 16, 64, 1 << 20)


class StreamKit:
    @staticmethod
    def record(rng: random.Random, i: int) -> object:
        text = "".join(rng.choice('ab ,:[]{}"\\\n\té💥\u2028') for _ in range(rng.randint(0, 12)))
        return {
            "name": f"pkg-{i}",
            "id": f"GHSA-{i:04d}",
            "summary": text,
            "ranges": [[rng.randint(-5, 10**12), rng.random(), None, True]],
            "nested": {"deep": [{"x": text}] * rng.randint(0, 3)},
        }

    @staticmethod
    def write(tmp_path: Path, text: str, zipped: bool) -> Path:
        path = tmp_path / ("a.json.gz" if zipped else "a.json")
        if zipped:
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def streamed(path: Path, window: int) -> list[object]:
        return list(AdvisoryFiles.stream_records(path, chunk=window))


class TestStreamedElements:
    @pytest.mark.parametrize("zipped", [True, False])
    def test_random_arrays_stream_as_json_load_reads_them(
        self, tmp_path: Path, zipped: bool
    ) -> None:
        rng = random.Random(20261031)  # noqa: S311 -- a fixture, not key material
        for trial in range(40):
            values: list[object] = [StreamKit.record(rng, i) for i in range(rng.randint(0, 25))]
            values += [rng.randint(-(10**15), 10**15), 1.5e300, "s", None, False, [], {}]
            rng.shuffle(values)
            gap = rng.choice(["", " ", "\n", " \t\r\n "])
            text = gap + "[" + gap + ("," + gap).join(json.dumps(v) for v in values) + gap + "]"
            path = StreamKit.write(tmp_path, text + gap, zipped)
            whole = AdvisoryFiles._read_records(path)
            for window in WINDOWS:
                assert StreamKit.streamed(path, window) == whole, (trial, window)

    @pytest.mark.parametrize(
        "text",
        [
            "[]",
            " [ ] ",
            "[\n]\n",
            "[1, 23, 456, 7890]",
            "[-0.5e-3]",
            "[1.25 ,-0.5E+3,10e2 ]",
            "[0 ]",
        ],
    )
    def test_short_arrays_and_numbers_cut_by_the_window(self, tmp_path: Path, text: str) -> None:
        """A number cut by the window (`-0` of `-0.5e-3`) is taken only once its ',' or ']' is read."""
        path = StreamKit.write(tmp_path, text, zipped=False)
        for window in WINDOWS:
            assert StreamKit.streamed(path, window) == json.loads(text)

    @pytest.mark.parametrize("text", ['{"a": [1]}', '"[1, 2]"', "", "  ", "7"])
    def test_a_top_level_that_is_not_an_array_yields_nothing(
        self, tmp_path: Path, text: str
    ) -> None:
        path = StreamKit.write(tmp_path, text, zipped=False)
        assert StreamKit.streamed(path, 3) == []


class TestStreamedTextThatIsNotJson:
    @pytest.mark.parametrize(
        "text", ["[1,]", "[1 2]", "[1]x", "[1", '[{"a": ', "[,1]", "[1,,2]", '["a]', "[1]]"]
    )
    def test_it_is_refused(self, tmp_path: Path, text: str) -> None:
        with pytest.raises(ValueError):
            json.loads(text)
        path = StreamKit.write(tmp_path, text, zipped=False)
        for window in WINDOWS:
            with pytest.raises(ValueError):
                StreamKit.streamed(path, window)

    def test_a_gzip_stream_cut_short_is_refused(self, tmp_path: Path) -> None:
        path = StreamKit.write(tmp_path, json.dumps([{"name": "a"}] * 2_000), zipped=True)
        path.write_bytes(path.read_bytes()[:-40])
        with pytest.raises(ValueError):
            StreamKit.streamed(path, 64)


class TestTheStreamedBuild:
    def test_the_stream_keeps_what_parse_keeps(self, tmp_path: Path) -> None:
        """Records without a name, and elements that are not records, are left out alike."""
        values = [{"name": "a", "id": "1"}, {"id": "2"}, 3, {"name": ""}, {"name": "B", "id": "4"}]
        path = StreamKit.write(tmp_path, json.dumps(values), zipped=True)
        assert list(ShippedAdvisories._stream(path)) == ShippedAdvisories._parse(path)


# Item 74 cut 1: the release-built table (intel/advisories/shipped_table).
DIGEST = "ab" * 32


class TableKit:
    @staticmethod
    def records(n: int) -> list[dict[str, object]]:
        """Inert advisory-shaped records: names repeat so a name holds several, in file order."""
        return [
            {"name": f"Pkg-{i % (n // 3 + 1)}", "id": f"ADV-{i}", "versions": [f"1.0.{i}"]}
            for i in range(n)
        ]

    @staticmethod
    def table(tmp_path: Path, records: list[dict[str, object]], digest: str = DIGEST) -> Path:
        path = tmp_path / "advisories-npm.tbl"
        path.write_bytes(ShippedTable.build(records, digest))
        return path


class TestTheTableAnswersWhatTheRecordsSay:
    def test_every_name_returns_its_records_in_file_order(self, tmp_path: Path) -> None:
        records = TableKit.records(300)
        table = ShippedTable.open(TableKit.table(tmp_path, records), DIGEST)
        assert table is not None and table.count == 300
        expected: dict[str, list[dict[str, object]]] = {}
        for raw in records:
            expected.setdefault(str(raw["name"]).lower(), []).append(raw)
        assert sorted(table.names()) == sorted(expected)
        for name, rows in expected.items():
            assert list(table.get(name)) == rows

    def test_a_name_never_spans_two_blocks(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(shipped_table, "BLOCK_BYTES", 64)
        records = [{"name": "one", "id": f"A-{i}"} for i in range(50)] + [
            {"name": "two", "id": "B"}
        ]
        table = ShippedTable.open(TableKit.table(tmp_path, records), DIGEST)
        assert table is not None
        assert [r["id"] for r in table.get("one")] == [f"A-{i}" for i in range(50)]
        assert [r["id"] for r in table.get("two")] == ["B"]

    @pytest.mark.parametrize("name", ["", "0", "pkg-999", "zzzz", "pkg-1-extra"])
    def test_an_absent_name_is_empty(self, tmp_path: Path, name: str) -> None:
        table = ShippedTable.open(TableKit.table(tmp_path, TableKit.records(30)), DIGEST)
        assert table is not None and table.get(name) == ()

    def test_count_except_removes_exactly_the_named_records(self, tmp_path: Path) -> None:
        table = ShippedTable.open(TableKit.table(tmp_path, TableKit.records(30)), DIGEST)
        assert table is not None
        assert table.count_except(frozenset({"ADV-1", "ADV-2", "NOT-THERE"})) == 28


class TestATableThatIsNotThisFilesIsRefused:
    def test_another_files_digest(self, tmp_path: Path) -> None:
        assert ShippedTable.open(TableKit.table(tmp_path, TableKit.records(9)), "cd" * 32) is None

    def test_a_wrong_magic_or_a_cut_file(self, tmp_path: Path) -> None:
        path = TableKit.table(tmp_path, TableKit.records(9))
        data = path.read_bytes()
        path.write_bytes(b"XXXX" + data[4:])
        assert ShippedTable.open(path, DIGEST) is None
        path.write_bytes(data[:-5])
        assert ShippedTable.open(path, DIGEST) is None

    def test_every_shipped_table_is_its_data_files(self) -> None:
        # A data refresh without the release step would leave a stale table: refused at read time,
        # and caught here first.
        sources = sorted(DATA_DIR.glob("advisories-*.json.gz"))
        assert sources
        for source in sources:
            table = source.with_name(source.name.removesuffix(".json.gz") + ".tbl")
            assert ShippedTable.open(table, AdvisoryFiles.digest_of(source)) is not None, table.name


class TestOnlyThePackagesOwnTableIsRead:
    def test_a_table_beside_a_synced_copy_is_not_read(self, tmp_path: Path, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.shipped import ShippedAdvisories

        source = tmp_path / "advisories-npm.json.gz"
        import gzip

        source.write_bytes(gzip.compress(json.dumps(TableKit.records(9)).encode()))
        digest = AdvisoryFiles.digest_of(source)
        TableKit.table(tmp_path, TableKit.records(9), digest)
        opened: list[Path] = []
        real_open = ShippedTable.open
        monkeypatch.setattr(
            ShippedTable,
            "open",
            classmethod(lambda cls, path, d: opened.append(path) or real_open(path, d)),
        )
        monkeypatch.setattr(
            ShippedAdvisories, "_verified_file", staticmethod(lambda e: (source, digest))
        )
        ShippedAdvisories.reset_caches()
        try:
            ShippedAdvisories.records("npm")
        finally:
            ShippedAdvisories.reset_caches()
        assert opened == []


class TestAnEmptyPackageBuildsNoIndex:
    def test_no_sqlite_index_is_built(self, tmp_path: Path, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.advisory_index import AdvisoryIndex
        from cordon_scanner.intel.advisories.shipped import ShippedAdvisories

        def refuse(*args: object, **kwargs: object) -> bool:
            raise AssertionError("an advisory index was built for an empty package")

        monkeypatch.setattr(AdvisoryIndex, "_build", staticmethod(refuse))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = json.dumps({"name": "empty-probe", "version": "1.0.0"}).encode()
            info = tarfile.TarInfo("package/package.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "empty-probe-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        ShippedAdvisories.reset_caches()
        try:
            Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(target)
        finally:
            ShippedAdvisories.reset_caches()
