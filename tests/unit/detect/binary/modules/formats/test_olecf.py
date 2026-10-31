"""The `olecf` module (modules.formats.olecf) on compound files built by FormatKit: the directory
listed in order by bare name with kinds and sizes, the leading control character removed, the replace
rule for repeated names, a version 4 file's 4,096-byte sectors, and a file that is not a compound file."""

from __future__ import annotations

from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from cordon_scanner.detect.binary.modules.values import Data
from kits.formatkit import FormatKit


class TestListing:
    def test_the_directory_in_order(self) -> None:
        raw = FormatKit.cfb({"VBA/dir": b"d" * 10, "VBA/Module1": b"m" * 700})
        d = Olecf.data(raw)
        assert d["is_olecf"] is True
        assert [(s["name"], s["type"], s["size"]) for s in d["streams"].values()] == [
            (b"Root Entry", 5, 768), (b"VBA", 1, 0), (b"dir", 2, 10), (b"Module1", 2, 700),
        ]  # fmt: skip
        assert d["StreamType"] == {"UNKNOWN": 0, "STORAGE": 1, "STREAM": 2, "ROOT": 5}
        assert Data.conforms(Olecf.SCHEMA, d) == []

    def test_a_version_4_file_reads_as_its_version_3_twin(self) -> None:
        streams = {"VBA/dir": b"d" * 10, "Big": bytes(range(256)) * 40, "Small": b"s" * 100}
        three, four = FormatKit.cfb(streams), FormatKit.cfb(streams, sector=4096)
        assert four[26] == 4 and len(four) % 4096 == 0
        assert Olecf.data(four)["streams"] == Olecf.data(three)["streams"]
        compound = Olecf.compound(four)
        assert compound is not None
        assert {n: Olecf.stream(compound, e) for n, e in Olecf.listing(compound)}["Big"] == streams[
            "Big"
        ]

    def test_a_leading_control_character_is_dropped_from_a_name(self) -> None:
        raw = FormatKit.cfb({"\x05Summary": b"s", "Table": b"t" * 3})
        names = [(s["name"], s["size"]) for s in Olecf.data(raw)["streams"].values()]
        assert names == [
            (b"Root Entry", 128),
            (b"Summary", 1),
            (b"Table", 3),
        ]  # the root owns the mini stream

    def test_not_a_compound_file(self) -> None:
        d = Olecf.data(b"MZ not an ole file" * 40)
        assert d["is_olecf"] is False and d["streams"] == {}
        assert Olecf.data(b"")["is_olecf"] is False
        assert Data.conforms(Olecf.SCHEMA, d) == []

    def test_a_repeated_name_keeps_the_stream_in_the_first_position(self) -> None:
        raw = FormatKit.cfb({"A/x": b"1", "x": b"22"})
        names = [(s["name"], s["type"], s["size"]) for s in Olecf.data(raw)["streams"].values()]
        assert names == [(b"Root Entry", 5, 128), (b"A", 1, 0), (b"x", 2, 2)]

    def test_the_shared_helpers(self) -> None:
        raw = FormatKit.cfb({"VBA/dir": b"d" * 10})
        compound = Olecf.compound(raw)
        assert compound is not None
        listing = dict(Olecf.listing(compound))
        assert Olecf.stream(compound, listing["dir"]) == b"d" * 10
        assert Olecf.stream(compound, listing["VBA"]) is None
