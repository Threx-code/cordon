"""A Go module's record in the checksum database (`intel/provenance/gosumdb`), verified as a transparency-log client does.

The lookup answer and the seven tiles are the real ones for github.com/pkg/errors v0.9.1 (`gosumdb/`, fetched from
sum.golang.org on 2026-11-26), so the signature, the Merkle arithmetic and the audit path are the real ones. What is
tested is each way they fail, the tile paths, the tree arithmetic on trees of every shape, and what each failure is called."""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
from typing import Any

import pytest

from cordon_scanner.intel.provenance.gosumdb import GoSumdb, SumdbError, SumdbNote, SumdbTiles
from cordon_scanner.intel.provenance.transparency import Merkle
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "gosumdb"
MODULE, VERSION = "github.com/pkg/errors", "v0.9.1"
H1 = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4="


class Capture:
    """The recorded answer and tiles, served as the database serves them."""

    def __init__(self) -> None:
        recorded: dict[str, Any] = json.loads(
            (DATA / "pkg_errors_v0.9.1.json").read_text(encoding="utf-8")
        )
        self.answer = base64.b64decode(recorded["lookup"])
        self.tiles = {path: base64.b64decode(data) for path, data in recorded["tiles"].items()}

    def read(self, path: str) -> bytes:
        return self.tiles[path]

    def check(self, integrity: str | None = H1, answer: bytes | None = None) -> Any:
        return GoSumdb.verify(
            MODULE, VERSION, integrity, answer if answer is not None else self.answer, self.read
        )


class TestTheRealRecord:
    def test_a_record_in_the_signed_tree_with_the_hash_go_sum_pins_is_verified(self) -> None:
        found = Capture().check()
        assert found.outcome == "verified" and H1 in found.detail

    def test_a_lock_that_pins_no_h1_still_has_its_record_verified(self) -> None:
        assert Capture().check(None).outcome == "verified"
        assert Capture().check("zh:abcdef").outcome == "verified"

    def test_a_hash_go_sum_pins_that_the_database_never_recorded_is_invalid(self) -> None:
        found = Capture().check("h1:" + base64.b64encode(b"\x01" * 32).decode())
        assert found.outcome == "invalid" and "go.sum pins" in found.detail

    def test_the_tree_head_is_signed_by_the_databases_key(self) -> None:
        capture = Capture()
        note = SumdbNote.parse(capture.answer.decode().partition("\n\n")[2])
        assert note.size == 72258619 and len(note.root) == 32

    def test_another_module_named_by_the_record_is_not_this_one(self) -> None:
        found = GoSumdb.verify(
            "github.com/other/errors", VERSION, None, Capture().answer, Capture().read
        )
        assert found.outcome == "invalid" and "does not name" in found.detail

    def test_the_fixture_needs_seven_tiles_and_asks_for_no_others(self) -> None:
        asked: list[str] = []
        capture = Capture()

        def read(path: str) -> bytes:
            asked.append(path)
            return capture.read(path)

        assert GoSumdb.verify(MODULE, VERSION, H1, capture.answer, read).outcome == "verified"
        assert sorted(set(asked)) == sorted(capture.tiles) and len(asked) == len(set(asked)) == 7


class TestWhatTheDatabaseCannotBeTrustedFor:
    @staticmethod
    def altered(replace: tuple[bytes, bytes]) -> bytes:
        answer = Capture().answer
        assert replace[0] in answer
        return answer.replace(*replace, 1)

    def test_a_record_with_another_hash_is_not_in_the_tree(self) -> None:
        answer = self.altered((H1.encode(), b"h1:" + base64.b64encode(b"\x02" * 32)))
        found = Capture().check(None, answer)
        assert found.outcome == "invalid" and "audit path" in found.detail

    def test_a_signature_that_is_not_the_databases_is_refused(self) -> None:
        answer = Capture().answer.decode()
        line = answer.splitlines()[-1]
        raw = bytearray(base64.b64decode(line.rsplit(" ", 1)[1]))
        raw[10] ^= 1
        tampered = answer.replace(
            line, line.rsplit(" ", 1)[0] + " " + base64.b64encode(bytes(raw)).decode()
        )
        found = Capture().check(None, tampered.encode())
        assert found.outcome == "invalid" and "signature" in found.detail

    def test_a_tree_head_that_was_changed_after_it_was_signed_is_refused(self) -> None:
        answer = Capture().answer.decode().replace("72258619", "72258620")
        assert Capture().check(None, answer.encode()).outcome == "invalid"

    def test_an_answer_with_no_tree_head_or_no_record_is_invalid(self) -> None:
        assert Capture().check(None, b"706716\nonly a record\n").outcome == "invalid"
        assert Capture().check(None, b"\n\ngo.sum database tree\n1\n").outcome == "invalid"
        assert Capture().check(None, b"").outcome == "invalid"

    def test_a_record_id_past_the_signed_size_is_refused(self) -> None:
        answer = self.altered((b"706716\n", b"72258619\n"))
        found = Capture().check(None, answer)
        assert found.outcome == "invalid" and "does not hold" in found.detail

    def test_a_record_id_that_is_another_leaf_does_not_reach_the_root(self) -> None:
        answer = self.altered((b"706716\n", b"706717\n"))
        assert Capture().check(None, answer).outcome == "invalid"

    def test_a_tile_with_a_changed_byte_does_not_reach_the_signed_root(self) -> None:
        capture = Capture()
        path = sorted(capture.tiles)[0]
        data = bytearray(capture.tiles[path])
        data[0] ^= 1
        capture.tiles[path] = bytes(data)
        assert capture.check().outcome == "invalid"

    def test_a_tile_of_the_wrong_length_is_refused(self) -> None:
        capture = Capture()
        path = sorted(capture.tiles)[0]
        capture.tiles[path] = capture.tiles[path][:-1]
        assert capture.check().outcome == "invalid"

    def test_a_proof_that_asks_for_more_tiles_than_any_real_one_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("cordon_scanner.intel.provenance.gosumdb.MAX_TILES", 3)
        assert Capture().check().outcome == "invalid"


class TestAsking:
    def test_a_module_the_database_has_no_record_of_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(GoSumdb, "get", staticmethod(lambda url, limit: None))
        assert GoSumdb.check("example.com/private", "v1.0.0", None).outcome == "absent"

    def test_a_database_that_cannot_be_reached_is_unverifiable_not_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(url: str, limit: int) -> bytes:
            raise urllib.error.URLError("unreachable")

        monkeypatch.setattr(GoSumdb, "get", staticmethod(refuse))
        assert GoSumdb.check(MODULE, VERSION, H1).outcome == "unverifiable"

    def test_a_version_recorded_without_its_v_is_asked_with_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []
        monkeypatch.setattr(GoSumdb, "get", staticmethod(lambda url, limit: asked.append(url)))
        GoSumdb.check(MODULE, "0.9.1", None)
        assert asked == ["https://sum.golang.org/lookup/github.com/pkg/errors@v0.9.1"]

    def test_upper_case_is_escaped_in_the_address(self) -> None:
        assert (
            GoSumdb.lookup_url("github.com/Azure/go", "v1.0.0-RC1")
            == "https://sum.golang.org/lookup/github.com/!azure/go@v1.0.0-!r!c1"
        )

    def test_the_real_check_end_to_end_with_the_served_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = Capture()

        def get(url: str, limit: int) -> bytes:
            return (
                capture.answer
                if "/lookup/" in url
                else capture.read(url.removeprefix("https://sum.golang.org/"))
            )

        monkeypatch.setattr(GoSumdb, "get", staticmethod(get))
        assert GoSumdb.check(MODULE, VERSION, H1).outcome == "verified"


class TestTheTreeArithmetic:
    """The same code on trees of every shape, against the textbook definition of the Merkle tree hash."""

    @staticmethod
    def leaves(count: int) -> list[bytes]:
        return [Merkle.leaf(f"record {i}\n".encode()) for i in range(count)]

    @classmethod
    def textbook(cls, hashes: list[bytes]) -> bytes:
        """RFC 9162 2.1.1, written out."""
        if len(hashes) == 1:
            return hashes[0]
        k = 1 << ((len(hashes) - 1).bit_length() - 1)
        return Merkle.node(cls.textbook(hashes[:k]), cls.textbook(hashes[k:]))

    @classmethod
    def tiles(cls, hashes: list[bytes]) -> dict[str, bytes]:
        """Every tile of a tree whose leaf hashes are `hashes`, as the database lays them out."""
        out: dict[str, bytes] = {}
        level, layer = 0, hashes
        while layer:
            for n in range(0, len(layer), 256):
                block = layer[n : n + 256]
                suffix = "" if len(block) == 256 else f".p/{len(block)}"
                out[f"tile/8/{level}/{SumdbTiles.number(n // 256)}{suffix}"] = b"".join(block)
            # the hashes 8 levels up: the root of each full block of 256
            layer = [
                cls.textbook(layer[i : i + 256])
                for i in range(0, len(layer) - len(layer) % 256, 256)
            ]
            level += 1
        return out

    @pytest.mark.parametrize("size", [1, 2, 3, 7, 8, 11, 255, 256, 257, 300, 513, 700])
    def test_the_root_from_the_tiles_is_the_textbook_root(self, size: int) -> None:
        hashes = self.leaves(size)
        tiles = self.tiles(hashes)
        assert SumdbTiles(size, tiles.__getitem__).subtree(0, size) == self.textbook(hashes)

    @pytest.mark.parametrize("size", [1, 2, 3, 11, 256, 257, 300, 700])
    def test_every_leaf_proves_into_the_root_with_its_audit_path(self, size: int) -> None:
        hashes = self.leaves(size)
        tiles = SumdbTiles(size, self.tiles(hashes).__getitem__)
        root = self.textbook(hashes)
        for index in range(size):
            assert Merkle.root_from_proof(index, size, hashes[index], tiles.path(index)) == root

    def test_a_leaf_that_is_not_the_one_at_its_index_does_not_reach_the_root(self) -> None:
        hashes = self.leaves(11)
        tiles = SumdbTiles(11, self.tiles(hashes).__getitem__)
        assert Merkle.root_from_proof(4, 11, hashes[5], tiles.path(4)) != self.textbook(hashes)

    @pytest.mark.parametrize(
        ("number", "text"),
        [
            (0, "000"),
            (5, "005"),
            (999, "999"),
            (1000, "x001/000"),
            (1234067, "x001/x234/067"),
            (12345678, "x012/x345/678"),
        ],
    )
    def test_a_tile_number_is_written_in_groups_of_three_digits(
        self, number: int, text: str
    ) -> None:
        assert SumdbTiles.number(number) == text

    def test_a_partial_tile_is_named_with_its_width(self) -> None:
        asked: list[str] = []

        def read(path: str) -> bytes:
            asked.append(path)
            return b"\x00" * 32 * 11

        SumdbTiles(11, read).stored(0, 3)
        assert asked == ["tile/8/0/000.p/11"]

    def test_a_hash_the_tree_does_not_hold_is_refused(self) -> None:
        with pytest.raises(SumdbError):
            SumdbTiles(11, lambda path: b"").stored(0, 11)
        with pytest.raises(SumdbError):
            SumdbTiles(11, lambda path: b"\x00" * 32 * 11).stored(4, 0)

    def test_the_key_hint_is_the_one_go_prints(self) -> None:
        from cordon_scanner.intel.provenance.gosumdb import SumdbKey

        assert SumdbKey.hint().hex() == "033de0ae" and len(SumdbKey.raw()) == 32
        assert hashlib.sha256(b"x").digest()  # the hash is the standard library's
