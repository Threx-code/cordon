"""The `msi` module (modules.formats.msi): unsigned packages, a signature stream that is not a
signature, and the content the package digest covers (the tree from the root, each storage's children
in their names' UTF-16 byte order, the streams but the signature's, each storage's class id after its
children; the metadata's digest first where the package signs its metadata). The signed packages
replayed against both references are in test_signed_fixtures."""

from __future__ import annotations

import hashlib

from cordon_scanner.detect.binary.modules.formats.msi import Msi
from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from cordon_scanner.detect.binary.modules.values import Data
from kits.formatkit import FormatKit


class TestUnsigned:
    def test_a_package_without_a_signature_stream(self) -> None:
        d = Msi.data(FormatKit.cfb({"Table": b"t" * 600}))
        assert d == {"is_signed": False, "signatures": {}}
        assert Data.conforms(Msi.SCHEMA, d) == []

    def test_a_signature_stream_that_holds_no_signature(self) -> None:
        d = Msi.data(
            FormatKit.cfb({"\x05DigitalSignature": b"\x30\x03\x02\x01\x00", "Table": b"t"})
        )
        assert d["is_signed"] is False and d["signatures"] == {}

    def test_not_a_compound_file(self) -> None:
        assert Msi.data(b"PK\x03\x04 a zip") == {"is_signed": False, "signatures": {}}


class TestDigest:
    @staticmethod
    def digest(streams: dict[str, bytes]) -> bytes | None:
        compound = Olecf.compound(FormatKit.cfb(streams))
        assert compound is not None
        return Msi.digest("sha256", compound, Olecf.listing(compound))

    def test_the_streams_in_name_order_then_the_root_class_id(self) -> None:
        got = self.digest({"B": b"b" * 600, "\x05DigitalSignature": b"sig", "A": b"a" * 10})
        assert got == hashlib.sha256(b"a" * 10 + b"b" * 600 + bytes(16)).digest()

    def test_a_storage_is_walked_in_place_and_its_class_id_follows_its_children(self) -> None:
        got = self.digest({"Z": b"z", "S/two": b"2" * 5000, "S/one": b"1"})
        storage_then_root = b"1" + b"2" * 5000 + bytes(16) + b"z" + bytes(16)
        assert got == hashlib.sha256(storage_then_root).digest()  # "S" sorts before "Z"

    def test_a_name_that_begins_another_comes_first(self) -> None:
        got = self.digest({"AB": b"x", "A": b"y"})
        assert got == hashlib.sha256(b"y" + b"x" + bytes(16)).digest()

    def test_signed_metadata_is_hashed_first(self) -> None:
        streams = {"A": b"a" * 10, "\x05MsiDigitalSignatureEx": b"e" * 32}
        compound = Olecf.compound(FormatKit.cfb(streams))
        assert compound is not None
        records = compound.records
        root, a = (
            records[0],
            next(r for r in records if r[:4] == "A".encode("utf-16-le") + b"\x00\x00"),
        )
        metadata = hashlib.sha256(
            root[80:96]
            + root[96:100]
            + "A".encode("utf-16-le")
            + a[120:124]
            + a[96:100]
            + a[100:116]
        ).digest()
        content = b"a" * 10 + root[80:96]
        assert (
            Msi.digest("sha256", compound, Olecf.listing(compound))
            == hashlib.sha256(metadata + content).digest()
        )

    def test_an_unknown_hash_has_no_digest(self) -> None:
        compound = Olecf.compound(FormatKit.cfb({"A": b"a"}))
        assert compound is not None
        assert Msi.digest("no-such-hash", compound, Olecf.listing(compound)) is None
