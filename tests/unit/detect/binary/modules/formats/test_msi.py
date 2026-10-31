"""The `msi` module (modules.formats.msi): unsigned packages, a signature stream that is not a
signature, and the bytes the package digest covers (the header with its class id and version zeroed,
then the streams in directory order without the signature streams)."""

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
    def test_the_digest_covers_the_header_and_the_streams_in_order(self) -> None:
        raw = FormatKit.cfb({"A": b"a" * 600, "\x05DigitalSignature": b"sig", "B": b"b" * 10})
        compound = Olecf.compound(raw)
        assert compound is not None
        listing = Olecf.listing(compound)
        got = Msi.digest("sha256", compound, listing)
        head = raw[:8] + bytes(20) + raw[28:512]
        assert got == hashlib.sha256(head + b"a" * 600 + b"b" * 10).digest()
        assert Msi.digest("no-such-hash", compound, listing) is None
