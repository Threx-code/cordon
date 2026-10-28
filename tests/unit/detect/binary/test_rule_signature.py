"""The Authenticode signature reader (rule_signature) against the reference engine's recorded values, plus
the ASN.1 primitives it is built on. ``values()`` returns schema-shaped data; recode() renders it the way
the reference reports ``pe.signatures`` (bytes as hex, a sequence as its slots in order, integers signed) so
the two compare leaf by leaf. The real-file and malformed-file differentials live in the review harness;
these pin the fixture's values and the decoder's contract. A ``decode_whole`` strictness check is included:
a malformation in declared structure fails the decode, a malformation inside an opaque value does not.
"""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.detect.binary import rule_signature as rs
from cordon_scanner.detect.binary.rule_signature import BadDer, Tlv
from cordon_scanner.detect.binary.rule_values import Call, Data, Record, Scalar, Seq
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
SIGNED = sorted(n for n, e in EXPECTED.items() if (e["modules"].get("pe") or {}).get("signatures"))


class Render:
    """Schema-shaped data rendered and flattened the way the reference reports ``pe.signatures``."""

    @staticmethod
    def recode(declared: Any, data: Any) -> Any:
        if data is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Scalar):
            if declared is Scalar.TEXT:
                return {"b": data.hex()}
            if declared is Scalar.INT:
                v = data & ((1 << 64) - 1)
                return v - (1 << 64) if v >> 63 else v
            return data
        if isinstance(declared, Record):
            out = {}
            for k, kind in declared.fields.items():
                if k in data and data[k] is not None:
                    rendered = Render.recode(kind, data[k])
                    if rendered is not None:
                        out[k] = rendered
            return out
        if isinstance(declared, Seq):
            return [Render.recode(declared.item, v) for _k, v in sorted(data.items())]
        return data

    @staticmethod
    def leaves(value: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(value, dict) and "b" not in value:
            for k, x in value.items():
                Render.leaves(x, f"{prefix}.{k}" if prefix else str(k), out)
        elif isinstance(value, list):
            for i, x in enumerate(value):
                Render.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(value)
        else:
            out[prefix] = value
        return out


class TestSignatureValues:
    """Every signature value the reference recorded for a signed fixture comes back byte-identical."""

    def test_values_match_the_reference(self) -> None:
        assert SIGNED, "expected at least one signed fixture"
        for name in SIGNED:
            data = (DIR / name).read_bytes()
            signatures, _is_signed = rs.Signatures.signature_values(data)
            got = Render.leaves(Render.recode(Seq(rs.SIGNATURE), signatures), "", {})
            want = Render.leaves(EXPECTED[name]["modules"]["pe"]["signatures"], "", {})
            assert {
                k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]
            } == {}
            assert sorted(set(got) - set(want)) == []

    def test_is_signed_matches(self) -> None:
        for name in SIGNED:
            _sigs, is_signed = rs.Signatures.signature_values((DIR / name).read_bytes())
            assert is_signed == EXPECTED[name]["modules"]["pe"].get("is_signed", 0)

    def test_conforms_to_the_declared_schema(self) -> None:
        for name in SIGNED:
            signatures, _ = rs.Signatures.signature_values((DIR / name).read_bytes())
            assert Data.conforms(Seq(rs.SIGNATURE), signatures) == []

    def test_a_non_pe_has_no_signatures(self) -> None:
        signatures, is_signed = rs.Signatures.signature_values(
            b"not an executable at all, no MZ header"
        )
        assert signatures == {}
        assert is_signed == 0


class TestAsn1Decoder:
    """The BER decoder, and the strict ``decode_whole`` the d2i-equivalent paths use."""

    @staticmethod
    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag, len(body)]) + body

    def test_decode_reads_a_sequence(self) -> None:
        inner = self.tlv(0x02, b"\x01") + self.tlv(0x02, b"\x02")  # two INTEGERs
        node = Tlv.decode(self.tlv(0x30, inner))
        assert node.is_tag(16) and node.constructed
        assert [c.whole_number() for c in node.row(2)] == [1, 2]

    def test_integer_rejects_non_minimal_padding(self) -> None:
        # 0x00 0x01 is a padded encoding of 1; OpenSSL's c2i refuses it
        try:
            Tlv.number_from(b"\x00\x01")
        except BadDer:
            pass
        else:
            raise AssertionError("expected BadDer on a padded integer")

    def test_strict_fails_a_truncated_declared_field(self) -> None:
        # a SEQUENCE whose inner element claims more length than is present
        bad = self.tlv(
            0x30, bytes([0x30, 0x05, 0x02, 0x01])
        )  # inner SEQUENCE says 5 bytes, 2 present
        Tlv.decode(bad)  # lazy decode of the outer is fine
        try:
            Tlv.decode_whole(bad)
        except BadDer:
            pass
        else:
            raise AssertionError("expected BadDer: declared structure is broken")

    def test_strict_keeps_garbage_inside_an_octet_string(self) -> None:
        # an OCTET STRING whose bytes are not valid DER is still accepted: d2i never looks inside it
        garbage_der = bytes([0x30, 0x7F, 0x02])  # a SEQUENCE claiming 127 bytes with 1 present
        node = Tlv.decode_whole(self.tlv(0x30, self.tlv(0x04, garbage_der)))
        assert node.row(1)[0].bytes_of() == garbage_der
