"""The Authenticode signature reader (modules.signature) against the reference engine's recorded values, plus
the ASN.1 primitives it is built on. ``values()`` returns schema-shaped data; recode() renders it the way
the reference reports ``pe.signatures`` (bytes as hex, a sequence as its slots in order, integers signed) so
the two compare leaf by leaf. The real-file and malformed-file differentials live in the review harness;
these pin the fixture's values and the structured parse's opacity contract: a malformation in declared
structure fails the parse, one inside an opaque value (an OCTET STRING, or a CMS non-certificate
CertificateChoices) does not.
"""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.detect.binary.modules import signature as rs
from cordon_scanner.detect.binary.modules.der import BadDer, Clock, Tlv
from cordon_scanner.detect.binary.modules.values import Call, Data, Record, Scalar, Seq
from cordon_scanner.detect.binary.modules.x509 import X500
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
    """The BER decoder the structured parse reads through."""

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


class TestCountersignCertSetOpacity:
    """The parse is the template: a Microsoft timestamp's certificate set may hold a non-certificate
    CertificateChoices (a v1AttrCert [1]), which CMS types as one opaque SEQUENCE and never descends. A
    scatter inside such an element must not fail the countersignature -- it still verifies with its full
    chain and digest, the signed content being untouched -- while a malformed element's own TLV header, or a
    damaged plain certificate (declared structure, which is descended), is refused. cpython-wmi.pyd carries a
    real, verifying Microsoft timestamp; we append elements to its countersignature's certificate set and
    refix the enclosing DER lengths, so the signature over the untouched signed content still holds.

    The named difference (modules.signature): the reference empties such a countersignature; this
    reader reports it verified, since its signature, imprint and digest all check. It is the only
    difference left on the 14,292-file malformed set: 43 values, on one file."""

    @staticmethod
    def _der_len(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    @staticmethod
    def _reseal(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + TestCountersignCertSetOpacity._der_len(len(body)) + body

    def _timestamp(self) -> tuple[Tlv, bytes]:
        """The real Microsoft-timestamp countersignature value, and the parent signature it stamps."""
        data = (DIR / "cpython-wmi.pyd").read_bytes()
        at = int.from_bytes(data[0x3C:0x40], "little")
        is64 = int.from_bytes(data[at + 0x18 : at + 0x1A], "little") == 0x20B
        table = at + (16 if is64 else 0) + 0x98
        addr = int.from_bytes(data[table : table + 4], "little")
        length = int.from_bytes(data[addr : addr + 4], "little")
        _, signed = rs.Pkcs7.parse(data[addr + 8 : addr + length])
        assert signed is not None
        signer = signed.signers[0]
        value = rs.Signer.values_of(signer.unsigned_attrs, rs.Signatures.MS_TIMESTAMP)
        assert value is not None
        return value[0], signer.signature

    def _with_extra(self, value: Tlv, extra: bytes) -> Tlv:
        """``value`` (a ContentInfo) with ``extra`` appended to its SignedData certificate set, the enclosing
        DER lengths refixed."""
        oid, content = value.row(2)
        (signed,) = content.unpack()
        parts = signed.unpack()
        index = next(i for i, p in enumerate(parts) if p.is_context(0) and p.constructed)
        spans = [p.span for p in parts]
        spans[index] = self._reseal(parts[index].span[0], parts[index].body + extra)
        new_signed = self._reseal(signed.span[0], b"".join(spans))
        new_content = self._reseal(content.span[0], new_signed)
        return Tlv.decode(self._reseal(value.span[0], oid.span + new_content))

    def test_the_real_timestamp_verifies(self) -> None:
        value, parent = self._timestamp()
        counter = rs.Countersign.from_microsoft(value, parent, 0)
        assert counter.verified
        assert len(counter.chain or []) == 2
        assert counter.digest_alg == "sha256"

    def test_a_scatter_inside_an_opaque_choice_still_verifies(self) -> None:
        # a well-formed v1AttrCert [1] whose interior is a truncated SEQUENCE: kept opaque, so untouched
        value, parent = self._timestamp()
        counter = rs.Countersign.from_microsoft(
            self._with_extra(value, bytes([0xA1, 0x03, 0x30, 0x01, 0x02])), parent, 0
        )
        assert counter.verified
        assert len(counter.chain or []) == 2
        assert counter.digest_alg == "sha256"

    def test_a_choice_whose_own_tlv_overruns_is_refused(self) -> None:
        # the element must still be one well-formed TLV: a [1] whose length runs past the set is refused
        value, parent = self._timestamp()
        counter = rs.Countersign.from_microsoft(
            self._with_extra(value, bytes([0xA1, 0x7F, 0x30, 0x01, 0x02])), parent, 0
        )
        assert not counter.verified
        assert not counter.chain
        assert counter.digest_alg is None

    def test_a_damaged_plain_certificate_is_refused(self) -> None:
        # a malformed plain certificate (a SEQUENCE that is not a certificate) is declared structure: it is
        # descended, fails the whole parse, and the countersignature comes out empty
        value, parent = self._timestamp()
        counter = rs.Countersign.from_microsoft(
            self._with_extra(value, bytes([0x30, 0x01, 0x02])), parent, 0
        )
        assert not counter.verified
        assert not counter.chain
        assert counter.digest_alg is None


class TestClock:
    """ASN.1 time to seconds since the epoch, matching OpenSSL's ASN1_TIME_to_tm then timegm."""

    @staticmethod
    def utc(text: bytes) -> Tlv:
        return Tlv(0, False, 23, b"\x17" + bytes([len(text)]) + text, text)

    @staticmethod
    def generalized(text: bytes) -> Tlv:
        return Tlv(0, False, 24, b"\x18" + bytes([len(text)]) + text, text)

    def test_utc_time_and_its_century(self) -> None:
        assert Clock.seconds(self.utc(b"200101000000Z")) == 1577836800
        assert Clock.seconds(self.utc(b"500101000000Z")) == -631152000

    def test_offset_and_omitted_seconds(self) -> None:
        assert Clock.seconds(self.utc(b"2001010000Z")) == 1577836800
        assert Clock.seconds(self.utc(b"200101010000+0100")) == 1577836800

    def test_fractional_seconds_only_in_generalized_time(self) -> None:
        assert Clock.seconds(self.generalized(b"20200101000000.123Z")) == 1577836800
        assert Clock.seconds(self.utc(b"200101000000.1Z")) is None

    def test_an_impossible_date_reads_as_the_fallback(self) -> None:
        bad = self.utc(b"200230000000Z")
        assert Clock.seconds(bad) is None
        assert Clock.at_or_fallback(bad) == Clock.FALLBACK == -2209075200

    def test_timegm_reaches_any_year(self) -> None:
        assert Clock.timegm(1970, 1, 1, 0, 0, 0) == 0
        assert Clock.timegm(1, 1, 1, 0, 0, 0) == -62135596800


class TestX500Names:
    """X.509 names: the one-line form and the folded comparison key, as OpenSSL builds them."""

    @staticmethod
    def name(*entries: tuple[str, int, bytes]) -> X500:
        rdns = []
        for oid, tag, value in entries:
            arcs = [int(x) for x in oid.split(".")]
            body = bytes([arcs[0] * 40 + arcs[1], *arcs[2:]])
            atv = b"\x06" + bytes([len(body)]) + body + bytes([tag, len(value)]) + value
            atv = b"\x30" + bytes([len(atv)]) + atv
            rdns.append(b"\x31" + bytes([len(atv)]) + atv)
        raw = b"".join(rdns)
        return X500.parse(Tlv.decode(b"\x30" + bytes([len(raw)]) + raw))

    def test_oneline_short_names_and_escapes(self) -> None:
        n = self.name(("2.5.4.6", 19, b"US"), ("2.5.4.3", 12, b"caf\xc3\xa9"))
        assert n.one_line() == b"/C=US/CN=caf\\xC3\\xA9"

    def test_names_fold_as_openssl_compares_them(self) -> None:
        spaced = self.name(("2.5.4.3", 19, b"  Example   CA "))
        plain = self.name(("2.5.4.3", 12, b"example ca"))
        assert spaced.key == plain.key

    def test_a_refused_value_type_fails_the_name(self) -> None:
        try:
            self.name(("2.5.4.3", 26, b"visible"))
        except BadDer:
            pass
        else:
            raise AssertionError("expected BadDer on a value type OpenSSL refuses")


class TestMoreAsn1:
    def test_integer_signed_values(self) -> None:
        assert Tlv.number_from(b"\x00\x80") == 128
        assert Tlv.number_from(b"\xff\x00") == -256

    def test_indefinite_length_is_read(self) -> None:
        node = Tlv.decode(b"\x30\x80\x02\x01\x05\x00\x00")
        assert node.indefinite
        assert node.unpack()[0].whole_number() == 5
