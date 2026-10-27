"""YARA's `pe`, `elf` and `dotnet` modules and the readers under them, as YARA 4.5.1 gives them.

The field-by-field differential against yara-python ran over every real executable in the corpus
(reviews/self-improving); these tests hold the rules it settled, so a change that breaks one is
caught here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.rule_lang import Rules
from cordon_scanner.detect.binary.rule_values import (
    Array,
    Dictionary,
    Function,
    Struct,
    TypedUndefined,
    Values,
)
from cordon_scanner.detect.binary.yara_authenticode import Asn1Time, AsnError, Ber, Name
from cordon_scanner.detect.binary.yara_dotnet import Dotnet
from cordon_scanner.detect.binary.yara_pe import Elf, Pe
from cordon_scanner.detect.binary.yara_tlsh import Tlsh
from support import ROOT


class TestAsn1Time:
    """OpenSSL 1.1's `ASN1_TIME_to_tm`, which the signature parser turns into seconds."""

    @staticmethod
    def utc(text: bytes) -> Ber:
        return Ber(0, False, 23, b"\x17" + bytes([len(text)]) + text, text, 0)

    @staticmethod
    def generalized(text: bytes) -> Ber:
        return Ber(0, False, 24, b"\x18" + bytes([len(text)]) + text, text, 0)

    def test_a_utc_time_and_its_century(self) -> None:
        assert Asn1Time.seconds(self.utc(b"200101000000Z")) == 1577836800
        assert Asn1Time.seconds(self.utc(b"500101000000Z")) == -631152000

    def test_seconds_may_be_left_out_and_an_offset_is_applied(self) -> None:
        assert Asn1Time.seconds(self.utc(b"2001010000Z")) == 1577836800
        assert Asn1Time.seconds(self.utc(b"200101010000+0100")) == 1577836800

    def test_fractional_seconds_only_in_generalized_time(self) -> None:
        assert Asn1Time.seconds(self.generalized(b"20200101000000.123Z")) == 1577836800
        assert Asn1Time.seconds(self.utc(b"200101000000.1Z")) is None

    def test_an_impossible_date_does_not_parse_and_reads_as_the_zeroed_time(self) -> None:
        bad = self.utc(b"200230000000Z")
        assert Asn1Time.seconds(bad) is None
        assert Asn1Time.or_zero(bad) == Asn1Time.ZERO == -2209075200

    def test_timegm_reaches_any_year(self) -> None:
        assert Asn1Time.timegm(1970, 1, 1, 0, 0, 0) == 0
        assert Asn1Time.timegm(1, 1, 1, 0, 0, 0) == -62135596800


class TestNames:
    @staticmethod
    def name(*entries: tuple[str, int, bytes]) -> Name:
        rdns = []
        for oid, tag, value in entries:
            arcs = [int(x) for x in oid.split(".")]
            body = bytes([arcs[0] * 40 + arcs[1], *arcs[2:]])
            atv = b"\x06" + bytes([len(body)]) + body + bytes([tag, len(value)]) + value
            atv = b"\x30" + bytes([len(atv)]) + atv
            rdns.append(b"\x31" + bytes([len(atv)]) + atv)
        raw = b"".join(rdns)
        return Name.parse(Ber.parse(b"\x30" + bytes([len(raw)]) + raw))

    def test_oneline_uses_short_names_and_escapes_bytes_outside_printable_ascii(self) -> None:
        name = self.name(("2.5.4.6", 19, b"US"), ("2.5.4.3", 12, b"caf\xc3\xa9"))
        assert name.oneline() == b"/C=US/CN=caf\\xC3\\xA9"

    def test_names_compare_folded_as_openssl_compares_them(self) -> None:
        a = self.name(("2.5.4.3", 19, b"  Example   CA "))
        b = self.name(("2.5.4.3", 12, b"example ca"))
        assert a.key == b.key

    def test_a_value_type_openssl_refuses_fails_the_name(self) -> None:
        with pytest.raises(AsnError):
            self.name(("2.5.4.3", 26, b"visible"))


class TestBer:
    def test_an_integer_with_a_padding_octet_is_refused(self) -> None:
        with pytest.raises(AsnError):
            Ber.integer_of(b"\x00\x01")
        assert Ber.integer_of(b"\x00\x80") == 128
        assert Ber.integer_of(b"\xff\x00") == -256

    def test_indefinite_lengths_are_read(self) -> None:
        node = Ber.parse(b"\x30\x80\x02\x01\x05\x00\x00")
        assert node.indefinite
        assert node.children()[0].integer() == 5


class TestTlsh:
    def test_short_input_has_no_hash(self) -> None:
        assert Tlsh.digest(b"x" * 49) == b""

    def test_the_length_code_is_the_first_bound_that_holds(self) -> None:
        assert Tlsh.length_code(1) == 0
        assert Tlsh.length_code(50) == 9
        assert Tlsh.length_code(57) == 9
        assert Tlsh.length_code(58) == 10

    def test_single_precision_ratio(self) -> None:
        assert Tlsh.ratio(1, 3) == 33
        assert Tlsh.ratio(2, 3) == 66


class TestIntegers:
    def test_module_integers_are_signed_64_bit(self) -> None:
        assert Values.int64((1 << 64) - 7744) == -7744
        assert Values.int64(5) == 5
        assert Values.int64(True) is True

    def test_not_a_pe_is_zero_not_undefined(self) -> None:
        assert Rules.compile('import "pe" rule r { condition: pe.is_pe == 0 }').match(b"plain text")
        assert Rules.compile(
            'import "dotnet" rule r { condition: not defined dotnet.is_dotnet }'
        ).match(b"x")

    def test_function_signatures_type_check_as_yara_declares_them(self) -> None:
        rules = Rules.compile(
            'import "pe" rule r { condition: pe.imphash() == "" or pe.imports(pe.IMPORT_ANY, "k.dll", "f") '
            'or pe.import_rva("k.dll", "f") == 0 or pe.exports_index(/x/) == 0 }'
        )
        assert not rules.match(b"not a pe")


class RealFiles:
    """The fixtures under `data/yara/modules` and yara-python's values for them."""

    DIR: ClassVar[Path] = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
    EXPECTED: ClassVar[dict[str, Any]] = json.loads(
        (DIR / "expected.json").read_text(encoding="utf-8")
    )
    MODULES: ClassVar[dict[str, Any]] = {
        "pe": Pe.module,
        "elf": Elf.module,
        "dotnet": Dotnet.module,
    }

    @staticmethod
    def plain(v: Any) -> Any:
        """A module tree as yara-python reports it: defined values only, bytes as hex, signed 64."""
        if isinstance(v, Struct):
            out = {
                k: RealFiles.plain(x)
                for k, x in v.fields.items()
                if not isinstance(x, (Function, TypedUndefined))
            }
            return {k: x for k, x in out.items() if x is not None}
        if isinstance(v, Array):
            return [RealFiles.plain(x) for x in v.values()]
        if isinstance(v, Dictionary):
            return {k.decode("latin-1"): RealFiles.plain(x) for k, x in v.items.items()}
        if isinstance(v, (TypedUndefined, Function)):
            return None
        if isinstance(v, bytes):
            return {"b": v.hex()}
        return Values.int64(v)

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            for k, x in v.items():
                RealFiles.leaves(x, f"{prefix}.{k}" if prefix else k, out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                RealFiles.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(v)
        else:
            out[prefix] = v
        return out


class TestRealFiles:
    @pytest.mark.parametrize("name", sorted(RealFiles.EXPECTED))
    @pytest.mark.parametrize("module", ["pe", "elf", "dotnet"])
    def test_every_value_is_the_one_yara_gives(self, name: str, module: str) -> None:
        data = (RealFiles.DIR / name).read_bytes()
        expected = RealFiles.EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = RealFiles.leaves(expected["modules"][module], "", {})
        got = RealFiles.leaves(RealFiles.plain(RealFiles.MODULES[module](data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", sorted(RealFiles.EXPECTED))
    def test_every_function_returns_what_yara_returns(self, name: str) -> None:
        data = (RealFiles.DIR / name).read_bytes()
        for call, value in RealFiles.EXPECTED[name]["functions"].items():
            literal = value if value.lstrip("-").isdigit() else '"' + value + '"'
            rule = f'import "pe"\nimport "elf"\nrule r {{ condition: {call} == {literal} }}'
            assert Rules.compile(rule).match(data), call
