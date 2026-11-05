"""The vt module's network functions (modules/reports/vt_net.py) against YARA-X 1.21.0's own test
assertions: every assertion in its typos, homoglyphs, bitsquatting and interleaved tests and its
squatting cases (data/rule_reference/yarax/vt-net-assertions-1.21.0.json, extracted from the
reference's source unchanged), and its in_range and parse_domain cases written out below."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.reports.vt_net import (
    DomainParts,
    PublicSuffix,
    Typos,
    VtNet,
)
from support import ROOT

ASSERTIONS: list[list[Any]] = json.loads(
    (ROOT / "tests/unit/data/rule_reference/yarax/vt-net-assertions-1.21.0.json").read_text(
        encoding="utf-8"
    )
)
FUNCTIONS = {
    "insertion": Typos.insertion,
    "omission": Typos.omission,
    "replacement": Typos.replacement,
    "vowel_swap": Typos.vowel_swap,
    "doubling": Typos.doubling,
    "swap": Typos.swap,
    "bitsquatting": Typos.bitsquatting,
    "is_homoglyph": Typos.homoglyph,
}


class TestReferenceAssertions:
    def test_every_assertion_was_read(self) -> None:
        assert len(ASSERTIONS) == 133

    @pytest.mark.parametrize(("name", "a", "b", "c", "want"), ASSERTIONS)
    def test_each_assertion_holds(
        self, name: str, a: str, b: str, c: str | None, want: bool
    ) -> None:
        if name == "squatting":
            got = VtNet.permutation_of(b.encode(), a.encode())
        elif name == "interleaved":
            got = Typos.interleaved(a, b, c or "-")
        else:
            got = FUNCTIONS[name](a, b)
        assert got is want, (name, a, b)


class TestInRange:
    @pytest.mark.parametrize(
        ("ip", "cidr", "want"),
        [
            ("192.168.1.100", "192.168.1.100/32", True),
            ("192.168.1.100", "192.168.1.1/17", True),
            ("192.168.1.100", "192.168.1.0/24", True),
            ("192.168.1.100", "192.168.1.0/32", False),
            ("192.168.1.100", "192.168.1.0/31", False),
            ("142.250.184.164", "142.250.184.164/20", True),
            ("142.250.184.164", "142.250.176.0/20", True),
            ("2001:db8::1", "2001:db8::1/32", True),
            ("2001:db8::1", "2001:db8::1/34", True),
            ("2001:0DB8:7654:0010:FEDC:0000:0000:3210", "2001:db8::1/34", False),
            ("2001:db8::1", "2001:db8::1/64", True),
            ("192.168.1.100", "2001:db8::1/32", False),
            ("192.168.1.100", "192.168.1.100", False),
            ("not an ip", "192.168.1.0/24", False),
        ],
    )
    def test_in_range(self, ip: str, cidr: str, want: bool) -> None:
        assert VtNet.in_range(ip.encode(), cidr.encode()) is want


class TestParseDomain:
    @pytest.mark.parametrize(
        ("name", "parts"),
        [
            ("www.google.com", DomainParts("www.google", "www", "google", "com")),
            ("gov.uk", DomainParts(None, None, None, "gov.uk")),
            ("www.gov.uk", DomainParts("www", "www", None, "gov.uk")),
            ("ftp.gov.uk", DomainParts("ftp", "ftp", None, "gov.uk")),
            ("www.ncbi.nlm.nih.gov", DomainParts("www.ncbi.nlm.nih", "www.ncbi.nlm", "nih", "gov")),
        ],
    )
    def test_the_reference_cases(self, name: str, parts: DomainParts) -> None:
        assert VtNet.parse_domain(name.encode()) == parts

    @pytest.mark.parametrize(
        ("name", "size"),
        [
            (b"example.com", 3),
            (b"example.com.", 4),
            (b"a.b.ck", 4),  # *.ck: any label under ck is a suffix
            (b"www.ck", 2),  # !www.ck: the exception ends the suffix at ck
            (b"x.unknowntld", 10),  # no rule: the last label alone
            (b"", None),
            (b"a..com", 3),
        ],
    )
    def test_the_suffix_rules(self, name: bytes, size: int | None) -> None:
        assert PublicSuffix.length(name) == size
