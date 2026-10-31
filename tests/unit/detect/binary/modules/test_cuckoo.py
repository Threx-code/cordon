"""The `cuckoo` module (modules.cuckoo) against the reference engine's answers.

Each case is a report and the rules it matches, recorded from YARA 4.5.8's own module
(`yara -x cuckoo=report.json`, cordon-yara-ref:2) on the same rules and report. The reports are
written here; they are a sandbox's records of a run, not samples. The one deliberate difference --
a non-text item where the reference reads text, which crashes it -- is pinned on its own.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.cuckoo import Cuckoo
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import Rules


class Probe:
    """The probe rules, one per function or quirk, and a run of them over one report."""

    RULES: ClassVar[dict[str, str]] = {
        "dns_new": "cuckoo.network.dns_lookup(/evil/)",
        "dns_noip": "cuckoo.network.dns_lookup(/noip/)",
        "dns_old": "cuckoo.network.dns_lookup(/old/)",
        "get": r"cuckoo.network.http_get(/a\.php/)",
        "post_lower": "cuckoo.network.http_post(/up/)",
        "req": "cuckoo.network.http_request(/up/)",
        "ua": "cuckoo.network.http_user_agent(/Mozilla/)",
        "host_abc": "cuckoo.network.host(/b/)",
        "host_empty_re": "cuckoo.network.host(/z*/)",
        "host_anchor": "cuckoo.network.host(/^9/)",
        "host_ab": "cuckoo.network.host(/ab/)",
        "host_z": "cuckoo.network.host(/zz/)",
        "tcp443": r"cuckoo.network.tcp(/9\.9/, 443)",
        "tcp80str": r"cuckoo.network.tcp(/8\.8/, 80)",
        "udp53": r"cuckoo.network.udp(/8\.8\.4/, 53)",
        "key": "cuckoo.registry.key_access(/Run/)",
        "file": "cuckoo.filesystem.file_access(/drop/)",
        "mutex": "cuckoo.sync.mutex(/M1/)",
        "nomatch_not": "not cuckoo.sync.mutex(/nothere/)",
        "is_undef": "not defined cuckoo.network.host(/zzz/)",
    }
    SOURCE: ClassVar[str] = 'import "cuckoo"\n' + "".join(
        f"rule {name} {{ condition: {cond} }}\n" for name, cond in RULES.items()
    )
    COMPILED: ClassVar[list[Rules]] = []

    @staticmethod
    def run(report: Any) -> set[str]:
        if not Probe.COMPILED:
            Probe.COMPILED.append(Rules.compile(Probe.SOURCE))
        raw = None if report is None else json.dumps(report).encode()
        given = None if raw is None else {"cuckoo": Cuckoo.module(raw)}
        return {m.rule for m in Probe.COMPILED[0].match(b"x\n", given=given)}


FULL: dict[str, Any] = {
    "network": {
        "domains": [
            {"ip": "1.2.3.4", "domain": "evil.example.com"},
            {"domain": "noip.example.com"},
        ],
        "dns": [{"ip": "5.6.7.8", "hostname": "old.example.com"}],
        "http": [
            {
                "uri": "http://evil.example.com/a.php",
                "method": "GET",
                "user-agent": "Mozilla/5.0 X",
            },
            {"uri": "http://p.example.com/up", "method": "post"},
        ],
        "hosts": ["9.9.9.9", "abc"],
        "tcp": [{"dst": "9.9.9.9", "dport": 443}, {"dst": "8.8.8.8", "dport": "80"}],
        "udp": [{"dst": "8.8.4.4", "dport": 53}],
    },
    "behavior": {
        "summary": {
            "keys": ["HKLM\\Software\\Run\\x"],
            "files": ["C:\\temp\\drop.exe"],
            "mutexes": ["Global\\M1"],
        }
    },
}
NOTHING = {"nomatch_not"}


class TestAsTheReferenceAnswers:
    @pytest.mark.parametrize(
        ("report", "want"),
        [
            # every function on a full report; `dns` is not read when `domains` is there, a
            # domain needs an `ip`, a method is any case, a port must be an integer, and a
            # regular expression matching the empty text counts
            (
                FULL,
                {"dns_new", "get", "post_lower", "req", "ua", "host_abc", "host_empty_re",
                 "host_anchor", "host_ab", "tcp443", "udp53", "key", "file", "mutex",
                 "nomatch_not"},
            ),
            (None, NOTHING),
            ({}, NOTHING),
            ({"network": {}}, NOTHING),
            ({"network": [1, 2]}, NOTHING),
            ({"network": {"http": {"uri": "x", "method": "get"}}}, NOTHING),
            ({"behavior": "x"}, NOTHING),
            ({"behavior": {"summary": []}}, NOTHING),
            ([1], NOTHING),
            ({"network": {"tcp": [{"dst": "9.9.9.9", "dport": 443.0}]}}, NOTHING),
            # a text item is read to its first NUL
            ({"network": {"hosts": ["ab\x00zz"]}}, {"host_ab", "host_abc", "host_empty_re", "nomatch_not"}),
            # the older format, where a report has no `domains`
            ({"network": {"dns": [{"ip": "5.6.7.8", "hostname": "old.example.com"}]}}, {"dns_old", "nomatch_not"}),
        ],
    )  # fmt: skip
    def test_the_rules_matched_are_the_references(self, report: Any, want: set[str]) -> None:
        assert Probe.run(report) == want

    @pytest.mark.parametrize(
        "raw",
        [b"not json", b'{"network": {"tcp": [{"dport": 18446744073709551615}]}}', b'"text"',
         b'{"a": NaN}', b'{"a": "\\ud800"}'],
    )  # fmt: skip
    def test_a_report_the_reference_refuses_is_refused(self, raw: bytes) -> None:
        with pytest.raises(ValueError, match="cuckoo report"):
            Cuckoo.module(raw)

    def test_the_values_fit_the_declaration(self) -> None:
        assert Data.conforms(Cuckoo.SCHEMA, Cuckoo.values(FULL)) == []


class TestWhereTheReferenceFails:
    @pytest.mark.parametrize(
        "report",
        [
            {"network": {"hosts": [7, "9.9.9.9"]}},
            {"behavior": {"summary": {"keys": [1], "files": [None], "mutexes": [{}]}}},
        ],
    )
    def test_an_item_that_is_not_text_is_skipped_where_the_reference_crashes(
        self, report: Any
    ) -> None:
        got = Probe.run(report)
        assert "nomatch_not" in got
        assert ("host_anchor" in got) == ("hosts" in report.get("network", {}))
