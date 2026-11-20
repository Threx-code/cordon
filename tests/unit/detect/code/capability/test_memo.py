"""The capability detector's pattern-tier hits kept per distinct whole file
(`detect/code/capability/memo`)."""

from __future__ import annotations

import dataclasses
from typing import Any

from cordon_scanner.detect.code.capability.memo import CapabilityMemo
from cordon_scanner.foundation.content import FileContent


class Matcher:
    """A stand-in for the detector: counts how often the pattern tier runs."""

    def __init__(self) -> None:
        self.runs = 0

    def match_capabilities(self, content: FileContent, candidates: Any, language: Any) -> list[Any]:
        self.runs += 1
        return [("hit", len(content.raw), language)]


class TestCapabilityMemo:
    RULES = (object(), object())
    RAW = b"import os\n" + b"x = 1\n" * 1000

    def test_the_same_file_and_rules_are_matched_once(self) -> None:
        matcher = Matcher()
        a = FileContent.from_bytes("a/one.py", self.RAW)
        b = FileContent.from_bytes("b/copy.py", self.RAW)
        first = CapabilityMemo.hits(matcher, a, self.RULES, "python")
        assert CapabilityMemo.hits(matcher, b, self.RULES, "python") == first
        assert matcher.runs == 1

    def test_other_rules_or_language_are_matched_again(self) -> None:
        matcher = Matcher()
        content = FileContent.from_bytes("a/two.py", self.RAW + b"# two\n")
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        CapabilityMemo.hits(matcher, content, (object(),), "python")
        CapabilityMemo.hits(matcher, content, self.RULES, "javascript")
        assert matcher.runs == 3

    def test_a_cut_short_file_is_matched_every_time(self) -> None:
        matcher = Matcher()
        content = dataclasses.replace(
            FileContent.from_bytes("a/three.py", self.RAW + b"# three\n"), truncated=True
        )
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        assert matcher.runs == 2


class TestDestinationHosts:
    """URL hosts a file names, kept as salted digests: never the name, only well-formed hosts, at most 32."""

    def test_hosts_and_domains_are_digests_never_names(self) -> None:
        from cordon_scanner.detect.code.capability.memo import DestinationHosts

        hosts, domains = DestinationHosts.of(
            "fetch('https://api.example.com/v1'); ws = 'wss://Push.Example.com:443/x'"
        )
        assert hosts == {
            DestinationHosts.digest("api.example.com"),
            DestinationHosts.digest("push.example.com"),
        }
        assert domains == {DestinationHosts.digest("example.com")}
        assert all(len(d) == 16 and "example" not in d for d in hosts | domains)

    def test_an_address_is_its_own_domain_and_junk_is_not_a_host(self) -> None:
        from cordon_scanner.detect.code.capability.memo import DestinationHosts

        hosts, domains = DestinationHosts.of(
            "http://10.0.0.5/a http://localhost/b https://-bad-.example/c https://a..b/d"
        )
        assert hosts == {DestinationHosts.digest("10.0.0.5")}
        assert domains == {DestinationHosts.digest("10.0.0.5")}

    def test_at_most_thirty_two_hosts_a_file(self) -> None:
        from cordon_scanner.detect.code.capability.memo import DestinationHosts

        text = " ".join(f"https://h{i}.example.org/" for i in range(100))
        assert len(DestinationHosts.of(text)[0]) == DestinationHosts.MAX
