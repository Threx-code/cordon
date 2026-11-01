"""detect.binary.rule_engine.anchoring.anchor_index: a common anchor's places come from the
automaton's one pass, kept packed, so neither the Python loop (`Places.occurrences`) nor
`bytes.count` reads the file for it again; the file's places budget is spent only when they are
read, exactly as the loop spends it; past `KEEP_MOST` the file reads them the old way. Native only:
the Python reading has no pass to keep from (review 6y, the one-pass lever)."""

from __future__ import annotations

import sys

import pytest

from cordon_scanner.detect.binary.rule_engine.anchoring.anchor_index import AnchorIndex
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places
from cordon_scanner.detect.binary.rule_engine.lang import Rules

pytestmark = pytest.mark.skipif(not Automaton.NATIVE, reason="the one pass is the native one")


class Probe:
    """A rule whose hex anchor occurs thousands of times, among enough other strings that the
    anchor automaton is the native one, as in any real rule set."""

    DATA = (b"xyz MZ\x90\x00 abcd " * 3000) + b"MZ\x90\x00\x03\x00 needle-here"
    FILLER = "\n".join(
        f"rule f{i} {{ strings: $a = {{ {i // 256:02X} {i % 256:02X} EE {i % 251:02X} 7A }} "
        "condition: $a }"
        for i in range(400)
    )
    RULE = "rule r { strings: $a = { 4D 5A 90 00 [1-2] 00 } condition: $a }"

    @staticmethod
    def rules() -> Rules:
        return Rules.compile(Probe.RULE + "\n" + Probe.FILLER)

    @staticmethod
    def c_calls(run) -> dict[str, int]:
        calls = {"bytes.count": 0, "bytes.find": 0}

        def profile(frame, event, arg) -> None:
            name = getattr(arg, "__qualname__", "")
            if event == "c_call" and name in calls:
                calls[name] += 1

        sys.setprofile(profile)
        try:
            run()
        finally:
            sys.setprofile(None)
        return calls


class TestKeptPositions:
    def test_a_common_anchor_is_not_read_again(self) -> None:
        rules = Probe.rules()
        found: list[list[str]] = []
        calls = Probe.c_calls(lambda: found.append([m.rule for m in rules.match(Probe.DATA)]))
        assert found == [["r"]]
        # before: one bytes.count for the count, and a bytes.find for each of ~3,000 places
        assert calls == {"bytes.count": 0, "bytes.find": 0}

    def test_the_answer_is_the_loop_s(self, monkeypatch) -> None:
        rules = Probe.rules()
        kept = sorted((m.rule, sorted(m.strings)) for m in rules.match(Probe.DATA))
        monkeypatch.setattr(AnchorIndex, "KEEP_MOST", 0)  # nothing kept: the loop reads it
        looped = sorted((m.rule, sorted(m.strings)) for m in Probe.rules().match(Probe.DATA))
        assert kept == looped

    def test_past_what_a_file_keeps_it_reads_them_as_before(self, monkeypatch) -> None:
        monkeypatch.setattr(AnchorIndex, "KEEP_MOST", 100)  # fewer than the anchor's places
        rules = Probe.rules()
        calls = Probe.c_calls(lambda: rules.match(Probe.DATA))
        assert calls["bytes.find"] > 1000  # the loop, as before: nothing held past the bound

    def test_the_budget_refuses_the_file_as_the_loop_did(self, monkeypatch) -> None:
        from cordon_scanner.detect.binary.rule_engine.lang import RuleError

        monkeypatch.setattr(Places, "MOST", 500)  # fewer than the anchor's ~3,000 places
        outcomes = []
        for keep in (Places.MOST, 0):  # kept, then the loop
            monkeypatch.setattr(AnchorIndex, "KEEP_MOST", keep)
            try:
                Probe.rules().match(Probe.DATA)
                outcomes.append("matched")
            except RuleError as exc:
                outcomes.append(type(exc).__name__)
        assert outcomes[0] == outcomes[1] != "matched"
