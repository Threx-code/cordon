"""Results of a pure analysis kept by their text (`analysis/shared/content_memo`)."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.resolve import CallResolver
from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.analysis.shared.content_memo import ContentMemo


class Counting:
    """An analysis that counts how often it runs."""

    def __init__(self) -> None:
        self.runs = 0

    def __call__(self) -> list[int]:
        self.runs += 1
        return [1, 2, 3]


class TestContentMemo:
    def test_the_same_text_is_worked_out_once(self) -> None:
        memo, work = ContentMemo(smallest=1), Counting()
        assert memo.get("k", "some text", work) == [1, 2, 3]
        assert memo.get("k", "some text", work) == [1, 2, 3]
        assert work.runs == 1

    def test_each_caller_gets_its_own_list(self) -> None:
        memo = ContentMemo(smallest=1)
        first = memo.get("k", "text", Counting())
        first.append(99)
        assert memo.get("k", "text", Counting()) == [1, 2, 3]

    def test_keys_and_texts_are_told_apart(self) -> None:
        memo, work = ContentMemo(smallest=1), Counting()
        memo.get("a", "text", work)
        memo.get("b", "text", work)
        memo.get("a", "other", work)
        assert work.runs == 3

    def test_a_short_text_is_worked_out_every_time(self) -> None:
        memo, work = ContentMemo(smallest=100), Counting()
        memo.get("k", "short", work)
        memo.get("k", "short", work)
        assert work.runs == 2

    def test_bounded_by_entries_and_by_weight_oldest_first(self) -> None:
        memo = ContentMemo(entries=2, weight=1000, smallest=1)
        for text in ("one", "two", "three"):
            memo.get("k", text, Counting())
        work = Counting()
        memo.get("k", "one", work)  # dropped as the oldest
        assert work.runs == 1
        heavy = ContentMemo(entries=100, weight=5, smallest=1)
        heavy.get("k", "one", Counting())
        heavy.get("k", "two", Counting())  # 6 items held > 5: "one" goes
        again = Counting()
        heavy.get("k", "one", again)
        assert again.runs == 1

    def test_lone_surrogates_are_texts_like_any_other(self) -> None:
        memo, work = ContentMemo(smallest=1), Counting()
        memo.get("k", "a\udc80b", work)
        memo.get("k", "a\udc81b", work)
        assert work.runs == 2


class TestTheAnalysesItHolds:
    SOURCE = (
        "const cp = require('child_process');\n"
        + "function f(x) { return x; }\n" * 200
        + ("cp.exec(process.env.TOKEN);\n")
    )

    def test_flows_come_back_the_same_from_the_memo(self) -> None:
        first = JsFlow.flows(self.SOURCE)
        assert JsFlow.flows(self.SOURCE) == first
        assert JsFlow._flows(self.SOURCE) == first

    def test_calls_come_back_the_same_from_the_memo(self) -> None:
        resolver = CallResolver()
        first = resolver.resolve_calls(self.SOURCE)
        assert resolver.resolve_calls(self.SOURCE) == first
        assert [c for _, c in resolver.resolve_parts([(0, 0, 0, self.SOURCE)])] == first
