"""A refused archive member's gap names what drove the refusal (`ArchiveMembers.cause_class`), so a
report shows whether a refusal was resource-driven: the scan's own budget, the member's size, an
unreadable member, or the member's content (reviews/release-080/LOAD-INDEPENDENT-BUDGETS.md)."""

from __future__ import annotations

import pytest

from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.sources.base import Rejection


class TestTheCauseClass:
    @pytest.mark.parametrize(
        ("reason", "detail", "expected"),
        [
            (Rejection.ENTRIES, "scan budget exhausted", "budget"),
            (Rejection.ENTRIES, "extraction stopped early at a limit", "budget"),
            (Rejection.ENTRIES, "more than 100000 entries", "size"),
            (Rejection.SIZE, "member exceeds the uncompressed budget", "size"),
            (Rejection.RATIO, "", "size"),
            (Rejection.PADDED, "", "size"),
            (Rejection.DEPTH, "", "size"),
            (Rejection.UNREADABLE, "bad header", "unreadable"),
            (Rejection.TRAVERSAL, "../x", "content"),
            (Rejection.NAME, "", "content"),
            (Rejection.UNSUPPORTED_FORMAT, "a rar archive", "content"),
        ],
    )
    def test_each_refusal_has_one_class(self, reason: str, detail: str, expected: str) -> None:
        assert ArchiveMembers.cause_class(reason, detail) == expected

    def test_the_gap_says_the_class_and_keeps_the_reason(self) -> None:
        finding = ArchiveMembers.not_examined("a.tar!x", Rejection.ENTRIES, "scan budget exhausted")
        assert finding.rule_id == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED"
        assert "(entry_count)" in finding.message
        assert "Cause class: budget." in finding.message
