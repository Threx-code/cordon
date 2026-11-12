"""A refused archive member's gap names what drove the refusal, so a report shows whether a refusal
was resource-driven: the scan's own budget, the member's size, an unreadable member, or its content
(`sources.base.REJECTION_CAUSE`; reviews/release-080/LOAD-INDEPENDENT-BUDGETS.md). The class is a
value stated per refusal reason, never read back out of a detail string."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import cordon_scanner.sources as sources_package
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.sources.base import REJECTION_CAUSE, Rejection

CLASSES = {"budget", "size", "unreadable", "content"}


def reasons() -> list[str]:
    return [v for k, v in vars(Rejection).items() if k.isupper() and isinstance(v, str)]


class TestEveryReasonStatesItsClass:
    def test_every_reason_has_a_class_of_the_value_set(self) -> None:
        missing = [r for r in reasons() if r not in REJECTION_CAUSE]
        assert not missing, f"a refusal reason with no cause class: {missing}"
        assert set(REJECTION_CAUSE.values()) <= CLASSES
        assert set(REJECTION_CAUSE) <= set(reasons())

    def test_every_refusal_site_raises_a_reason_that_has_one(self) -> None:
        """Each `RejectedMember(name, <reason>, ...)` in the readers names a `Rejection.X` that has a
        class (a reason passed as a variable is checked where it is built)."""
        known = {k for k, v in vars(Rejection).items() if k.isupper() and v in REJECTION_CAUSE}
        sites = 0
        for path in Path(sources_package.__file__).parent.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "RejectedMember"
                    and len(node.args) >= 2
                ):
                    continue
                reason = node.args[1]
                if isinstance(reason, ast.Attribute) and isinstance(reason.value, ast.Name):
                    sites += 1
                    assert reason.value.id == "Rejection" and reason.attr in known, (
                        f"{path.name}:{node.lineno} refuses with a reason that has no cause class"
                    )
        assert sites > 20  # the readers' refusals were found, not an empty scan


class TestTheClass:
    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            (Rejection.BUDGET, "budget"),
            (Rejection.ENTRIES, "size"),
            (Rejection.SIZE, "size"),
            (Rejection.RATIO, "size"),
            (Rejection.PADDED, "size"),
            (Rejection.DEPTH, "size"),
            (Rejection.UNREADABLE, "unreadable"),
            (Rejection.TRAVERSAL, "content"),
            (Rejection.NAME, "content"),
            (Rejection.UNSUPPORTED_FORMAT, "content"),
        ],
    )
    def test_each_reason_has_one_class(self, reason: str, expected: str) -> None:
        assert ArchiveMembers.cause_class(reason) == expected

    def test_the_gap_says_the_class_and_keeps_the_reason(self) -> None:
        finding = ArchiveMembers.not_examined("a.tar!x", Rejection.BUDGET, "scan budget exhausted")
        assert finding.rule_id == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED"
        assert "(scan_budget)" in finding.message
        assert "Cause class: budget." in finding.message
