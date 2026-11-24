"""The pull-request comment for a set of decisions (flow 9.1), and the one notification a REVIEW result raises.

The comment says what was decided and why, and, for a result that needs a person (REVIEW or BLOCK), gives the three things the
author can do: request an exception, report a false positive, use an allowed version. The links are made from the platform's
base URL (https only) and the subject and decision digest, so the platform opens each with the context in hand. Text that came
from a package (a name, a reason) is written as plain text: markup, links and table breaks are neutralised.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, ClassVar

from cordon_scanner.decide.decision.outcome import Decision, States


class PrComment:
    """`render(results, base)` and `notification(results, owner, pr)`; `results` are (artifact name, Decision) pairs."""

    MAX_REASONS: ClassVar[int] = 5
    MAX_TEXT: ClassVar[int] = 300
    MAX_ROWS: ClassVar[int] = 50
    ACTIONS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("Request an exception", "exceptions/new", "an approver decides for this digest"),
        (
            "Report a false positive",
            "false-positives/new",
            "the finding is wrong for this artifact",
        ),
        (
            "Use an allowed version",
            "allowed-versions",
            "the versions the policy accepts for this name",
        ),
    )
    _UNRESERVED: ClassVar[frozenset[str]] = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    _BASE: ClassVar[re.Pattern[str]] = re.compile(
        r"https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/-]*)?"
    )
    _MARKUP: ClassVar[re.Pattern[str]] = re.compile(r"[\\`*_<>\[\]()|#!&~]")

    @classmethod
    def text(cls, value: str) -> str:
        """`value` as one line of plain text in markdown: every character that could open markup or HTML is escaped."""
        flat = " ".join(value.split())[: cls.MAX_TEXT]
        return cls._MARKUP.sub(lambda m: "\\" + m.group(0), flat)

    @classmethod
    def verdict(cls, results: list[tuple[str, Decision]]) -> str:
        """The strictest state of the results (ALLOW when there are none)."""
        state = States.ALLOW
        for _name, decision in results:
            state = States.stricter(state, decision.state)
        return state

    @classmethod
    def link(cls, base: str, path: str, name: str, decision: Decision) -> str:
        if not cls._BASE.fullmatch(base):
            raise ValueError("the platform base URL must be an https URL with no query")
        query = f"subject={cls._quote(name)}&decision={cls._quote(decision.inputs_digest)}"
        return f"{base.rstrip('/')}/{path}?{query}"

    @staticmethod
    def _quote(value: str) -> str:
        """`value` percent-encoded: every byte but an unreserved one."""
        return "".join(
            chr(b) if chr(b) in PrComment._UNRESERVED else f"%{b:02X}"
            for b in value.encode("utf-8")
        )

    @classmethod
    def render(cls, results: list[tuple[str, Decision]], base: str) -> str:
        overall = cls.verdict(results)
        lines = [f"## Cordon: {overall}", ""]
        for name, decision in results[: cls.MAX_ROWS]:
            lines.append(
                f"- **{cls.text(name)}**: {decision.state} ({', '.join(cls.text(c) for c in decision.reason_codes)})"
            )
            lines.append(f"  {cls.text(decision.explanation.summary)}")
            lines.extend(
                f"  - {cls.text(r.text)}" for r in decision.explanation.reasons[: cls.MAX_REASONS]
            )
        if len(results) > cls.MAX_ROWS:
            lines.append(f"- and {len(results) - cls.MAX_ROWS} more")
        if States.rank(overall) >= States.rank(States.REVIEW):
            name, decision = next((n, d) for n, d in results if d.state == overall)
            lines += ["", f"What you can do about **{cls.text(name)}**:", ""]
            lines += [
                f"- [{label}]({cls.link(base, path, name, decision)}): {why}"
                for label, path, why in cls.ACTIONS
            ]
        return "\n".join(lines) + "\n"

    @classmethod
    def notification(
        cls, results: list[tuple[str, Decision]], owner: str, pr: str
    ) -> dict[str, Any] | None:
        """The one notification a REVIEW result raises, to `owner`: None for any other result. Its `key` is the same for the same
        decisions on the same pull request, so a re-run or an edited comment never raises a second one."""
        if cls.verdict(results) != States.REVIEW:
            return None
        digests = sorted(d.inputs_digest for _n, d in results if d.state == States.REVIEW)
        key = hashlib.sha256("\n".join([pr, *digests]).encode("utf-8")).hexdigest()
        return {
            "type": "notification",
            "to": owner,
            "pull_request": pr,
            "state": States.REVIEW,
            "subjects": sorted({n for n, d in results if d.state == States.REVIEW})[: cls.MAX_ROWS],
            "key": key,
        }


__all__ = ["PrComment"]
