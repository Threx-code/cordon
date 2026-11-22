"""The size of what a decision says: the library bounds its own free text, so a receiver can cap it one notch above.

A decision's text is mostly fixed templates with ids, but some of it is an input echoed back: the path of a file the scan could not read, an approval's conditions, an intel match's id. A path can be any length
and hold any character a file name can hold, and a scan of a large package can give thousands of findings, each one a reason. Left alone, a decision could carry a great deal of text that was never the library's to say. So:

* a reason's text and the summary (`<state>: <code> <first reason>`) are at most `TEXT` characters, cut with an ellipsis;
* a gap path inside a reason is cut at `PATH` characters with an ellipsis, and the approval conditions inside a reason at `CONDITIONS`;
* a decision lists at most `REASONS` reasons, then one more that says how many were not listed (its code is the first unlisted reason's, so the code list a decision carries, made from all of them, still names every code);
* a control character in any of it (a file name can hold one) is replaced by `?`.

The structured fields of a reason (`rule_id`, `path`, `line`, `evidence_hash`) are data, not text, and are left as they are. `reason_codes` is made from every reason before the list is bounded.
"""

from __future__ import annotations

import unicodedata
from dataclasses import replace
from typing import ClassVar

from cordon_scanner.decide.decision.outcome import Reason


class Bounds:
    TEXT: ClassVar[int] = 320
    """The most characters in a reason's text and in the summary."""
    REASONS: ClassVar[int] = 100
    """The most reasons listed, before the one that counts the rest."""
    PATH: ClassVar[int] = 200
    """The most characters of a path kept inside a reason's text (then an ellipsis)."""
    CONDITIONS: ClassVar[int] = 500
    """The most characters of an approval's conditions kept inside a reason's text."""
    ELLIPSIS: ClassVar[str] = "…"

    @classmethod
    def clean(cls, text: str) -> str:
        """`text` with every control character replaced by `?`."""
        if text.isprintable():
            return text
        return "".join("?" if unicodedata.category(char) == "Cc" else char for char in text)

    @classmethod
    def cut(cls, text: str, limit: int) -> str:
        """`text` made safe and no longer than `limit` characters, an ellipsis last when it was cut."""
        text = cls.clean(text)
        return text if len(text) <= limit else text[: limit - 1] + cls.ELLIPSIS

    @classmethod
    def path(cls, path: str) -> str:
        """A path as it is written inside a reason: its first `PATH` characters and an ellipsis when there are more."""
        text = cls.clean(path)
        return text if len(text) <= cls.PATH else text[: cls.PATH] + cls.ELLIPSIS

    @classmethod
    def conditions(cls, conditions: tuple[str, ...]) -> str:
        """An approval's conditions joined for a reason, cut at `CONDITIONS` characters."""
        text = cls.clean("; ".join(conditions))
        return text if len(text) <= cls.CONDITIONS else text[: cls.CONDITIONS - 1] + cls.ELLIPSIS

    @classmethod
    def summary(cls, text: str) -> str:
        return cls.cut(text, cls.TEXT)

    @classmethod
    def reasons(cls, reasons: tuple[Reason, ...]) -> tuple[Reason, ...]:
        """At most `REASONS` reasons with their text bounded, and one more counting the rest when there were more."""
        bounded = tuple(
            replace(item, text=cls.cut(item.text, cls.TEXT))
            if len(item.text) > cls.TEXT or not item.text.isprintable()
            else item
            for item in reasons[: cls.REASONS]
        )
        rest = reasons[cls.REASONS :]
        if not rest:
            return bounded
        return (*bounded, Reason(rest[0].code, f"and {len(rest)} more reasons, not listed"))


__all__ = ["Bounds"]
