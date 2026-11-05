"""Where JavaScript hands an evaluator a program it carries as a string (review 98).

`Function("w", "<822 KB>")(...)` from a postinstall was the whole of a hijacked `is` release:
nothing is decoded, so the decode-and-run composites never see it. A string a thousand characters
long handed to `eval`, `Function` or `vm` is a program carried as data; what code builds at run time
-- `new Function("return this")`, a template compiled to a function -- is short or computed.
"""

from __future__ import annotations

import re
from typing import ClassVar


class JsStringCode:
    #: Where JavaScript turns a string into code it runs.
    EVALUATOR: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])(?:eval|Function|new\s{1,4}Function)\s{0,4}\("
        r"|(?:\bvm|require\(\s{0,4}['\"](?:node:)?vm['\"]\s{0,4}\))\s{0,4}\.\s{0,4}"
        r"(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s{0,4}\("
        r"|\bnew\s{1,4}vm\s{0,4}\.\s{0,4}Script\s{0,4}\("
    )
    #: A string this long handed to an evaluator is a program carried as data.
    MIN: ClassVar[int] = 1000
    #: `Function`'s parameter names, skipped before the body.
    SHORT_ARG: ClassVar[re.Pattern[str]] = re.compile(
        r"""\s{0,8}(?:'[^'\\\n]{0,80}'|"[^"\\\n]{0,80}"|`[^`\\]{0,80}`)\s{0,8},"""
    )

    @classmethod
    def first_run(cls, text: str) -> tuple[int, int] | None:
        """The character span of the first evaluator handed a long literal, or None."""
        if len(text) < cls.MIN:
            return None
        for call in cls.EVALUATOR.finditer(text):
            index = call.end()
            for _ in range(3):
                short = cls.SHORT_ARG.match(text, index)
                if short is None:
                    break
                index = short.end()
            while index < len(text) and text[index] in " \t\r\n":
                index += 1
            if index >= len(text) or text[index] not in "'\"`":
                continue
            if cls.string_length(text, index) < cls.MIN:
                continue
            return (call.start(), call.end())
        return None

    @staticmethod
    def string_length(text: str, open_quote: int) -> int:
        """The length of the string literal opening at `open_quote`, or 0 if it does not close."""
        quote = text[open_quote]
        index = open_quote + 1
        while index < len(text):
            char = text[index]
            if char == "\\":
                index += 2
                continue
            if char == quote:
                return index - open_quote - 1
            if char == "\n" and quote != "`":
                return 0
            if quote == "`" and text.startswith("${", index):
                return 0  # a template that computes part of itself is not a literal
            index += 1
        return 0


__all__ = ["JsStringCode"]
