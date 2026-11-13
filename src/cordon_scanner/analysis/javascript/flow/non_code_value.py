"""Expressions whose value cannot be code, however the text inside them was chosen (reviews/pypi-98/26).

`eval(t.length)` evaluates a number and `eval(t === "a")` a boolean: nothing a server sent or a decode
produced runs. The reply and decode labels (`Taint.NARROWED`) stop at such an expression. The test is
the shape of the whole expression and is closed on the safe side: anything that can pass text on (a
concatenation, a slice, a trim, a ternary, an `||`, a parsed field, a template) keeps its labels."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.analysis.javascript.evaluation.values import Tok

#: An operator at the top of an expression that can make its value one of the operands, or join them.
_PASSES_TEXT_ON: Final = frozenset(
    {"?", ":", "||", "&&", "??", ",", "+", "-", "*", "/", "%", "**", "|", "&", "^", "<<", ">>",
     ">>>", "=>", "=", "...", "+=", "||=", "&&=", "??="}
)  # fmt: skip
_COMPARISONS: Final = frozenset({"===", "!==", "==", "!=", "<", ">", "<=", ">="})
_ACCESS: Final = frozenset({".", "?."})
_OPENERS: Final = frozenset({"(", "[", "{"})


class NonCodeValue:
    """Whether the token range `[a, b)` is an expression of a kind that cannot be code."""

    #: Members and methods that give a number or a boolean, whatever they are called on.
    MEMBERS: ClassVar[frozenset[str]] = frozenset({"length"})
    METHODS: ClassVar[frozenset[str]] = frozenset(
        {"indexOf", "lastIndexOf", "includes", "startsWith", "endsWith", "search", "charCodeAt",
         "codePointAt", "localeCompare", "test"}
    )  # fmt: skip
    #: A call of one of these on anything returns a number or a boolean.
    FUNCTIONS: ClassVar[frozenset[str]] = frozenset(
        {"Number", "parseInt", "parseFloat", "Boolean", "isNaN", "isFinite"}
    )

    @classmethod
    def holds(cls, tokens: list[Tok], match: list[int], a: int, b: int) -> bool:
        top = cls._top(tokens, match, a, b)
        if top is None or not top:
            return False
        if len(top) == 1 and tokens[top[0]].value == "(" and match[top[0]] == b - 1:
            return cls.holds(tokens, match, top[0] + 1, b - 1)  # `( expr )`
        operators = [
            tokens[i].value
            for i in top
            if tokens[i].kind == "punct"
            and tokens[i].value not in _ACCESS
            and tokens[i].value not in _OPENERS
        ]
        if any(op in _PASSES_TEXT_ON for op in operators):
            return False
        if any(op in _COMPARISONS for op in operators):
            return True
        names = [tokens[i].value if tokens[i].kind == "name" else None for i in top]
        if operators == ["!"] and names[0] is None and cls._chain(tokens, top[1:]):
            return True
        if operators:
            return False
        if names[0] == "typeof" and cls._chain(tokens, top[1:]):
            return True
        if len(top) >= 3 and tokens[top[-1]].value == "(" and names[-2] in cls.METHODS:
            return tokens[top[-3]].value in _ACCESS
        if len(top) >= 2 and names[-1] in cls.MEMBERS:
            return tokens[top[-2]].value in _ACCESS
        if len(top) == 2 and names[0] in cls.FUNCTIONS and tokens[top[1]].value == "(":
            return True
        return len(top) == 4 and names[0] == "JSON" and names[2] == "stringify"

    @staticmethod
    def _chain(tokens: list[Tok], top: list[int]) -> bool:
        """Names, `.` and groups only: an operand, with no operator of its own."""
        return bool(top) and all(
            tokens[i].kind == "name" or tokens[i].value in _ACCESS or tokens[i].value in _OPENERS
            for i in top
        )

    @staticmethod
    def _top(tokens: list[Tok], match: list[int], a: int, b: int) -> list[int] | None:
        """The tokens of the range outside every bracket pair, each pair standing as its opener. None
        where a token is of a kind the shape test does not read (a template, an error)."""
        out: list[int] = []
        k = a
        while k < b:
            token = tokens[k]
            if token.kind in ("tmpl", "regex"):
                return None
            out.append(k)
            if token.kind == "punct" and token.value in _OPENERS and match[k] > k:
                k = match[k] + 1
            else:
                k += 1
        return out
