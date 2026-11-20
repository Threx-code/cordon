"""Padding for tests of readers that once stopped at a size: text that says nothing, in lines, of an exact length."""

from __future__ import annotations


class Padding:
    """`Padding.lines(chars)`: comment lines, `chars` characters in all, each ending in a newline."""

    @staticmethod
    def lines(chars: int, comment: str = "//") -> str:
        line = comment + " " + "x" * 77 + "\n"
        whole, rest = divmod(chars, len(line))
        return line * whole + (comment[0] * (rest - 1) + "\n" if rest else "")
