"""Elixir source with its literals set aside: each heredoc, string, charlist and comment replaced by a
space, so a reader counting `do` and `end` sees only code (`Mixfile.balanced`)."""

from __future__ import annotations


class ElixirLiterals:
    """Literals and comments in Elixir source, found in one read."""

    @staticmethod
    def blanked(text: str) -> str:
        """Each heredoc, string, charlist and comment replaced by a space, read once: what the
        substitution of a heredoc (three double quotes to the next three), a double- or single-quoted
        literal on one line with backslash escapes, or a `#` comment, by a space, gives. As an
        expression an unclosed literal was read to its line's end (a heredoc, to the text's) from every
        quote after it. Here a heredoc with no closing one ends every later heredoc, and a quoted
        literal that cannot close marks the quotes of its kind before where it stopped as failing
        too: each was read as escaped inside it, so its own read continues the same way."""
        out: list[str] = []
        at, size = 0, len(text)
        heredocs_open = True
        fail_before = {'"': 0, "'": 0}
        while at < size:
            char = text[at]
            if char == '"' and heredocs_open and text.startswith('"""', at):
                close = text.find('"""', at + 3)
                if close >= 0:
                    out.append(" ")
                    at = close + 3
                    continue
                heredocs_open = False
            if char in fail_before and at >= fail_before[char]:
                end = ElixirLiterals._quoted_end(text, at, char)
                if end > 0:
                    out.append(" ")
                    at = end
                    continue
                fail_before[char] = -end
            elif char == "#":
                newline = text.find("\n", at)
                out.append(" ")
                at = size if newline < 0 else newline
                continue
            out.append(char)
            at += 1
        return "".join(out)

    @staticmethod
    def _quoted_end(text: str, start: int, quote: str) -> int:
        """Past the literal opening at `start` (no raw newline in it; a backslash escapes the next
        character but a newline), or minus where its read stopped when it cannot close."""
        at, size = start + 1, len(text)
        while at < size:
            char = text[at]
            if char == quote:
                return at + 1
            if char == "\n":
                return -at
            if char == "\\":
                if at + 1 >= size or text[at + 1] == "\n":
                    return -at
                at += 2
                continue
            at += 1
        return -at


__all__ = ["ElixirLiterals"]
