"""A list split at a separator, with the space around each separator dropped, in linear time.

`re.split(r"\\s*,\\s*", text)` is the obvious spelling, and it is quadratic: on a long run of space
with no separator in it, the search tries every start in the run and backs off through all of it
from each. Text the scanner reads is hostile, so a run of space is a run an attacker chose.

`Delimited.split(text, ",")` gives exactly that list: the text split at each separator, the space
before a separator taken off the piece ahead of it, the space after it off the piece behind, and
the text's own leading and trailing space left as `re.split` leaves them. Space is what `\\s` means
for a str, which is what `str.isspace` means, so `str.lstrip()` and `str.rstrip()` remove the same.
"""

from __future__ import annotations


class Delimited:
    """Lists written as text: `a, b ,c`."""

    @staticmethod
    def split(text: str, separator: str) -> list[str]:
        """`re.split(r"\\s*" + re.escape(separator) + r"\\s*", text)`, for a one-character
        separator that is not itself space."""
        parts = text.split(separator)
        last = len(parts) - 1
        return [
            (part.lstrip() if index else part).rstrip()
            if index < last
            else (part.lstrip() if index else part)
            for index, part in enumerate(parts)
        ]


__all__ = ["Delimited"]
