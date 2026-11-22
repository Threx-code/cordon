"""Whether the words an Agent Threat Rule matched are a phrase or only the markup that ends a label or opens a list item.

The rules were written for traffic, where a match is a sentence somebody typed. In a file a pattern that ends in `[:=-]` can take
the bullet of the next list item for its final dash, or a heading's colon for its punctuation, and then the match is on structure:

```
  match                                          shape
  "... current configuration\n   -"              ends as the bullet of the next list item   ──► a fragment
  "Updated configuration:" + a code fence, a     a heading's colon, and what follows it is
     table, a list, key: value lines, nothing    not prose                                   ──► a fragment
  "Updated configuration:" + a sentence          a label with its payload below              ──► a phrase
  "New instructions: ignore the above"           a mark with words on both sides             ──► a phrase
  "ignore all previous instructions"             words in a sentence, a cell or a heading    ──► a phrase
```

The shape is the match's own: where it sits (a table cell, a heading, a list item) does not change it, so an instruction written
inside a table row or under a heading is as much a phrase as one in a paragraph. A label counts as a heading only when what
follows it is not prose: the layout of an injected block is a label and its instruction on the next line, so a label whose next
non-blank line is a sentence (letters, four words or more, no code marks) is a phrase, with or without a blank line between.
`SUSPECT.AGENT.INJECTION_CORROBORATED.001` counts a phrase finding only when it has a match that is not a fragment
(`decide/composites.py`); the finding itself is graded as before.

What is NOT a fragment, measured (reviews/mcp-98, PR 90 pre-test): a match that starts or stops inside a word, one with no word of
three letters in it, and one that runs across the end of a sentence all look like noise, and each removes legitimate units from the
composite -- and each also removes the malicious ones the composite catches, because for those skills the phrase is as much noise as
for the legitimate ones and the learned reading of the instructions carries the signal. On the 3,456 malicious skills of the dev
half, the 36 the composite newly blocks, ruling a match with the in-word shape a fragment lost 28 of them (20 by that rule alone), the
no-word shape 7 and the sentence shape 1; the bullet-or-label shape lost none. So only that one is kept: the rest is a matter for the
patterns of the rules themselves, each with its own pre-test.
"""

from __future__ import annotations

import re
from typing import Final


class MatchShape:
    """The shape of one match: its span in the text the rule read."""

    CODE: Final[str] = "fragment_only"
    """The `Explanation.basis` code a finding carries when every match it names is a fragment."""

    #: Marks that end a label or open a list item, which a pattern's own `[:=-]` can take for punctuation.
    LABEL_MARKS: Final[str] = ":=-"
    #: How far past a label the next non-blank line is looked for, in characters.
    LOOKAHEAD: Final[int] = 2000
    #: How many lines past a label are looked at: blank lines up to the first line with text.
    LOOKAHEAD_LINES: Final[int] = 8
    #: A line that opens with one of these is a fence, a table row, a heading, a list item or a tag, not a sentence.
    _STRUCTURE: Final = ("```", "~~~", "|", "#", "- ", "* ", "+ ", "<", "![", "---", "***", "===")
    _NUMBERED: Final = re.compile(r"\d{1,3}[.)]\s")
    #: `key: value` with a short value is configuration, not a sentence: the longest key and the most words of a value.
    KEY_CHARS: Final[int] = 40
    VALUE_WORDS: Final[int] = 3
    _CODE_MARKS: Final = frozenset("{}<>;=|$")
    PROSE_WORDS: Final[int] = 4
    """Whitespace-separated words a line needs to be a sentence."""
    PROSE_LETTERS: Final[int] = 12
    """Letters a line without that many words needs to be a sentence (a language written without spaces)."""

    @staticmethod
    def fragment(text: str, start: int, end: int) -> bool:
        """True when the match at `start`..`end` of `text` is empty, or ends as a list bullet or a heading's colon."""
        if not text[start:end].strip():
            return True
        return MatchShape.ends_as_markup(text, start, end)

    @staticmethod
    def ends_as_markup(text: str, start: int, end: int) -> bool:
        """The match ends in a `:`, `=` or `-` that is a list bullet or a heading's colon, not punctuation in a sentence.

        A bullet is a mark with nothing before it on its line. A label's mark has nothing after it on its line, and
        is a heading's colon when the text after it is not prose; a label whose next line is a sentence is a phrase
        with its payload below. A mark with words on both sides, `New instructions: ignore the above`, is the
        punctuation the rule meant."""
        matched = text[start:end].rstrip()
        if not matched or matched[-1] not in MatchShape.LABEL_MARKS:
            return False
        mark = start + len(matched) - 1
        line_start = text.rfind("\n", 0, mark) + 1
        line_end = text.find("\n", mark)
        line_end = len(text) if line_end < 0 else line_end
        if not text[line_start:mark].strip():
            return True
        if text[mark + 1 : line_end].strip():
            return False
        return not MatchShape.prose_follows(text, line_end)

    @staticmethod
    def prose_follows(text: str, at: int) -> bool:
        """True when the first non-blank line after `at` is a sentence: the payload of the label above it."""
        lines = text[at : at + MatchShape.LOOKAHEAD].splitlines()
        for line in lines[: MatchShape.LOOKAHEAD_LINES]:
            if line.strip():
                return MatchShape.sentence(line)
        return False

    @staticmethod
    def key_value(line: str) -> bool:
        """A `key: value` line: a short key of word characters, dots, dashes and slashes, and a value of at most three words.
        A longer value is a sentence that happens to open with a word and a colon (`Note: ignore the earlier rules ...`)."""
        key, mark, value = line.partition(":")
        key = key.strip()
        if not mark or not key or len(key) > MatchShape.KEY_CHARS:
            return False
        if not all(char.isalnum() or char in "_.-/" for char in key):
            return False
        words = len(value.split())
        return 0 < words <= MatchShape.VALUE_WORDS

    @staticmethod
    def sentence(line: str) -> bool:
        """A line of words: not a fence, a table row, a heading, a list item, a tag, a `key: value` line or code."""
        stripped = line.strip()
        if stripped.startswith(MatchShape._STRUCTURE) or MatchShape._NUMBERED.match(stripped):
            return False
        if any(mark in MatchShape._CODE_MARKS for mark in stripped):
            return False
        if MatchShape.key_value(stripped):
            return False
        letters = sum(1 for char in stripped if char.isalpha())
        return (
            len(stripped.split()) >= MatchShape.PROSE_WORDS or letters >= MatchShape.PROSE_LETTERS
        )

    @staticmethod
    def codes(text: str, spans: list[tuple[int, int]]) -> tuple[str, ...]:
        """The `Explanation.basis` codes for a finding's matches: `fragment_only` when there are matches and every one is a
        fragment."""
        if spans and all(MatchShape.fragment(text, start, end) for start, end in spans):
            return (MatchShape.CODE,)
        return ()


__all__ = ["MatchShape"]
