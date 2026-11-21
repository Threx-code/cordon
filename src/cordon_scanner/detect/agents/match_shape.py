"""Whether the words an Agent Threat Rule matched are a phrase or only the markup that ends a label or opens a list item.

The rules were written for traffic, where a match is a sentence somebody typed. In a file a pattern that ends in `[:=-]` can take
the bullet of the next list item for its final dash, or a heading's colon for its punctuation, and then the match is on structure:

```
  match                                          shape
  "... current configuration\n   -"              ends as the bullet of the next list item   ──► a fragment
  "Updated configuration:"  (end of line)        ends as a heading's colon, nothing after   ──► a fragment
  "New instructions: ignore the above"           a mark with words on both sides            ──► a phrase
  "ignore all previous instructions"             words in a sentence, a cell or a heading   ──► a phrase
```

The shape is the match's own: where it sits (a table cell, a heading, a list item) does not change it, so an instruction written
inside a table row or under a heading is as much a phrase as one in a paragraph. `SUSPECT.AGENT.INJECTION_CORROBORATED.001` counts a
phrase finding only when it has a match that is not a fragment (`decide/composites.py`); the finding itself is graded as before.

What is NOT a fragment, measured (reviews/mcp-98, PR 90 pre-test): a match that starts or stops inside a word, one with no word of
three letters in it, and one that runs across the end of a sentence all look like noise, and each removes legitimate units from the
composite -- and each also removes the malicious ones the composite catches, because for those skills the phrase is as much noise as
for the legitimate ones and the learned reading of the instructions carries the signal. On the 3,456 malicious skills of the dev
half, the 36 the composite newly blocks, ruling a match with the in-word shape a fragment lost 28 of them (20 by that rule alone), the
no-word shape 7 and the sentence shape 1; the bullet-or-label shape lost none. So only that one is kept: the rest is a matter for the
patterns of the rules themselves, each with its own pre-test.
"""

from __future__ import annotations

from typing import Final


class MatchShape:
    """The shape of one match: its span in the text the rule read."""

    CODE: Final[str] = "fragment_only"
    """The `Explanation.basis` code a finding carries when every match it names is a fragment."""

    #: Marks that end a label or open a list item, which a pattern's own `[:=-]` can take for punctuation.
    LABEL_MARKS: Final[str] = ":=-"

    @staticmethod
    def fragment(text: str, start: int, end: int) -> bool:
        """True when the match at `start`..`end` of `text` is empty, or ends as a list bullet or a heading's colon."""
        if not text[start:end].strip():
            return True
        return MatchShape.ends_as_markup(text, start, end)

    @staticmethod
    def ends_as_markup(text: str, start: int, end: int) -> bool:
        """The match ends in a `:`, `=` or `-` that is a list bullet or a heading's colon, not punctuation in a sentence.

        A bullet is a mark with nothing before it on its line; a label's mark has nothing after it on its line. A
        mark with words on both sides, `New instructions: ignore the above`, is the punctuation the rule meant."""
        matched = text[start:end].rstrip()
        if not matched or matched[-1] not in MatchShape.LABEL_MARKS:
            return False
        mark = start + len(matched) - 1
        line_start = text.rfind("\n", 0, mark) + 1
        line_end = text.find("\n", mark)
        line_end = len(text) if line_end < 0 else line_end
        before = text[line_start:mark]
        after = text[mark + 1 : line_end]
        return not before.strip() or not after.strip()

    @staticmethod
    def codes(text: str, spans: list[tuple[int, int]]) -> tuple[str, ...]:
        """The `Explanation.basis` codes for a finding's matches: `fragment_only` when there are matches and every one is a
        fragment."""
        if spans and all(MatchShape.fragment(text, start, end) for start, end in spans):
            return (MatchShape.CODE,)
        return ()


__all__ = ["MatchShape"]
