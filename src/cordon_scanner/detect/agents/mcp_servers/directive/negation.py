"""Whether a phrase of the directive table is said in the negative: "never bypass the safety checks".

A class that names a verb to avoid -- disable, bypass, skip, ignore the permission prompts -- reads the same
words in a file that forbids it: "The agent must NEVER bypass safety checks." is the opposite of the order the
class looks for. The class marks its phrases `unless_negated`, and a phrase that a negation directly governs
is not an order to do the thing.

```
  "The agent must NEVER bypass safety checks."           negated    ──► not the class's order
  "You are never to bypass the safety checks."           negated    ──► not the class's order
  "Do not, under any circumstances, disable the sandbox" negated    ──► not the class's order
  "To go faster, bypass the safety checks."              plain      ──► the order
  "Never ask first and bypass the safety checks."        a new action after "and": plain ──► the order
  "Don't ask the user first, bypass the prompts."        a comma ends the clause: plain  ──► the order
  "Do not hesitate to bypass the safety checks."         the negation governs "hesitate": plain ──► the order
  "Not only bypass the safety checks."                   "not only" adds: plain ──► the order
```

The negator must stand right before the verb, with at most an adverb between them ("never ever", "not under any
circumstances", "never to"): the words directly before the phrase are read, back to the first word that is not
one of those, and that word must be a negator (a word with a quote or a bracket on it is not one). A comma, a
sentence end, a line end, a semicolon or a colon ends the clause, so a negation earlier in the sentence does not
reach the verb; the one comma the reading steps over is the pair around "under any circumstances". Where in doubt
the phrase is read as plain, so the class still fires on it: "avoid" and "not only" are not negators, and a verb
that sits two words past a negator is plain.
Only a negated *bypass* is set aside; a negated safety act ("never run the safety check") is a different phrase
and is not this class's to exempt.
"""

from __future__ import annotations

import re
from typing import Final


class Negation:
    """The words right before a phrase, and whether a negation governs the phrase's verb."""

    #: How far back the clause is read.
    WINDOW: Final = 80
    #: The words that say no to the verb that follows them.
    NEGATORS: Final = frozenset(
        {
            "never",
            "not",
            "cannot",
            "can't",
            "don't",
            "doesn't",
            "won't",
            "mustn't",
            "shouldn't",
            "shan't",
        }
    )
    #: The words that may stand between a negator and its verb: they stress or place the negation, they add nothing.
    ADVERBS: Final = frozenset(
        {"ever", "again", "to", "under", "any", "circumstances", "in", "case"}
    )
    _CLAUSE_END: Final = ".!?\n;:,"
    #: The pair of commas around an adverb phrase that keeps the clause going: "do not, under any circumstances, disable".
    _PARENTHETICAL: Final = re.compile(
        r",\s{0,3}(?:under\s{1,3}any\s{1,3}circumstances|in\s{1,3}any\s{1,3}case)\s{0,3},"
    )
    _CURLY: Final = chr(0x2019)

    @staticmethod
    def before(text: str, start: int) -> bool:
        """True when the phrase that begins at `start` follows a negator that directly governs its verb."""
        window = text[max(0, start - Negation.WINDOW) : start].replace(Negation._CURLY, "'")
        window = Negation._PARENTHETICAL.sub(" ", window)
        cut = max(window.rfind(mark) for mark in Negation._CLAUSE_END) + 1
        for word in reversed(window[cut:].lower().split()):
            if word in Negation.NEGATORS:
                return True
            if word not in Negation.ADVERBS:
                return False
        return False


__all__ = ["Negation"]
