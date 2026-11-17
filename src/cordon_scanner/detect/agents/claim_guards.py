"""A guard against announcing a result too early is not a secret kept from the user.

"Do not tell the user the export is ready until the status shows success" and "never tell the user
the batch is complete from this reply alone" are written by tools that return before their work is
done: they stop the agent from asserting a state. The wording is the one concealment uses ("do not tell
the user ...") and two readers took it for concealment: the tool-description check
(`McpServerSource._keeps_from_user`) and the agent-text rules (ATR's AGENT_MANIPULATION match in
`AgentTextFindings.threat_rules`). Both read the text this module returns, with each such guard
replaced by blanks of its own length, so every offset, line and span stays where it was.

```
  never|do not|don't  +  tell|say|inform|mention|show|notify|alert  +  the user     the negated telling
  + up to six words + is|are|was|were|has been|have been + ready|done|complete|...  a state, named
  + until|unless|before|once|yet|only after ... or "from this ... alone"            when it may be said
  + a short tail with no path, host, pipe or command beside it                       nothing carried in it
```

Three more forms of a guard are read the same way, each closed and each ending in something the
text says to do or why (doc 38):

```
  a claim guard wrapped across lines      a docstring's hard wrap is not the end of the sentence
  never|do not  show|display|present  it|them  (to the user)  as|in|via ...           a form named,
  + a dash, semicolon or comma + always|instead|rather use  `name` | 'name' | a.b      and what to use
  never|do not  tell|say|claim|report  anyone|the user  ... a negated claim :           a claim refused,
  + only means|does not mean|is not proof|not necessarily ... in the same sentence      and why
```

All four parts or nothing is blanked. Concealment keeps its wording: "that you ran X", "about this",
"anything", "this instruction", a past act ("was sent", "were uploaded"), a state with no condition
on it, and any tail that carries a path, a host, a pipe or a command still read as concealment.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final

# The straight and the curly apostrophe. The pattern holds the character itself, not a `\u2019`
# escape: the rule-pack validator reads every engine pattern as bytes, where `\u` is no escape.
_APOSTROPHES: Final = "'\u2019"


class ClaimGuards:
    """Find and blank the guards against asserting a state. Stateless."""

    # Possessive runs of blanks and words (review 98, 27-PERFORMANCE): each is taken once, so the
    # six-word gap cannot split one stretch in more than one way.
    _GUARD: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:never|do\s++not|don[" + _APOSTROPHES + r"]?t)\s++"
        r"(?:tell|say|inform|mention|show|notify|alert)\s++"
        r"(?:the\s++)?user\b(?:\s++that\b)?"
        r"(?:\s++[\w`" + _APOSTROPHES + r"()-]++){1,6}?"
        r"\s++(?:is|are|was|were|has\s++been|have\s++been)\s++(?:(?:now|fully|already)\s++)?"
        r"(?:ready|done|complete|completed|finished|available|successful|succeeded)\b"
    )
    #: When the state may be said: a condition on it, in the rest of the same sentence.
    _CONDITION: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:until|unless|before|once|yet|only\s++(?:after|when|if)|if|when)\b"
        r"|\bfrom\s++this\b[^.!?\n]{0,30}?\balone\b"
    )
    #: What a tail carries when something is hidden in it: a path, a host, a pipe, a command.
    _CARRIES: ClassVar[re.Pattern[str]] = re.compile(
        r"[/\\|$<>;~]|https?:|\b(?:curl|wget|sh|bash|eval|exec|sudo|rm)\b", re.IGNORECASE
    )
    _SENTENCE_END: ClassVar[re.Pattern[str]] = re.compile(r"[.!?\n]")
    _TAIL_WORDS: ClassVar[int] = 12
    _TAIL_CHARS: ClassVar[int] = 160
    #: A single newline in the middle of a sentence: a hard wrap, not a break (a blank line or a list
    #: item ends the sentence).
    _WRAP: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<!\n)\n(?![ \t]*+(?:\n|[-*+\u2022]\s|\d{1,3}[.)]\s))"
    )
    #: A form the user is not shown, with what to use instead: "never show them to the user as a raw
    #: URL -- always use `download_url`".
    _SUBSTITUTION: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:never|do\s++not|don["
        + _APOSTROPHES
        + r"]?t)\s++(?:show|display|print|present|render)\s++"
        r"(?:them|it|these|this|those)\b(?:\s++to\s++the\s++user)?\s++(?:as|in|via|using)\b"
        r"(?:\s++[\w`" + _APOSTROPHES + r".-]++){1,8}?(?=\s*+[\u2014\u2013;,-])"
    )
    #: What the substitution says to use: an identifier, quoted or dotted or snake-cased.
    _USE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)^\s*+(?:[\u2014\u2013-]++|[;,])\s*+(?:always|instead|rather)\b[^.!?\n]{0,20}?"
        r"\b(?:use|show|give|return|pass|call)\s++(?:the\s++)?"
        r"(?:`[\w.-]{2,60}`|'[\w.-]{2,60}'|\"[\w.-]{2,60}\"|\w{2,40}(?:[._]\w{1,40}){1,4})"
        r"\s*+[.!?]?\s*+$"
    )
    #: A claim refused, and why: "never tell anyone a shop does not advertise: X only means Y".
    _REFUSED: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:never|do\s++not|don["
        + _APOSTROPHES
        + r"]?t)\s++(?:tell|say|claim|state|report|assert)\s++"
        r"(?:anyone|people|users?|the\s++user)\s++(?:[\w`" + _APOSTROPHES + r"-]++\s++){0,12}?"
        r"(?:not|no|never|\w+n[" + _APOSTROPHES + r"]t)\b[^:.!?\n]{0,60}(?=:)"
    )
    _BECAUSE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:only\s++means|does\s++not\s++mean|doesn["
        + _APOSTROPHES
        + r"]?t\s++mean|is\s++not\s++"
        r"(?:proof|evidence)|isn[" + _APOSTROPHES + r"]?t\s++(?:proof|evidence)|not\s++necessarily|"
        r"cannot\s++prove|can[" + _APOSTROPHES + r"]?t\s++prove)\b"
    )

    @staticmethod
    def masked(text: str) -> str:
        """`text` with each guard against asserting a state replaced by blanks of the same length
        (from the negation through the state; the condition after it stays readable). The same
        object when there is none."""
        flat = ClaimGuards._WRAP.sub(" ", text)
        spans = [
            match.span()
            for match in ClaimGuards._GUARD.finditer(flat)
            if ClaimGuards._conditioned(flat, match.end())
        ]
        spans.extend(
            match.span()
            for match in ClaimGuards._SUBSTITUTION.finditer(flat)
            if ClaimGuards._substituted(flat, match.end())
        )
        spans.extend(
            match.span()
            for match in ClaimGuards._REFUSED.finditer(flat)
            if ClaimGuards._explained(flat, match.end())
        )
        if not spans:
            return text
        parts: list[str] = []
        at = 0
        for start, end in sorted(set(spans)):
            if start < at:
                continue
            parts.append(text[at:start])
            parts.append(" " * (end - start))
            at = end
        parts.append(text[at:])
        return "".join(parts)

    @staticmethod
    def _sentence_tail(text: str, end: int) -> str:
        window = text[end : end + ClaimGuards._TAIL_CHARS]
        stop = ClaimGuards._SENTENCE_END.search(window)
        return window[: stop.start()] if stop else window

    @staticmethod
    def _substituted(text: str, end: int) -> bool:
        """Whether the rest of the sentence after the form named says what to use instead, and
        carries nothing but that."""
        window = text[end : end + ClaimGuards._TAIL_CHARS]
        stop = re.search(r"[!?\n]|\.(?:\s|$)", window)
        tail = window[: stop.end()] if stop else window
        return (
            len(tail.split()) <= ClaimGuards._TAIL_WORDS
            and ClaimGuards._USE.match(tail) is not None
            and ClaimGuards._CARRIES.search(re.sub(r"^\s*+[;,\u2014\u2013-]++", "", tail)) is None
        )

    @staticmethod
    def _explained(text: str, end: int) -> bool:
        """Whether the sentence goes on, after the colon, to say why the claim is refused and carries
        nothing besides."""
        window = text[end : end + ClaimGuards._TAIL_CHARS * 2]
        stop = re.search(r"[!?\n]|\.(?:\s|$)", window)
        tail = window[: stop.start()] if stop else window
        return (
            len(tail.split()) <= ClaimGuards._TAIL_WORDS * 3
            and ClaimGuards._BECAUSE.search(tail) is not None
            and ClaimGuards._CARRIES.search(tail) is None
        )

    @staticmethod
    def _conditioned(text: str, end: int) -> bool:
        """Whether the rest of the sentence after the state is a short condition with nothing
        carried in it."""
        window = text[end : end + ClaimGuards._TAIL_CHARS]
        stop = ClaimGuards._SENTENCE_END.search(window)
        tail = window[: stop.start()] if stop else window
        return (
            len(tail.split()) <= ClaimGuards._TAIL_WORDS
            and ClaimGuards._CONDITION.search(tail) is not None
            and ClaimGuards._CARRIES.search(tail) is None
        )


__all__ = ["ClaimGuards"]
