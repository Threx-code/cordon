"""The defensive-document gate for agent-text rules (review 98, skills G1).

A third-party ``SKILL.md`` that is itself about these attacks -- a security, red-team or CTF
skill that explains prompt injection, jailbreaks or payloads -- quotes the very wording the
agent-text rules (`atr`) match. A stable match there is the documented payload, not the act, so
such a file blocks a stable, high/critical match only beside Cordon's own evidence in the same
file: hidden text, credentials moved, concealment, or a fetch-and-run -- the code evidence, not
the injection wording it quotes. That is the bar an instruction file already gets (AG-2). Review
98 found ctf/offensive/hardened security skills blocked on documented attack wording that
carried no payload; this gate warns on them instead.
"""

from __future__ import annotations

import re
from typing import Final

#: A document about the attack, quoting it: security notes, payload lists, red-team playbooks.
DISCUSSES_INJECTION: Final = re.compile(
    r"(?i)prompt[ -]?injection|jailbreak|red[ -]team|(?:injection|attack|test)[ -]payloads?"
)


_QUOTE_PAIRS: Final = (('"', '"'), ("\u201c", "\u201d"), ("\u2018", "\u2019"), ("'", "'"))


class DefensiveDoc:
    """When a file documents these attacks, and what still counts as proof inside one."""

    @staticmethod
    def frontmatter_end(text: str) -> int:
        """Where a leading `---` frontmatter block ends (0 when there is none)."""
        if not text.startswith(("---\n", "---\r\n")):
            return 0
        close = re.search(r"(?m)^---[ \t]*\r?$", text[3:])
        return 0 if close is None else 3 + close.end()

    @staticmethod
    def _paragraph(text: str, start: int, end: int) -> tuple[int, int]:
        low = text.rfind("\n\n", 0, start)
        high = text.find("\n\n", end)
        return (0 if low < 0 else low + 2), (len(text) if high < 0 else high)

    @staticmethod
    def quoted_example(text: str, start: int, end: int) -> bool:
        """Whether the span at [start, end) is shown as an example: inside a fenced code block, a
        blockquote line, inline code, or a pair of quotation marks in its own paragraph.

        Wording that stands bare in a sentence would act as an instruction to the agent that
        reads the file, whatever the file says about itself."""
        fences = len(re.findall(r"(?m)^[ \t]*(?:```|~~~)", text[:start]))
        if fences % 2 == 1:
            return True
        line_start = text.rfind("\n", 0, start) + 1
        if text[line_start:start].lstrip().startswith(">"):
            return True
        low, high = DefensiveDoc._paragraph(text, start, end)
        before, after = text[low:start], text[end:high]
        if before.count("`") % 2 == 1 and "`" in after:
            return True
        for opener, closer in _QUOTE_PAIRS:
            if opener == closer:
                if before.count(opener) % 2 == 0 or closer not in after:
                    continue
            else:
                if before.rfind(opener) <= before.rfind(closer) or closer not in after:
                    continue
            cut = before.rfind(opener)
            if opener == "'" and cut > 0 and before[cut - 1].isalnum():
                continue  # an apostrophe, not an opening quote
            return True
        return False

    @staticmethod
    def lowers(documentation: bool, text: str, start: int, end: int, *, model_agrees: bool) -> bool:
        """Whether this match is lowered as a documented example. Text the author controls is not
        enough on its own: the wording must be quoted as an example, beside the defensive
        vocabulary in the same paragraph and outside frontmatter, and the learned model must not
        read the file as an attack (S6, `reviews/release-080/SECURITY-HARDENING.md`)."""
        if not documentation or model_agrees or start < DefensiveDoc.frontmatter_end(text):
            return False
        if not DefensiveDoc.quoted_example(text, start, end):
            return False
        low, high = DefensiveDoc._paragraph(text, start, end)
        return DISCUSSES_INJECTION.search(text[max(low, DefensiveDoc.frontmatter_end(text)) : high]) is not None

    @staticmethod
    def code_evidence(hidden: object, exfil: object, concealed: object, alarming: object) -> bool:
        """Cordon's own evidence in the file *without* the injection wording -- in a file about
        payloads the quoted payload is not proof, but hidden text, credentials moved, concealment
        or an alarming call still is."""
        return bool(hidden or exfil or concealed or alarming is not None)

    @staticmethod
    def is_defensive(documentation: bool, text: str) -> bool:
        """Whether this is a documentation file (a skill, not a tool description or command) that
        is itself about these attacks, so its attack wording is quoted, not carried."""
        return documentation and DISCUSSES_INJECTION.search(text) is not None

    @staticmethod
    def stable_blocks(
        corroborated_code: bool, defensive: bool, corroborated: bool, instruction_file: bool
    ) -> bool:
        """Whether a stable, high/critical agent-text match should block. A defensive document
        blocks only on code evidence; otherwise the ordinary bar applies -- corroborated, or not
        an instruction file at all."""
        return corroborated_code or (not defensive and (corroborated or not instruction_file))
