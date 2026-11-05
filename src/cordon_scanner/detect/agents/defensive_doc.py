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


class DefensiveDoc:
    """When a file documents these attacks, and what still counts as proof inside one."""

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
