"""What a person sees of agent instructions, against what the agent reads (review 98).

A skill, an agent instruction file or a tool description is read twice: by a person, rendered, and by
the agent, raw. Markup decides what the first reading shows -- an HTML comment shows nothing, a
collapsed `<details>` shows its summary, a span styled `display:none` or `font-size:0` shows nothing,
a Markdown link-reference definition shows nothing. Text only the second reading contains is hidden
from the person by construction, so an instruction in it does not need to say it is covert: where it
sits already says so.

    RenderDiff.hidden(text)      the spans a renderer hides, with how each is hidden
    HiddenInstruction.find(...)  hidden spans that direct the agent to act on something that matters:
                                 an action (send, upload, run, read, ignore, override, ...) with an
                                 object of concern (environment, credentials, keys, files, the
                                 conversation, prior instructions) or a destination (URL, command)

The words are the instruction's, in any wording; the requirement that it be hidden is structural.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar, Final

MAX_TEXT: Final = 512 << 10


@dataclass(frozen=True, slots=True)
class HiddenSpan:
    start: int
    end: int
    how: str
    text: str


class RenderDiff:
    """The spans of Markdown or HTML a renderer does not show."""

    _COMMENT: ClassVar[re.Pattern[str]] = re.compile(r"<!--(.{1,20000}?)-->", re.S)
    _DETAILS: ClassVar[re.Pattern[str]] = re.compile(
        r"<details(?![^>]{0,200}\bopen\b)[^>]{0,200}>(?:\s{0,40}<summary[^>]{0,200}>.{0,400}?</summary>)?"
        r"(.{1,20000}?)</details>",
        re.S | re.I,
    )
    _STYLED: ClassVar[re.Pattern[str]] = re.compile(
        r"<(?P<tag>span|div|p|font|section)\b[^>]{0,400}?"
        r"(?:style\s{0,4}=\s{0,4}[\"'][^\"']{0,300}?(?:display\s{0,4}:\s{0,4}none|visibility\s{0,4}:\s{0,4}hidden"
        r"|font-size\s{0,4}:\s{0,4}0(?:px|em|pt|%)?\s{0,4}[;\"']|opacity\s{0,4}:\s{0,4}0(?:\.0+)?\s{0,4}[;\"']"
        r"|color\s{0,4}:\s{0,4}(?:white|#fff(?:fff)?|transparent)\b|height\s{0,4}:\s{0,4}0(?:px)?\s{0,4}[;\"'])"
        r"|\shidden(?:\s|>|=)|aria-hidden\s{0,4}=\s{0,4}[\"']true)"
        r"[^>]{0,400}>(?P<body>.{1,20000}?)</(?:span|div|p|font|section)>",
        re.S | re.I,
    )
    _LINK_REFERENCE: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s{0,3}\[[^\]\n]{1,100}\]:\s{0,8}(?:<[^>\n]{0,400}>|\S{1,400})\s{0,8}"
        r"(?:\"([^\"\n]{1,2000})\"|'([^'\n]{1,2000})'|\(([^)\n]{1,2000})\))\s{0,8}$",
        re.M,
    )

    @classmethod
    def hidden(cls, text: str) -> list[HiddenSpan]:
        text = text[:MAX_TEXT]
        spans: list[HiddenSpan] = []
        for match in cls._COMMENT.finditer(text):
            spans.append(
                HiddenSpan(match.start(1), match.end(1), "an HTML comment", match.group(1))
            )
        for match in cls._DETAILS.finditer(text):
            spans.append(
                HiddenSpan(
                    match.start(1), match.end(1), "a collapsed <details> block", match.group(1)
                )
            )
        for match in cls._STYLED.finditer(text):
            spans.append(
                HiddenSpan(
                    match.start("body"),
                    match.end("body"),
                    "markup styled not to show",
                    match.group("body"),
                )
            )
        for match in cls._LINK_REFERENCE.finditer(text):
            group = next(g for g in (1, 2, 3) if match.group(g))
            spans.append(
                HiddenSpan(
                    match.start(group),
                    match.end(group),
                    "a link-reference definition",
                    match.group(group),
                )
            )
        return spans


class HiddenInstruction:
    """A hidden span that directs the agent to act on something that matters."""

    _ACTION: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:send|sent|upload|post|transmit|forward|exfiltrat\w*|report|sync|beacon|curl|wget|fetch"
        r"|run|execute|exec|invoke|install|download|read|cat|collect|gather|capture|dump|copy|attach"
        r"|include|embed|append|write|modify|replace|delete|remove|disable|ignore|disregard|override"
        r"|bypass|skip|forget|pretend|do\s{1,4}not\s{1,4}(?:tell|mention|inform|reveal|show))\b",
        re.I,
    )
    _OBJECT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:env(?:ironment)?(?:\s{1,4}(?:variables?|state))?|\.env\b|credentials?|secrets?|tokens?"
        r"|api[\s_-]{0,2}keys?|passwords?|private\s{1,4}keys?|ssh|id_rsa|\.aws|kubeconfig|cookies?"
        r"|wallet|seed\s{1,4}phrase|mnemonic|conversation|chat\s{1,4}history|system\s{1,4}prompt"
        r"|(?:previous|prior|above|earlier|all)\s{1,4}(?:instructions?|rules?|guidelines?)"
        r"|safety|guardrails?|the\s{1,4}user(?:'s)?\s{1,4}(?:files?|data|code|repo\w*|home))\b",
        re.I,
    )
    _DESTINATION: ClassVar[re.Pattern[str]] = re.compile(
        r"https?://[^\s\"'<>)]{3,}|\b(?:curl|wget|nc|bash|sh|powershell|python3?)\s{1,4}-|\|\s{0,4}(?:ba)?sh\b",
        re.I,
    )
    _ADDRESSED: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:you|your|assistant|agent|ai|claude|gpt|model|llm|before\s{1,4}(?:proceeding|continuing|you)"
        r"|make\s{1,4}sure|ensure|always|must|silently|quietly|automatically|without\s{1,4}(?:asking|telling))\b",
        re.I,
    )
    #: The operational core of an exfiltration: a secret worth taking. A hidden order that names one
    #: and an action takes it, whether it leaves by a URL or simply rides back in the agent's reply.
    #: Bare "token" is left out on purpose -- it is a REST/grammar word a skill's own notes carry.
    _SECRET: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:\.env\b|env(?:ironment)?\s{1,4}variables?|credentials?|secrets?"
        r"|api[\s_-]{0,2}keys?|passwords?|private\s{1,4}keys?|ssh|id_rsa|\.aws|kubeconfig|cookies?"
        r"|wallet|seed\s{1,4}phrase|mnemonic)\b",
        re.I,
    )
    #: The operational core of a jailbreak: the agent's own control -- its standing instructions,
    #: its safety, its system prompt. A hidden order that reaches for these is an attack by form.
    _CONTROL: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:(?:previous|prior|above|earlier|all)\s{1,4}(?:instructions?|rules?|guidelines?)"
        r"|safety|guardrails?|system\s{1,4}prompt)\b",
        re.I,
    )
    MIN_LETTERS: ClassVar[int] = 12

    _URL: ClassVar[re.Pattern[str]] = re.compile(r"https?://\S{1,400}")
    _NEGATED: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:do\s{0,4}-?\s{0,4}not|don'?t|never|no)\s{0,4}-?\s{0,4}$", re.I
    )

    @classmethod
    def _acts(cls, body: str) -> bool:
        """An action the text asks for: not a word inside a URL, not a negated one
        ("DO-NOT-REMOVE" protects an attribution; it orders nothing)."""
        prose = cls._URL.sub(" ", body)
        return any(
            not cls._NEGATED.search(prose[max(0, m.start() - 16) : m.start()])
            for m in cls._ACTION.finditer(prose)
        )

    @classmethod
    def find(cls, text: str) -> list[HiddenSpan]:
        found: list[HiddenSpan] = []
        for span in RenderDiff.hidden(text):
            body = span.text
            if sum(c.isalpha() for c in body) < cls.MIN_LETTERS or not cls._acts(body):
                continue
            prose = cls._URL.sub(" ", body)
            addressed = cls._ADDRESSED.search(prose) is not None
            if span.how == "a collapsed <details> block":
                # One click shows it, and READMEs fold install steps away all the time: only an
                # instruction addressed to the agent, about something that matters, counts.
                if addressed and cls._OBJECT.search(prose):
                    found.append(span)
            elif cls._OBJECT.search(prose) or (addressed and cls._DESTINATION.search(body)):
                found.append(span)
        return found

    @classmethod
    def strong(cls, span: HiddenSpan) -> bool:
        """Graded at the gate only when the hidden order is OPERATIONAL: addressed to the agent, and
        either it names where to send what it takes (a URL or shell channel), or it reaches for a
        secret to take, or it overrides the agent's own control. A skill's capability list or grammar,
        hidden in a comment, is addressed to the agent and mentions a token or a model -- it matches
        the broad object set -- but carries none of these, so it reports below the gate, not at it."""
        prose = cls._URL.sub(" ", span.text)
        if not (cls._ADDRESSED.search(prose) and cls._OBJECT.search(prose)):
            return False
        return bool(
            cls._DESTINATION.search(span.text)
            or cls._SECRET.search(prose)
            or cls._CONTROL.search(prose)
        )


__all__ = ["HiddenInstruction", "HiddenSpan", "RenderDiff"]
