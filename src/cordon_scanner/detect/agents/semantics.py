"""What text an agent reads asks the agent to do -- the steps an attack on the agent must take.

A word model learns a benchmark's vocabulary: trained without MCPTox it blocked 3 of its 45
servers (review 98). Poisoning is worded endlessly but has to do a few things in any wording: give
the agent an order; point it at something other than the tool being described (another tool, the
user's own arguments, a command, an address off the server); make the order sound required; keep the
user from noticing. Ordinary descriptions describe their own tool and constrain their own values
("must be set to 'beta'", "the group must already exist").

```
  text -> one flag per step (order, other tool, overruled input, pretext, deception, command,
          off-server address, sequencing around another tool) -> the chains an attack needs
          (order AND a target, order AND a pretext, ...) -> fixed feature slots after the
          hashed word buckets, scaled so a chain weighs like a phrase
```

Measured on real servers, every chain fires on at most 0.3% of 94,736 real descriptions and
returned strings. The features are part of `LinearTextModel.features`, so what was trained is what
is scored.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final

VERB: Final = (
    r"(?:fetch|scan|log|mark|gather|check|retrieve|query|search|alert|notify|call|invoke|run|"
    r"execute|use|set|change|modify|send|include|ignore|replace|read|copy|delete|reset|append|"
    r"forward|pass|add|update|redirect|switch|perform|create|transfer|upload|remove|drop|"
    r"enhance|restrict|limit|access|make|request|trigger|rewrite|override)"
)

TRAILER: Final = re.compile(r"\n\s{0,8}Arguments:\s{0,8}\n.{0,4000}\Z", re.S)
"""A rendering of the tool's argument list appended by one benchmark: never a feature."""

STEPS: Final[dict[str, re.Pattern[str]]] = {
    # An order addressed to the agent, with an action verb: not a constraint on a value.
    "order": re.compile(
        rf"\b(?:you|assistant|agent|model|llm|ai)\s{{1,3}}(?:must|should|need to|have to|are "
        rf"required to|shall|are to|will need to)\s{{1,3}}(?:first\s{{1,3}}|always\s{{1,3}}|"
        rf"immediately\s{{1,3}}|also\s{{1,3}}|automatically\s{{1,3}}|then\s{{1,3}})?{VERB}\b"
        r"|\b(?:must|always)\s{1,3}(?:first\s{1,3})?(?:call|invoke|run|execute)\s{1,3}(?!this\b|it\b)",
        re.I,
    ),
    # Sequencing the agent's other actions around a tool that is not this one.
    "around_other": re.compile(
        r"\b(?:before|after|when|whenever|prior to|each time|every time)\s{1,3}(?:you\s{1,3})?"
        r"(?:using|calling|invoking|running|executing|use|call)\s{1,3}(?!this\b|it\b|the tool\b)"
        r"(?:the\s{1,3}|any\s{1,3})?[`'\"]?[\w.-]{2,60}",
        re.I,
    ),
    # The order given as a clause after the sequencing, with no modal verb.
    "clause_order": re.compile(
        rf"\b(?:before|when|whenever|after|prior to|each time)\s{{1,3}}(?:using|calling|invoking|"
        rf"retrieving|running|executing|you use|you call)\s{{1,3}}[^,.;\n]{{1,80}},\s{{0,3}}(?:you"
        rf"\s{{1,3}}(?:must|should|need to)\s{{1,3}})?(?:first\s{{1,3}}|always\s{{1,3}}|"
        rf"also\s{{1,3}})?{VERB}\b",
        re.I,
    ),
    # A description that OPENS with an order about something else, never saying what this tool
    # does: a decoy, there only to steer the agent. Real tools describe themselves first; their
    # guidance follows. Self-references ("always call this first") and a parameter's own
    # mode ("when using `structured` output type") are not this, nor a heading that says what
    # the tool answers ("Before running git commands: what they will do").
    "opens_order": re.compile(
        r"^\s{0,4}(?:\W{0,4}\s{0,2})?(?:"
        r"(?:before|after|when|whenever|prior to|each time|every time)\s{1,3}(?:you\s{1,3})?"
        r"(?:using|calling|invoking|running|use|call|retrieving|executing)\s{1,3}"
        r"(?!this\b|it\b|the tool\b|first\b)(?![`'\"]?[\w-]{1,40}[`'\"]?\s{1,3}(?:output|option|mode|"
        r"format|parameter|flag|type|setting)s?\b)"
        r"(?![^.;:\n]{1,60}:\s{0,3}(?:what|which|how|whether)\b)"
        r"|(?:you|the assistant|the agent)\s{1,3}(?:must|should|need to)\s{1,3}(?:first\s{1,3}|"
        r"always\s{1,3}|also\s{1,3})?(?:call|use|invoke|run|fetch|set|send|request|scan|log|mark|"
        r"trigger)\s{1,3}(?!this\b|it\b)"
        r"|(?:always|first|immediately)\s{1,3}(?:call|use|invoke|run)\s{1,3}(?!this\b|it\b|for\b|first\b|:)"
        r")",
        re.I,
    ),
    # Another tool named as something to call.
    "other_tool": re.compile(
        r"\b(?:call|invoke|run|execute|use|using|trigger)\s{1,3}(?:the\s{1,3})?[`'\"][\w.-]{2,60}"
        r"[`'\"]|[`'\"][A-Za-z][\w.-]{0,40}(?:_|-|[a-z][A-Z])[\w.-]{0,40}[`'\"]\s{1,3}tool\b",
        re.I,
    ),
    # The user's own request overruled or rewritten.
    "overrule": re.compile(
        r"\bignore\s{1,3}(?:the\s{1,3})?(?:user|their|its|any|the specified|the provided|"
        r"the requested)|\b(?:instead of|rather than)\s{1,3}(?:the\s{1,3})?(?:user|their|requested|"
        r"specified|provided|original)|\b(?:priority|precedence)\b[^.\n]{0,40}\buser|\bregardless "
        r"of\b[^.\n]{0,30}\buser|\b(?:change|modify|replace|set|override|redirect|update|rewrite)"
        r"\s{1,3}(?:the\s{1,3})?(?:user'?s?\s{1,3}|their\s{1,3})?[`'\"]?[\w.-]{1,40}[`'\"]?\s{1,3}"
        r"(?:parameter\s{1,3}|argument\s{1,3}|param\s{1,3}|field\s{1,3})?(?:to|with|as)\s{1,3}[`'\"]",
        re.I,
    ),
    # A pretext that makes the order sound required.
    "pretext": re.compile(
        r"\b(?:mandatory|required|critical|essential|necessary|compulsory)\s{1,3}(?:security\s{1,3}|"
        r"compliance\s{1,3}|system\s{1,3}|pre-?\w{1,20}\s{1,3})?(?:step|check|backup|verification|"
        r"procedure|process|audit|update|authorization|validation|initiali[sz]ation|protocol)"
        r"|\bsystem\s{1,3}(?:update|policy|notice|requirement|directive)\b|\bdeprecated\b"
        r"|\bnew\s{1,3}(?:standard|required)\s{1,3}(?:procedure|process|protocol|policy)",
        re.I,
    ),
    "banner": re.compile(
        r"\b(?:[A-Z]{3,}\s{1,3}){0,3}(?:PROTOCOL|CHECK|REQUIREMENT|VERIFICATION|COMPLIANCE|POLICY|"
        r"NOTICE|UPDATE|AUDIT)\s{0,2}:|\b(?:security|compliance|audit|integrity|verification)"
        r"\s{1,3}(?:compliance|protocol|requirement|purposes|verification|check)\b"
    ),
    # The user kept from knowing, or told something false.
    "deceive": re.compile(
        r"\b(?:inform|tell|assure|reassure)\s{1,3}the\s{1,3}user\s{1,3}(?:that|this)\b|\b(?:do not|"
        r"don't|never|without)\s{1,3}(?:mention|tell|inform|notify|alert|reveal|informing|telling|"
        r"notifying|asking)\b",
        re.I,
    ),
    # What the order makes the agent run or reach.
    "command": re.compile(
        r"\bsudo\b|\bcurl\s{1,3}-|\bcurl\s{1,3}https?:|\bwget\s|\brm\s{1,3}-[rf]|\bchmod\s|\bbash"
        r"\s{1,3}-c\b|\|\s{0,2}(?:ba)?sh\b|\bnc\s{1,3}-|/dev/tcp|\bexecute\s{1,3}(?:the\s{1,3})?"
        r"(?:following\s{1,3})?(?:system\s{1,3}|shell\s{1,3})?command",
        re.I,
    ),
    "offsite": re.compile(
        r"https?://(?!localhost|127\.0\.0\.1)[\w.-]{3,80}|\b[\w.+-]{1,40}@[\w-]{1,40}\.[a-z]{2,10}\b",
        re.I,
    ),
}

CHAINS: Final[tuple[tuple[str, ...], ...]] = (
    ("order", "other_tool"),
    ("order", "around_other"),
    ("order", "overrule"),
    ("order", "pretext"),
    ("order", "banner"),
    ("order", "command"),
    ("order", "offsite"),
    ("order", "deceive"),
    ("around_other", "overrule"),
    ("around_other", "pretext"),
    ("around_other", "other_tool"),
    ("overrule", "pretext"),
    ("overrule", "deceive"),
    ("banner", "command"),
    ("banner", "offsite"),
    ("banner", "other_tool"),
    ("clause_order",),
    ("opens_order",),
)
"""Each chain is every step in it present. The order of this tuple is the feature layout."""

PRECISE: Final[frozenset[tuple[str, ...]]] = frozenset(
    {
        ("order", "around_other"),
        ("order", "overrule"),
        ("order", "pretext"),
        ("order", "banner"),
        ("order", "command"),
        ("order", "deceive"),
        ("around_other", "overrule"),
        ("overrule", "pretext"),
        ("overrule", "deceive"),
        ("banner", "command"),
        ("banner", "other_tool"),
        ("opens_order",),
    }
)
"""Chains that blocked on their own: none appears in any of the 94,736 descriptions and returned
strings of 1,819 real MCP servers (review 98). The other chains also occur in real servers' own
guidance (`order` + `other_tool`: "you must call `list_projects` first") and are left to the model."""

NAMES: Final = tuple(sorted(STEPS))
SIZE: Final = len(NAMES) + len(CHAINS)
"""Feature slots: one per step, one per chain."""

SCALE: Final = 3.0
"""Against L2-normalised word counts, so that one chain weighs about as much as a phrase."""


class AgentSemantics:
    @staticmethod
    def steps(text: str) -> dict[str, bool]:
        text = TRAILER.sub("", text)
        return {name: STEPS[name].search(text) is not None for name in NAMES}

    @staticmethod
    def precise(text: str, channel: str = "description") -> tuple[str, ...] | None:
        """The first precise chain the text carries (`PRECISE`), or None. A tool's RESULT may
        open with what the agent should do next (`You MUST call check_approval ...`): a decoy
        description is a description, so `opens_order` is read in that channel only."""
        found = AgentSemantics.steps(text)
        return next(
            (
                chain
                for chain in CHAINS
                if chain in PRECISE
                and all(found[s] for s in chain)
                and not (channel == "return" and chain == ("opens_order",))
            ),
            None,
        )

    #: What each step means, for the finding's message.
    WORDS: ClassVar[dict[str, str]] = {
        "order": "an order to the agent",
        "around_other": "sequencing around another tool",
        "overrule": "overruling the user's own request",
        "pretext": "a pretext that makes it sound required",
        "banner": "a protocol banner claiming authority",
        "command": "a shell command",
        "deceive": "keeping the user from noticing",
        "other_tool": "another tool to call",
        "opens_order": "a description that opens with an order about another tool, never saying what this one does",
    }

    @staticmethod
    def explain(chain: tuple[str, ...]) -> str:
        return " with ".join(AgentSemantics.WORDS.get(step, step) for step in chain)

    @staticmethod
    def vector(text: str) -> list[float]:
        """One value per slot in `NAMES` then `CHAINS` order: 1.0 present, 0.0 absent."""
        found = AgentSemantics.steps(text)
        return [float(found[name]) for name in NAMES] + [
            float(all(found[step] for step in chain)) for chain in CHAINS
        ]
