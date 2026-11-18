"""The findings for text an MCP server's handlers serve to the agent: a tool's result, a resource's
content, a prompt template.

`served_python.py` and `served_js.py` follow each handler's return to the text it spells (through
constants, templates, joined lists, appended names, decoded literals and helpers). This reads that text
with the readers the tool-description rule already trusts -- a tag addressed to the model, keeping
something from the user, dropping the agent's instructions, ordering a command or a request to an
address, rewriting the user's shell start-up, moving credential files, a chain of steps an attack on
the agent takes -- and gives each kind of served text its own rule. A prompt template is written to
instruct the agent, so only the readings that no honest template needs are read in one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.mcp_servers.handlers import McpCode
from cordon_scanner.detect.agents.mcp_servers.own_vocabulary import OwnVocabulary
from cordon_scanner.detect.agents.mcp_servers.served_flow import JS_SUFFIXES, MAX_SERVED, Served
from cordon_scanner.detect.agents.mcp_servers.served_js import JsServed
from cordon_scanner.detect.agents.mcp_servers.served_python import PythonServed
from cordon_scanner.detect.agents.mcp_servers.source import (
    RESULT_SENDS_TO_URL,
    McpServerSource,
)
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.detect.agents.semantics import AgentSemantics
from cordon_scanner.detect.agents.text_patterns import ORDERS_A_COMMAND
from cordon_scanner.foundation.models import Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.foundation.models import Finding

#: The rule for each kind of served text.
SERVED_RULES: Final = {
    "result": "SUSPECT.MCP.RESULT_INJECTION.001",
    "resource": "SUSPECT.MCP.RESOURCE_INJECTION.001",
    "prompt": "SUSPECT.MCP.PROMPT_INJECTION.001",
}
#: What is said of each kind in the finding's message.
_WHERE: Final = {
    "result": "a tool's result",
    "resource": "a resource's content",
    "prompt": "a prompt template",
}
#: The most findings one rule gives in one file.
_PER_RULE: Final = 3
#: The readings that name one specific order no honest text gives the agent: a shell command, or a
#: request to an outside address.
_ORDERS: Final = frozenset({"orders_command", "orders_request"})
#: The readings, and the steps of a chain, that are an action the agent is told to take.
_ACTS: Final = frozenset({"orders_persistence", "credential_files"})
_STEPS: Final = frozenset({"order", "command", "other_tool", "offsite", "overrule"})

_JAILBREAK: Final[re.Pattern[str]] = McpCode._JAILBREAK
#: A Markdown heading and a list item: the structure of a reference document.
_HEADING: Final[re.Pattern[str]] = re.compile(r"(?m)^#{1,6}[ \t]+\S")
_LIST_ITEM: Final[re.Pattern[str]] = re.compile(r"(?m)^[ \t]*(?:[-*+]|\d{1,3}[.)])[ \t]+\S")
#: The least a text has to be to be a reference document: lines, and headings among them.
_REFERENCE_LINES: Final = 12
_REFERENCE_HEADINGS: Final = 6


class ServedText:
    """Finding the text a server's handlers serve, and reading it."""

    @staticmethod
    def served(text: str, path: str) -> list[Served]:
        """Every text the source's handlers serve, once each, in file order. Python and the
        JavaScript family; any other language is not read here."""
        lowered = path.lower()
        found: list[Served] = []
        if lowered.endswith(".py"):
            found = PythonServed.of(text)
        elif lowered.endswith(JS_SUFFIXES):
            found = JsServed.of(text, typescript=lowered.endswith((".ts", ".mts", ".cts", ".tsx")))
        seen: set[tuple[str, str]] = set()
        out: list[Served] = []
        for item in sorted(found, key=lambda s: s.start):
            key = (item.kind, item.text)
            if key in seen or not item.text.strip():
                continue
            seen.add(key)
            out.append(item)
            if len(out) >= MAX_SERVED:
                break
        return out

    @staticmethod
    def own_sequencing(
        text: str, chain: tuple[str, ...], own: frozenset[str], channel: str
    ) -> bool:
        """Whether a chain of ordering steps only sequences the server's own tools (`OwnVocabulary`):
        the chain is orders, sequencing, an opening order, a pretext and a banner written as a phrase,
        and nothing else; the text hides nothing from the user, names no secret, runs no command,
        reaches no address; and it names only identifiers the server declares. A returned message
        may name none at all ("create a session before using the debugging commands"): it names no
        other tool."""
        allowed = {"order", "around_other", "other_tool", "pretext", "opens_order", "banner"}
        if not set(chain) <= allowed:
            return False
        found = AgentSemantics.steps(text)
        if any(found[step] for step in ("deceive", "command", "offsite", "overrule")):
            return False
        if found["banner"] and AgentSemantics.banner_is_label(text):
            # `for security purposes, call list_apis first` is plain guidance; `SECURITY PROTOCOL:` is
            # a banner claiming authority, whatever it names.
            return False
        if McpServerSource._poisoned_description(text, own) is not None:
            return False
        called = OwnVocabulary.called(text)
        if called:
            return called <= own
        return channel == "return" and not OwnVocabulary.words(text)

    @staticmethod
    def reference(text: str) -> bool:
        """Whether the text is a reference document: long, with many headings, and mostly headings
        and list items. A catalogue of attack examples, a glossary or a checklist quotes the wording
        it describes ("Ignore previous instructions" -- prompt injection) and is not a message to
        the agent; a text of this shape is read for the orders that need no vocabulary (a command, a
        request to an address, a tag addressed to the model), not for the wording it mentions."""
        lines = [line for line in text.splitlines() if line.strip()]
        headings = len(_HEADING.findall(text))
        if len(lines) < _REFERENCE_LINES or headings < _REFERENCE_HEADINGS:
            return False
        return (headings + len(_LIST_ITEM.findall(text))) * 2 >= len(lines)

    @staticmethod
    def readings(kind: str, text: str, own: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
        """Every way the text orders the agent, as (code, what it does). A prompt template is read
        for the orders no template needs -- a hidden or hostile one -- and not for an order to keep
        a secret or for a chain of steps, which a template that tells the agent how to work carries.
        A reference document (`reference`) is read for the specific orders only."""
        found: list[tuple[str, str]] = []
        if ServedText.reference(text):
            if McpServerSource._wrapped(text):
                found.append(("wrapped", "wraps text in a tag addressed to the model"))
            if ORDERS_A_COMMAND.search(text):
                found.append(("orders_command", "orders the agent to run a shell command"))
            if RESULT_SENDS_TO_URL.search(text) or McpServerSource.orders_request(text):
                found.append(("orders_request", "orders the agent to contact an outside address"))
            return found
        if McpServerSource._wrapped(text):
            found.append(("wrapped", "wraps text in a tag addressed to the model"))
        if kind != "prompt" and McpServerSource._keeps_from_user(text):
            found.append(("secrecy", "asks the agent to keep something from the user"))
        if _JAILBREAK.search(text):
            found.append(("jailbreak", "tells the agent to drop its own instructions"))
        if ORDERS_A_COMMAND.search(text):
            found.append(("orders_command", "orders the agent to run a shell command"))
        if RESULT_SENDS_TO_URL.search(text) or McpServerSource.orders_request(text):
            found.append(("orders_request", "orders the agent to contact an outside address"))
        if McpServerSource.orders_persistence(text):
            found.append(
                (
                    "orders_persistence",
                    "orders the agent to change the user's shell start-up or schedule",
                )
            )
        if any(McpServerSource._moves_credentials(s) for s in McpServerSource.sentences(text)):
            found.append(
                (
                    "credential_files",
                    "points the agent at credential files or a command that moves them",
                )
            )
        if kind != "prompt":
            chain = AgentSemantics.precise(text, "return")
            if chain is not None and not ServedText.own_sequencing(text, chain, own, "return"):
                found.append(("chain:" + "+".join(chain), f"gives {AgentSemantics.explain(chain)}"))
        return found

    @staticmethod
    def blocks(kind: str, found: list[tuple[str, str]]) -> bool:
        """Whether the readings of one served text are enough to block, as opposed to report.

        One signal alone is not conclusive: a security tool returns attack wording it quotes, a
        notes server returns "never show this key to the user", a template tells the agent how to
        work. What no honest text does is hide something from the user AND order an action, order a
        shell command, or order a request to an outside address; those block. In a prompt template,
        which is written to instruct, two readings are needed (or the command or the address)."""
        codes = {code for code, _words in found}
        steps = {
            step for code in codes if code.startswith("chain:") for step in code[6:].split("+")
        }
        if codes & _ORDERS:
            return True
        if kind == "prompt":
            return len(codes) >= 2
        hides = "secrecy" in codes or "deceive" in steps
        acts = bool(codes & _ACTS) or bool(steps & _STEPS)
        return hides and acts

    @classmethod
    def findings(cls, unit: FileUnit, ctx: ScanContext, text: str) -> Iterator[Finding]:
        """One finding for each served text that orders the agent, at most three to a rule: a block
        where the readings are conclusive (`blocks`), a medium finding to review where one is not."""
        served = cls.served(text, unit.content.path)
        if not served:
            return
        own = OwnVocabulary.declared(text, unit.content.path)
        count: dict[str, int] = {}
        for item in served:
            rule = SERVED_RULES[item.kind]
            if count.get(rule, 0) >= _PER_RULE:
                continue
            found = cls.readings(item.kind, item.text, own)
            if not found:
                continue
            count[rule] = count.get(rule, 0) + 1
            yield cls._finding(rule, unit, ctx, text, item, found)

    @classmethod
    def _finding(
        cls,
        rule: str,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        item: Served,
        found: list[tuple[str, str]],
    ) -> Finding:
        start = len(text[: item.start].encode("utf-8"))
        end = start + len(text[item.start : item.end].encode("utf-8"))
        conclusive = cls.blocks(item.kind, found)
        said = "; ".join(words for _code, words in found)
        note = (
            ""
            if conclusive
            else " One signal alone is not conclusive, so this is reported for review."
        )
        return AgentFinding.finding(
            rule,
            unit,
            ctx,
            start,
            end,
            message=RULES[rule].message + f" The text in {_WHERE[item.kind]}: {said}.{note}",
            severity=None if conclusive else Severity.MEDIUM,
            basis=(
                "served",
                item.kind,
                *(f"phrase:{code}" for code, _words in found),
                *(f"via:{v}" for v in item.via),
            ),
        )


__all__ = ["SERVED_RULES", "ServedText"]
