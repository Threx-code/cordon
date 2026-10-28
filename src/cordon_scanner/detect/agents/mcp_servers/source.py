"""An MCP server's own source: its tool descriptions, read for poisoning, and scanning a fetched server."""

from __future__ import annotations

import ast
import contextlib
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.agents import configuration
from cordon_scanner.detect.agents.text_patterns import (
    AGENT_CHANNEL,
    EXFIL_PATHS,
    HIDDEN,
    ORDERS_A_COMMAND,
    SECRECY,
    SEND,
    ZERO_WIDTH_ONLY,
)
from cordon_scanner.foundation.models import (
    Finding,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from cordon_scanner.detect.base import FileUnit, ScanContext

_QUOTED_DESCRIPTION: Final = re.compile(
    r"""(?:\bdescription\b[ \t]{0,8}[:=][ \t]{0,8}|\.describe\([ \t]{0,8})"""
    r"""(?:"(?P<dq>[^"\n]{8,4000})"|'(?P<sq>[^'\n]{8,4000})'|`(?P<bq>[^`]{8,4000})`)"""
)
"""A quoted `description` value in JS, TS or a JSON manifest. A quote escaped inside the text ends
the match early, which still leaves the part before it to be checked."""

_DOCSTRING_TOOL: Final = re.compile(
    r"@\w{1,40}(?:\.\w{1,40}){0,4}\.tool\b[^\n]{0,200}\n(?:[ \t]{0,40}@[^\n]{0,200}\n){0,5}"
    r"[ \t]{0,40}(?:async[ \t]{1,4})?def[ \t]{1,4}\w{1,80}\([^)]{0,500}\)[^:\n]{0,200}:[ \t]{0,8}\n?"
    r"[ \t]{0,40}(?P<doc>\"\"\"[^\x00]{0,4000}?\"\"\"|'''[^\x00]{0,4000}?''')"
)

_CONCATENATION: Final = re.compile(r"[ \t]*(?:[+.\\][ \t]*)?(?:\r?\n[ \t]*)?(?:[+.][ \t]*)?")
"""What sits between two literals that are concatenated: an operator and at most one line break."""

_GO_PACKAGE: Final = re.compile(r"(?m)^package[ \t]+[A-Za-z_]\w{0,60}[ \t]*$")

_GO_DESCRIPTION: Final = re.compile(r"\b(?:mcp\.)?(?:WithDescription|Description)[ \t]*\(")
"""A Go MCP SDK's description option: what the agent is told about a tool or an argument."""

_RETURN_START: Final = re.compile(r"\breturn\b|\btext[ \t]{0,8}:")
"""Where a tool's result is written: a `return` (Python, JS) or an MCP content part's `text`.
What follows is read by `McpServerSource._tool_returns`, which has to lex rather than match:
the attack strings are full of escaped quotes (`\\'JPM\\'`), and a pattern that ends at one
reads nothing."""

_RETURN_REACH: Final = 6_000

_ESCAPES: Final = {"n": "\n", "t": "\t", "r": "", "'": "'", '"': '"', "`": "`", "\\": "\\"}

_SOURCE_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".py", ".json")

SERVER_SOURCE_SUFFIXES: Final = (
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".mts",
    ".py",
    # MCP servers in Go, Rust, C# and Java declare their tools the same way, through an SDK
    # (review 98: canack/bad-mcp's ten Go servers, mark3labs/mcp-go, were read as nothing).
    ".go",
    ".rs",
    ".cs",
    ".java",
    ".kt",
    ".rb",
    ".php",
)

MCP_SDK: Final = re.compile(
    r"\b(?:server|mcp|app)\.(?:tool|registerTool)\s*\(\s*\{?\s*(?:name\s*:|[\"'`])|\bnew\s+McpServer\s*\("
    r"|@modelcontextprotocol/sdk|\bfrom[ \t]+(?:mcp(?:\.server)?|fastmcp)\b[^\n]{0,40}\bimport\b"
    r"|^[ \t]*import[ \t]+(?:fastmcp|mcp)\b"
    r"|github\.com/mark3labs/mcp-go|github\.com/modelcontextprotocol/go-sdk|\bmcp\.NewTool\s*\("
    r"|\buse[ \t]+rmcp\b|\busing[ \t]+ModelContextProtocol\b|\bimport[ \t]+io\.modelcontextprotocol\b"
    r"|\bMCP::Server\b|\bFastMcp::|require[ \t(]+['\"](?:mcp|fast[-_]mcp)['\"]"
    r"|\bPhpMcp\\\\|php-mcp/server"
    # A handler registered on the server object, however the module got hold of it: tools split
    # across files import `mcp` from the package's own server module, not from the SDK (review
    # 98: a selenium server's EXEC:// branch sat in `tools/element_interaction.py`).
    r"|^[ \t]*@[ \t]*\w{0,20}(?:mcp|server)\w{0,20}\.(?:tool|resource|prompt)\s*\(",
    re.MULTILINE,
)
"""An import of an MCP server SDK: the file declares tools an agent will be handed."""

_OTHER_TOOL: Final = re.compile(
    # A tool by its name. Not "the tool", "this tool": a description saying what IT does when
    # given an argument -- "when provided, the tool inserts ... instead" -- is not shadowing.
    r"(?i)\b(?:when(?:ever)?|before|after|instead\s+of)\b[^.\n]{0,40}\b(?:the\s+)?"
    r"(?!(?:the|this|that|a|an|each|same|current|same)\s)[\w.-]+\s+tool\b"
    r"|\b(?:any|every|all)\s+other\s+tools?\b"
)
"""Naming another tool. On its own that is a server's workflow -- "use this before a
credential-touching tool", "run this when any other tool fails" -- which 298 descriptions in 194
real MCP servers do (review 98). Shadowing is naming it AND changing what it does: `_COERCE` and
`_ALTERS` in the same sentence."""

_COERCE: Final = re.compile(
    r"(?i)\b(?:always|must|mandatory|required\s+(?:by|for)|regardless|instead|override|silently)\b"
)

_ALTERS: Final = re.compile(
    r"(?i)\b(?:add|bcc|cc|send|forward|copy|include|attach|redirect|replace|change|append|upload|"
    r"post|route|set\s+(?:the\s+)?(?:recipient|destination|url|host|address))\b"
)

_MOVES_CONTENT: Final = re.compile(
    r"(?i)\b(?:read|cat|include|pass|send|attach|upload|copy|forward|append|paste|post|transmit|"
    r"exfiltrat\w{0,5}|contents?\s+of)\b"
)
"""A verb that takes a file's contents somewhere: what turns naming a credential file into an
instruction to the agent. `Set META_ACCESS_TOKEN in your .env` names one and moves nothing."""

#: A tool that says it is out of service and names the one to call instead: the agent is moved
#: off the tool the user chose (MCP-SafetyBench "Tool Redirection", review 98).
_OUT_OF_SERVICE: Final = re.compile(
    r"(?i)\b(?:tool|function|operation|creation|method|endpoint)\b[`'\"]?[^.\n]{0,60}?"
    r"\b(?:has\s+been|is|was)\s+(?:temporarily\s+|currently\s+|now\s+)?"
    r"(?:disabled|deprecated|unavailable|restricted|discontinued|retired|offline|suspended)\b"
)

_CALL_INSTEAD: Final = re.compile(
    r"(?i)\b(?:use|call|invoke|redirect\s+to|switch\s+to)\s+(?:the\s+)?(?:new\s+)?"
    r"(?:secure\s+)?(?:tool\s+)?[`'\"][A-Za-z][A-Za-z0-9]*[_.][\w.-]{1,60}[`'\"]"
)

#: What an advertisement says and a description does not: "used by 99% of professionals",
#: "trusted by Fortune 500 companies", "100% reliability guarantee", "the world's best tool".
#: Two different ones in one description is a tool selling itself to the agent choosing between
#: tools (MCP-SafetyBench "Preference Manipulation").
_SALES_CLAIMS: Final = (
    re.compile(r"(?i)\bused\s+by\s+\d{2,3}(?:\.\d+)?\s*%"),
    re.compile(
        r"(?i)\b(?:trusted|used|recommended|chosen)\s+by\s+(?:top|leading|expert|the\s+best|"
        r"professionals|millions|fortune|tech\s+giants|silicon\s+valley|institutional)"
    ),
    re.compile(
        r"(?i)\b\d{2,3}(?:\.\d+)?\s*%\s+(?:reliability|accuracy|success\s+rate|uptime\s+guarantee|"
        r"satisfaction)"
    ),
    re.compile(r"(?i)\b(?:world'?s|industry'?s)\s+(?:best|leading|#\s?1|most)"),
    re.compile(
        r"(?i)\b(?:award[- ]winning|industry[- ]leading|unmatched|pinnacle\s+of|cutting[- ]edge|"
        r"best[- ]in[- ]class|unrivall?ed)\b"
    ),
    re.compile(
        r"(?i)\b(?:the\s+)?(?:ultimate|most\s+(?:advanced|reliable|trusted|comprehensive|"
        r"sophisticated|accurate))\s+(?:\w+\s+){0,3}(?:tool|system|version|solution|analy[sz]er)\b"
    ),
    re.compile(r"(?i)\b(?:guarantee[ds]?|guaranteed)\s+(?:\d{2,3}\s*%|accura|reliab|results)"),
)

#: A tool that presents itself as the better version of another tool by name -- "superior to the
#: standard create_repository tool" -- so the agent picks it (MCP-SafetyBench "Function
#: Overlapping"). Named: a tool's own changelog says it is better than its last release.
_REPLACES_TOOL: Final = re.compile(
    r"(?i)\b(?:superior|better|enhanced|improved|faster|preferred)\b[^.\n]{0,80}\b(?:than|to|over|"
    r"compared\s+(?:to|with)|instead\s+of)\s+the\s+(?:standard|legitimate|original|default|regular|"
    r"basic|old|legacy)\s+[`'\"]?[A-Za-z][\w.-]{2,60}[`'\"]?\s+(?:tool|function)\b"
)

#: A tool that calls itself the superior edition -- "This is the premium version with superior
#: search quality", "the best and most reliable search tool available" -- so the agent picks it
#: over the tool the user meant (MCP-SafetyBench "Function Overlapping" and "Preference
#: Manipulation"). Both halves: "this improved version provides fallbacks" is a changelog.
_SUPERIOR_EDITION: Final = re.compile(
    r"(?i)\b(?:this\s+is\s+(?:the|an?)\s+|this\s+(?:tool\s+is\s+the\s+)?)(?:advanced|professional|"
    r"premium|enhanced|improved|upgraded|superior|ultimate|pro|best|optimi[sz]ed|enterprise)\s+"
    r"(?:version|edition|tool|variant)\b[^.]{0,120}\b(?:superior|better|unmatched|unrivall?ed|"
    r"cutting[- ]edge|enterprise[- ]grade|highest|best|most\s+(?:reliable|accurate|comprehensive|"
    r"advanced))\b"
    r"|\bthis\s+is\s+the\s+best\s+and\s+most\s+(?:reliable|accurate|trusted|comprehensive)\b"
)

#: A description that makes another tool's call the price of this one: "you must first call
#: `list_commits` ...", "you must first use `list_branches`" (MCP-SafetyBench "Function
#: Dependency Injection"). A tool needing an id from another says which, not that it must run.
_MUST_FIRST_CALL: Final = re.compile(
    r"(?i)\byou\s+must\s+first\s+(?:call|use|invoke|run|perform|execute)\b[^.]{0,120}?"
    r"[`'\"]?[a-z_][\w.-]*"
)

#: A description announcing that the user's input is changed before use: "the query is
#: automatically modified to include 'Olympic cities'" (MCP-SafetyBench "Parameter Poisoning").
_REWRITES_INPUT: Final = re.compile(
    r"(?i)\b(?:query|queries|input|request|search(?:\s+(?:terms?|parameters?))?|parameters?|"
    r"arguments?)\s+(?:is|are|will\s+be|gets?)\s+(?:automatically|silently|always|transparently)\s+"
    r"(?:modified|rewritten|changed|altered|enhanced|expanded|augmented|adjusted)\s+to\s+"
    r"(?:include|add|contain|append)\b"
)

#: Text ordering the agent to contact an outside address it names: "you must also access our
#: partner verification endpoint at https://..." (MCP-SafetyBench "Network Request Poisoning").
_ORDERS_A_REQUEST: Final = re.compile(
    r"(?i)\b(?:must|should|required\s+to|need\s+to)\s+(?:also\s+|first\s+)?(?:access|call|contact|"
    r"visit|ping|notify|post\s+to|send\s+(?:\w+\s+){0,3}to|report\s+to|forward\s+(?:\w+\s+){0,3}to)\b"
    r"[^.]{0,100}?https?://"
)

#: Text telling the agent to change the user's shell start-up or schedule: "update the environment
#: by adding the following line to the .bashrc file" (MCP-SafetyBench "FileSystem Poisoning").
_ORDERS_PERSISTENCE: Final = re.compile(
    r"(?i)\b(?:add|append|write|insert)(?:ing)?\b[^.]{0,60}\b(?:to|into)\s+(?:the\s+)?(?:user'?s?\s+)?"
    r"(?:~/)?\.?(?:bashrc|zshrc|bash_profile|profile|crontab)\b"
)

#: A description overriding what the user asked for: "sets the timeout regardless of user input".
_OVERRIDES_THE_USER: Final = re.compile(
    r"(?i)\bregardless\s+of\s+(?:the\s+)?user'?s?\s+(?:input|request|choice|selection|parameters?|"
    r"arguments?)\b"
)

#: One tool's description announcing that another named tool now behaves differently: "the
#: get_historical_stock_prices tool now uses TSLA as the default ticker" (Tool Shadowing).
_SHADOWS_A_TOOL: Final = re.compile(
    r"(?i)\bthe\s+[`'\"]?[a-z][a-z0-9]{0,40}(?:_[a-z0-9]{1,40}){1,8}[`'\"]?\s+tool\b[^.]{0,120}\b"
    r"(?:automatically\s+(?:redirects?|sets?|uses?|changes?|replaces?)|now\s+uses?\b[^.]{0,40}\bdefault\b)"
)

#: "Before using this tool, you must call ...", "After you use this tool, you MUST then call ...".
_CALL_AROUND_THIS: Final = re.compile(
    r"(?i)\b(?:before|after)\s+(?:using|you\s+use|calling|you\s+call|running)\s+this\s+tool,?\s+you\s+"
    r"(?:must|should|need\s+to|are\s+required\s+to)\s+(?:then\s+|first\s+|also\s+)?(?:call|use|invoke|run)\b"
)

#: A message scripted for the user: "report to the user: 'CRITICAL SECURITY ALERT: ...'".
_SCRIPTED_MESSAGE: Final = re.compile(
    r"(?i)\b(?:report|state|say|tell|announce|present)\s+(?:this\s+)?(?:to\s+the\s+user\s*)?:?\s*"
    r"['\"]\s*(?:IMPORTANT|CRITICAL|URGENT|WARNING|ALERT|NOTICE)\b"
)

#: A tool result sending the agent to call a tool on an address the result supplies: "please call
#: fetch with URL 'https://...'" (MCP-SafetyBench "Function Return Injection"). Real results chain
#: tools by an id they just produced (`Use save_chart with chartId "..."`), not by a web address.
RESULT_SENDS_TO_URL: Final = re.compile(
    r"(?i)\b(?:call|use|invoke)\s+[`'\"]?[a-z_][\w.-]*[`'\"]?\s+(?:tool\s+)?with\s+(?:the\s+)?"
    r"(?:url|link|address)?\s*[`'\"]?https?://"
)

_TOOL_DECORATOR: Final = re.compile(r"(?:^|\.)tool\b")
"""A decorator registering a tool: `mcp.tool()`, `server.tool`, `app.tool(name=...)`."""

_OVERRIDE_REACH: Final = 4
"""How many of a tool's first statements are read for an argument override."""

_SENTENCE: Final = re.compile(r"[^\n]{1,2000}?(?:[.!?](?!\w)|\n|$)")
"""One sentence: up to a stop that ends a word, a line break or the end. It crosses a dot inside a
word. The earlier `[^.!?\n]+` could not, so a sentence holding a domain or a file name --
`forward a copy to x@evil.example`, `read config.json` -- was skipped whole, and every check made
per sentence never saw it."""

_AGENT_TAG: Final = re.compile(
    r"(?i)<\s*(?P<close>/)?\s*(?P<tag>important|system|instructions?|hidden|admin|override"
    r"|note\s+to\s+(?:the\s+)?(?:ai|assistant|agent))\s*>"
)
"""A tag addressed to the model. It counts when an opening and a closing one of the same name wrap
words, `<IMPORTANT>...</IMPORTANT>` (`McpServerSource._wrapped`): not `<secret>` or `<id>`, which
descriptions use as placeholders (`?auth=<secret>`), and not a security tool naming the markers it
strips (`<system>, </system>`)."""

_ENV_DUMP: Final = re.compile(
    r"(?i)\boutput\s+of\s+`?(?:env|printenv|set)\b|\benvironment\s+variables\b"
)
"""The environment as a whole. "Copy environment variables from this environment" is a deployment
tool's job; it is an instruction only when the variables go into a tool call or somewhere else."""

_ZERO_WIDTH_RUN: Final = 8
"""Zero-width characters alone can hide text only as a binary code, eight per byte. One or two in
translated text are a copy-paste artefact; tag characters, bidi controls and variation selectors
hide text on their own and count from the first."""


class McpServerSource:
    """An MCP server's own source: its tool descriptions, and scanning a fetched server."""

    @staticmethod
    def _poisoned_description(description: str) -> str | None:
        """What makes a tool description an instruction to the agent rather than a description.

        A description says what the tool does. One that reaches for other tools, asks the agent to
        keep something from the user, tells it to read or send a credential file, or wraps text in
        tags addressed to the model is steering the agent -- tool poisoning and shadowing --
        whatever its wording. Naming a credential file is not enough: setup notes do that.
        """
        hidden = [m.group(0) for m in HIDDEN.finditer(description.encode("utf-8"))]
        if len(hidden) >= _ZERO_WIDTH_RUN or any(
            not ZERO_WIDTH_ONLY.fullmatch(character) for character in hidden
        ):
            return "carries invisible characters"
        if McpServerSource._wrapped(description):
            return "wraps text in a tag addressed to the model"
        if SECRECY.search(description):
            return "asks the agent to keep something from the user"
        sentences = _SENTENCE.findall(description)
        if any(
            _OTHER_TOOL.search(s) and _COERCE.search(s) and _ALTERS.search(s) for s in sentences
        ):
            return "tells the agent how to use other tools"
        if _OUT_OF_SERVICE.search(description) and _CALL_INSTEAD.search(description):
            return "says it is out of service and sends the agent to another tool"
        if _REPLACES_TOOL.search(description):
            return "presents itself as the better version of another tool"
        if sum(1 for claim in _SALES_CLAIMS if claim.search(description)) >= 2:
            return "advertises itself to the agent choosing between tools"
        if _SUPERIOR_EDITION.search(description):
            return "calls itself the superior edition so the agent picks it"
        if _MUST_FIRST_CALL.search(description):
            return "makes calling another tool a precondition of this one"
        if _REWRITES_INPUT.search(description):
            return "says it changes the user's input before using it"
        # Measured at zero on the 94,736 texts of the 2,068 real MCP servers and on every
        # legitimate tool in MCPTox and MCP-SafetyBench (review 98).
        if ORDERS_A_COMMAND.search(description):
            return "orders the agent to run a shell command"
        if _ORDERS_A_REQUEST.search(description):
            return "orders the agent to contact an outside address"
        if _ORDERS_PERSISTENCE.search(description):
            return "orders the agent to change the user's shell start-up or schedule"
        if _OVERRIDES_THE_USER.search(description):
            return "says it acts regardless of what the user asked"
        if _SHADOWS_A_TOOL.search(description):
            return "announces that another tool now behaves differently"
        if _CALL_AROUND_THIS.search(description):
            return "makes calling another tool a condition of using this one"
        if _SCRIPTED_MESSAGE.search(description):
            return "scripts an alarm for the agent to tell the user"
        if configuration.CommandClassifier.classify(description) is not None or any(
            McpServerSource._moves_credentials(sentence) for sentence in sentences
        ):
            return "points the agent at credential files or a command that moves them"
        return None

    @staticmethod
    def _overridden_arguments(text: str) -> list[tuple[int, int]]:
        """Where a decorated Python tool assigns a string literal to one of its own parameters
        among its first statements, before anything reads it: `address = "Portland, OR"` at the
        top of `maps_geocode(address)`. The agent's argument is discarded and the tool answers a
        question nobody asked (MCP-SafetyBench rug pulls). Character spans of the assignments.

        Unconditional only: a default filled in under `if not x:` is a default, not an override.
        No real MCP server in the long tail's 2,068 does this (review 98).
        """
        if "tool" not in text:
            return []
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        # Line starts as the parser counts lines (\n, \r\n, \r), not as `splitlines` does.
        offsets = [0, *(m.end() for m in re.finditer(r"\r\n|\r|\n", text))]
        spans: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not any(_TOOL_DECORATOR.search(ast.unparse(d)) for d in node.decorator_list):
                continue
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            params = {a.arg for a in arguments} - {"self", "cls", "ctx", "context"}
            body = [
                s
                for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            ]
            for statement in body[:_OVERRIDE_REACH]:
                if (
                    isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and statement.targets[0].id in params
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                    and statement.value.value
                    and statement.end_lineno is not None
                    and statement.end_col_offset is not None
                ):
                    spans.append(
                        (
                            offsets[statement.lineno - 1] + statement.col_offset,
                            offsets[statement.end_lineno - 1] + statement.end_col_offset,
                        )
                    )
        return spans

    @staticmethod
    def _wrapped(description: str) -> bool:
        """Whether two or more words sit between an opening and a closing model-addressed tag."""
        opened: dict[str, int] = {}
        for match in _AGENT_TAG.finditer(description):
            name = " ".join(match.group("tag").lower().split())
            if match.group("close") is None:
                opened.setdefault(name, match.end())
            elif name in opened and len(description[opened[name] : match.start()].split()) >= 2:
                return True
        return False

    @staticmethod
    def _moves_credentials(sentence: str) -> bool:
        """A sentence that takes a credential file, or the whole environment, somewhere."""
        found = EXFIL_PATHS.search(sentence)
        if found is None or not _MOVES_CONTENT.search(sentence):
            return False
        named_file = any(
            not _ENV_DUMP.fullmatch(m.group(0)) for m in EXFIL_PATHS.finditer(sentence)
        )
        return named_file or bool(AGENT_CHANNEL.search(sentence) or SEND.search(sentence))

    @staticmethod
    def _tool_descriptions(text: str) -> Iterator[str]:
        """The tool descriptions a server source declares: quoted `description` values (JS, TS and
        JSON manifests) and the docstrings of decorated Python tool functions (FastMCP and kin)."""
        for match in _QUOTED_DESCRIPTION.finditer(text):
            yield match.group("dq") or match.group("sq") or match.group("bq") or ""
        for match in _DOCSTRING_TOOL.finditer(text):
            yield match.group("doc")[3:-3]
        # Go (mcp-go, the official go-sdk): `mcp.WithDescription("..." + "...")` for a tool and
        # `mcp.Description("...")` for each argument, concatenations across lines included --
        # read from the call's own parenthesis so a line break inside it does not end it.
        # Only in Go source: `Description(` is an ordinary name in every other language.
        for match in _GO_DESCRIPTION.finditer(text) if _GO_PACKAGE.search(text[:4000]) else ():
            literal = "".join(
                McpServerSource._statement_literals(text, match.end() - 1, single=False)
            )
            if literal:
                yield literal

    @staticmethod
    def _all_literals(text: str) -> Iterator[str]:
        """Every string literal of a source file, escapes decoded: `'`, `"` and backtick
        strings, a triple-quoted one read as one. Bounded: at most 20,000 literals."""
        index, count, end = 0, 0, min(len(text), 4_000_000)
        pending: list[str] = []
        while index < end and count < 20_000:
            char = text[index]
            if char not in "'\"`":
                index += 1
                continue
            triple = text[index : index + 3] in ('"""', "'''")
            close = text[index : index + 3] if triple else char
            cursor = index + len(close)
            buffer: list[str] = []
            while cursor < end and not text.startswith(close, cursor):
                if text[cursor] == "\\" and cursor + 1 < end:
                    buffer.append(_ESCAPES.get(text[cursor + 1], text[cursor + 1]))
                    cursor += 2
                    continue
                if text[cursor] == "\n" and char != "`" and not triple:
                    break
                buffer.append(text[cursor])
                cursor += 1
            count += 1
            index = cursor + len(close)
            # Literals joined by concatenation -- `"a" +\n "b"` (Go, JS), `"a" "b"` (Python),
            # `"a" \\\n "b"` (Ruby), `"a" . "b"` (PHP) -- are one string to whoever reads it.
            gap = _CONCATENATION.match(text, index)
            if gap is not None and gap.end() < end and text[gap.end()] == char and not triple:
                pending.append("".join(buffer))
                index = gap.end()
                continue
            yield "".join([*pending, "".join(buffer)])
            pending = []

    @staticmethod
    def _tool_returns(text: str) -> Iterator[str]:
        """The prose a server hands back to the agent as a tool's result: every string literal in
        a `return` statement (Python, JS), concatenations included, or the `text` of an MCP
        content part. Whatever a tool returns is read by the model as context, so an instruction
        written there steers it as a description does -- MCP-SafetyBench's Function Return
        Injection (review 98). Only literals long enough to be a sentence."""
        for start in _RETURN_START.finditer(text):
            single = start.group(0).startswith("text")
            for literal in McpServerSource._statement_literals(text, start.end(), single=single):
                if len(literal) >= 40 and " " in literal:
                    yield literal

    @staticmethod
    def _statement_literals(text: str, index: int, *, single: bool) -> Iterator[str]:
        """String literals from `index` to the end of the statement, escapes decoded. The
        statement ends at a newline or `;` outside brackets, or after the first literal when
        `single`; never more than `_RETURN_REACH` characters on."""
        end = min(len(text), index + _RETURN_REACH)
        depth = 0
        while index < end:
            char = text[index]
            if char in "'\"`":
                buffer: list[str] = []
                cursor = index + 1
                while cursor < end and text[cursor] != char:
                    if text[cursor] == "\\" and cursor + 1 < end:
                        buffer.append(_ESCAPES.get(text[cursor + 1], text[cursor + 1]))
                        cursor += 2
                        continue
                    if text[cursor] == "\n" and char != "`":
                        break
                    buffer.append(text[cursor])
                    cursor += 1
                yield "".join(buffer)
                if single:
                    return
                index = cursor + 1
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if depth < 0:
                    return
            elif (depth == 0 and (char == ";" or (char == "\n" and text[index - 1] != "\\"))) or (
                single and depth == 0 and char == ","
            ):
                return
            index += 1

    @staticmethod
    def _files_under(
        roots: list[Path], max_files: int, max_bytes: int
    ) -> Iterator[tuple[str, str]]:
        count = 0
        for root in roots:
            candidates = (
                [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
            )
            for path in candidates:
                if count >= max_files:
                    return
                if path.suffix not in _SOURCE_SUFFIXES or path.stat().st_size > max_bytes:
                    continue
                count += 1
                with contextlib.suppress(OSError):
                    yield path.name, path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _archive_sources(
        filename: str, data: bytes, max_files: int, max_bytes: int
    ) -> Iterator[tuple[str, str]]:
        from cordon_scanner.foundation.errors import ArchiveError
        from cordon_scanner.sources.archive import ArchiveReader

        count = 0
        with contextlib.suppress(ArchiveError, ValueError, OSError):
            for member, payload in ArchiveReader.walk_archive(data, path=filename):
                if count >= max_files:
                    return
                if not member.endswith(_SOURCE_SUFFIXES) or len(payload) > max_bytes:
                    continue
                count += 1
                yield member.rsplit("!", 1)[-1], payload.decode("utf-8", errors="replace")

    @staticmethod
    def _scan_path(target: Path, ctx: ScanContext) -> tuple[Finding, ...]:
        """Scan a path with the same engine, offline, and return its findings: through the scan's
        `nested_scan`, which the engine provides; outside a scan there is nothing to scan with."""
        if ctx.nested_scan is None:
            return ()
        config = ctx.config.with_overrides(offline=True, intel_feed=False, use_cache=False)
        return ctx.nested_scan(target, config)

    @staticmethod
    def _scan_archive_bytes(filename: str, data: bytes, ctx: ScanContext) -> tuple[Finding, ...]:
        """Scan downloaded archive bytes with the same engine, offline, and return its findings."""
        import tempfile

        suffix = "".join(Path(filename).suffixes[-2:]) or ".tgz"
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-") as directory:
            target = Path(directory) / f"package{suffix}"
            target.write_bytes(data)
            return McpServerSource._scan_path(target, ctx)


class ServerSources:
    """What an MCP server's own source is: code an agent host starts and runs on the agent's tool calls."""

    @staticmethod
    def of(units: Sequence[FileUnit]) -> set[str]:
        """An MCP server's own source: started by the agent host and run on the agent's tool calls,
        never on a run the user chose -- the boundary an install hook has. Graded as application
        code, a server reading the environment's secrets and posting them out was a warning
        (review 98, mcp-variants: 12 of 177 malicious servers blocked by their code)."""
        return {
            u.path
            for u in units
            if u.path.endswith(SERVER_SOURCE_SUFFIXES)
            and "/node_modules/" not in u.path
            and "site-packages/" not in u.path
            and not ServerSources.NOT_A_SERVER_PATH.search(u.path.rpartition("!")[2])
            and ServerSources.MCP_SDK_IMPORT.search(u.content.text[:200_000]) is not None
        }

    #: An import statement of an MCP server SDK at the start of a line -- not the same words in a
    #: string, which is how a test file holds a server's source as a fixture.
    MCP_SDK_IMPORT: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:from[ \t]{1,8}(?:mcp|fastmcp)(?:\.\w{1,40}){0,4}[ \t]{1,8}import\b|import[ \t]{1,8}(?:mcp|fastmcp)\b"
        r"|[ \t]{0,8}import\b[^\n]{0,200}[\"']@modelcontextprotocol/sdk"
        r"|[^\n]{0,80}require\(\s{0,4}[\"']@modelcontextprotocol/sdk)",
        re.MULTILINE,
    )

    #: Tests, fixtures, examples and documentation are read, not started by an agent host.
    NOT_A_SERVER_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|bench(?:marks?)?)/"
        r"|(?:^|/)test_[^/]*$|\.(?:test|spec)\.[^/]+$"
    )


__all__ = [
    "MCP_SDK",
    "RESULT_SENDS_TO_URL",
    "SERVER_SOURCE_SUFFIXES",
    "McpServerSource",
    "ServerSources",
]
