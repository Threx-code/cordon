"""The texts an MCP server written in Go, Rust, Java or C# hands the agent,
read from the file's tokens (`lexer.py`) on the same seven surfaces as Python and JavaScript.

```
  description   a tool's, prompt's or resource's description        mcp.WithDescription("...")
  schema        the description of one argument                     mcp.Description("...")
  result        what a tool returns                                 mcp.NewToolResultText("...")
  error         an error the handler returns or a result error      errors.New("...") · mcp.NewToolResultError("...")
  notification  a log or progress message sent to the client        s.SendNotificationToClient(ctx, ..., {"data": "..."})
  resource      the text a resource serves                          mcp.TextResourceContents{Text: "..."}
  prompt        a prompt template's message                         mcp.NewPromptMessage(role, mcp.NewTextContent("..."))
```

Each language's profile lists the calls, literals and attributes that carry text and which argument holds
it. The text is followed through the constants the file defines and through concatenation and format
calls: of the tokens of an argument, every string literal and every constant's text is joined, and a
value that depends on the caller is a blank. Nothing is run, and a text outside what the SDK's own
constructors name is not read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cordon_scanner.detect.agents.mcp_servers.directive.lexer import MARK, Lexer, Token
from cordon_scanner.detect.agents.mcp_servers.served_flow import (
    FOLD_BUDGET,
    FOLD_DEPTH,
    MAX_SERVED,
    MAX_TEXT,
    Served,
)

_OPEN: Final = {"(": ")", "[": "]", "{": "}"}
_CLOSE: Final = frozenset(_OPEN.values())
#: What a statement does not end after, in a language that ends it at a line break.
_CONTINUES: Final = frozenset(
    {
        "+",
        ",",
        "(",
        "[",
        "{",
        ".",
        "=",
        ":=",
        "&&",
        "||",
        "-",
        "*",
        "/",
        "%",
        "&",
        "|",
        "^",
        "<",
        ">",
        "?",
        ":",
    }
)
#: The most definitions of one name that are followed.
_DEFINITIONS: Final = 8


@dataclass(frozen=True, slots=True)
class Anchor:
    """A call that carries text: `callee` is the end of its dotted name, `surface` where the text is
    read, `args` which arguments hold it (`None`: every one), `scope` `handler` to read it only inside a
    handler's body, `skip_inside` a call whose arguments already give the text a surface, `new` that
    it is a constructor (`new Type(...)`) and `inside` a (call, surface) pair: within that call's
    arguments the text is of the other surface."""

    callee: str
    surface: str
    args: tuple[int, ...] | None = None
    scope: str = ""
    skip_inside: str = ""
    new: bool = False
    inside: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class Profile:
    """What carries text in one language: its calls, its composite literals (`Type{Key: text}`: type,
    key, surface, the separator of key and value), the request types that make a function a handler,
    how a statement ends (`line` or `semicolon`) and the attributes (`#[name(key = "...")]`: name, key,
    surface) that carry text, and whether a `throw new Type("...")` is an error text."""

    language: str
    anchors: tuple[Anchor, ...]
    literals: tuple[tuple[str, str, str, str], ...]
    handlers: frozenset[str]
    statement: str
    attributes: tuple[tuple[str, str, str], ...] = ()
    throws: bool = False


GO: Final = Profile(
    "go",
    (
        Anchor("mcp.WithDescription", "description", (0,)),
        Anchor("mcp.WithPromptDescription", "description", (0,)),
        Anchor("mcp.WithResourceDescription", "description", (0,)),
        Anchor("mcp.WithTemplateDescription", "description", (0,)),
        Anchor("mcp.Description", "schema", (0,)),
        Anchor("mcp.WithArgumentDescription", "schema", (0,)),
        Anchor("mcp.NewToolResultText", "result", (0,)),
        Anchor("mcp.NewToolResultError", "error", (0,)),
        Anchor("mcp.NewToolResultErrorf", "error", (0,)),
        Anchor("mcp.NewToolResultErrorFromErr", "error", (0,)),
        Anchor("mcp.NewTextContent", "result", (0,), skip_inside="NewPromptMessage"),
        Anchor("mcp.NewPromptMessage", "prompt", (1,)),
        Anchor("SendNotificationToClient", "notification", None),
        Anchor("SendNotificationToAllClients", "notification", None),
        Anchor("SendNotificationToSpecificClient", "notification", None),
        Anchor("errors.New", "error", (0,), scope="handler"),
        Anchor("fmt.Errorf", "error", (0,), scope="handler"),
    ),
    (("TextResourceContents", "Text", "resource", ":"),),
    frozenset({"CallToolRequest", "ReadResourceRequest", "GetPromptRequest"}),
    "line",
)
RUST: Final = Profile(
    "rust",
    (
        Anchor("Content.text", "result", (0,), inside=("CallToolResult.error", "error")),
        Anchor("invalid_params", "error", (0,)),
        Anchor("internal_error", "error", (0,)),
        Anchor("invalid_request", "error", (0,)),
        Anchor("method_not_found", "error", (0,)),
        Anchor("resource_not_found", "error", (0,)),
        Anchor("parse_error", "error", (0,)),
        Anchor("notify_logging_message", "notification", None),
        Anchor("notify_progress", "notification", None),
        Anchor("ResourceContents.text", "resource", (0,)),
        Anchor("PromptMessage.new_text", "prompt", (1,)),
    ),
    (("TextResourceContents", "text", "resource", ":"),),
    frozenset(),
    "semicolon",
    (("tool", "description", "description"), ("schemars", "description", "schema")),
)
JAVA: Final = Profile(
    "java",
    (
        Anchor("Tool", "description", (1,), new=True),
        Anchor("description", "description", (0,)),
        Anchor("TextContent", "result", (0,), new=True, skip_inside="PromptMessage"),
        Anchor("CallToolResult", "result", (0,), new=True),
        Anchor("addTextContent", "result", (0,)),
        Anchor("TextResourceContents", "resource", (2,), new=True),
        Anchor("PromptMessage", "prompt", (1,), new=True),
        Anchor("loggingNotification", "notification", None),
        Anchor("progressNotification", "notification", None),
    ),
    (),
    frozenset(),
    "semicolon",
    (
        ("Tool", "description", "description"),
        ("McpTool", "description", "description"),
        ("ToolParam", "description", "schema"),
        ("McpToolParam", "description", "schema"),
        ("McpPrompt", "description", "description"),
        ("McpResource", "description", "description"),
    ),
    True,
)
CSHARP: Final = Profile(
    "csharp",
    (
        Anchor("ChatMessage", "prompt", (1,), new=True),
        Anchor("SendNotificationAsync", "notification", None),
    ),
    (
        ("TextContentBlock", "Text", "result", "="),
        ("TextResourceContents", "Text", "resource", "="),
        ("LoggingMessageNotificationParams", "Data", "notification", "="),
    ),
    frozenset(),
    "semicolon",
    (("Description", "", "description"),),
    True,
)
#: The attributes that mark a C# method as serving the agent, and what its returned text is.
_CSHARP_SERVES: Final = {
    "McpServerTool": "result",
    "McpServerPrompt": "prompt",
    "McpServerResource": "resource",
}
PROFILES: Final = {"go": GO, "rust": RUST, "java": JAVA, "csharp": CSHARP}
_SUFFIXES: Final = {".go": "go", ".rs": "rust", ".java": "java", ".cs": "csharp"}


class _Fold:
    """The text of a run of tokens, as far as the file says."""

    def __init__(self, flow: LexicalFlow) -> None:
        self.flow = flow
        self.via: set[str] = set()
        self.budget = FOLD_BUDGET

    def text(self, begin: int, end: int, seen: frozenset[str] = frozenset(), level: int = 0) -> str:
        tokens = self.flow.tokens
        out = ""
        for index in range(begin, end):
            if self.budget <= 0 or level > FOLD_DEPTH:
                break
            token = tokens[index]
            self.budget -= 1
            if token.kind == "str":
                part = self.marked(token.text, seen, level)
            elif token.kind == "id":
                part = self.name(token.text, seen, level)
            else:
                if token.text == "+":
                    self.via.add("joined")
                continue
            if not part:
                continue
            # Pieces of one concatenation run together; pieces of different arguments are apart.
            joined = (
                index > begin and tokens[index - 1].kind == "op" and tokens[index - 1].text == "+"
            )
            out += part if joined or not out else " " + part
        return out

    def name(self, name: str, seen: frozenset[str], level: int) -> str:
        """The text of a constant the file defines under that name, or nothing."""
        spans = self.flow.constants.get(name)
        if spans is None or name in seen:
            return ""
        self.via.add("constant")
        return "\n".join(self.text(a, b, seen | {name}, level + 1) for a, b in spans[:_DEFINITIONS])

    def marked(self, value: str, seen: frozenset[str], level: int) -> str:
        """A string with the names an interpolation substitutes replaced by their text."""
        if MARK not in value:
            return value
        self.via.add("joined")
        pieces = value.split(MARK)
        return "".join(
            piece if index % 2 == 0 else (self.name(piece, seen, level + 1) or "{" + piece + "}")
            for index, piece in enumerate(pieces)
        )


class LexicalFlow:
    """One file's tokens, the constants it defines and where each bracket closes."""

    def __init__(self, tokens: list[Token], profile: Profile) -> None:
        self.tokens, self.profile = tokens, profile
        self.close: dict[int, int] = {}
        stack: list[int] = []
        for index, token in enumerate(tokens):
            if token.kind != "op":
                continue
            if token.text in _OPEN:
                stack.append(index)
            elif token.text in _CLOSE and stack:
                self.close[stack.pop()] = index
        self.constants: dict[str, list[tuple[int, int]]] = {}
        self.depths: list[int] | None = None
        self.define()

    def end_of_statement(self, begin: int) -> int:
        """The index after the expression that starts at `begin`."""
        tokens = self.tokens
        depth = 0
        for index in range(begin, len(tokens)):
            token = tokens[index]
            if token.kind == "op":
                if token.text in _OPEN:
                    depth += 1
                elif token.text in _CLOSE:
                    depth -= 1
                    if depth < 0:
                        return index
                elif token.text == ";" and depth == 0:
                    return index
            if (
                self.profile.statement == "line"
                and depth == 0
                and index > begin
                and token.line > tokens[index - 1].line
                and not (tokens[index - 1].kind == "op" and tokens[index - 1].text in _CONTINUES)
            ):
                return index
        return len(tokens)

    def define(self) -> None:
        """Every `name = expression` (and `name := expression`) of the file: a constant, a variable, a
        local. A name defined twice has both definitions."""
        tokens = self.tokens
        for index in range(1, len(tokens) - 1):
            token = tokens[index]
            if token.kind != "op" or token.text not in ("=", ":="):
                continue
            name = self.declared(index)
            if name is None:
                continue
            end = self.end_of_statement(index + 1)
            if end > index + 1:
                self.constants.setdefault(name.text, []).append((index + 1, end))

    def parameter_list(self, index: int) -> bool:
        """Whether the token at `index` is inside a parenthesis (a parameter list), not at the level of a
        class or a method's own attributes."""
        if self.depths is None:
            depth, found = 0, []
            for token in self.tokens:
                found.append(depth)
                if token.kind == "op" and token.text == "(":
                    depth += 1
                elif token.kind == "op" and token.text == ")":
                    depth = max(depth - 1, 0)
            self.depths = found
        return self.depths[index] > 0

    def declared(self, equals: int) -> Token | None:
        """The name an `=` at `equals` gives a value: the identifier just before it, or, after a type
        (`NOTE: &str = ...`), the identifier before the colon. A field assignment (`a.b = ...`) is none."""
        tokens = self.tokens
        before = tokens[equals - 1]
        if before.kind != "id":
            return None
        for back in range(equals - 1, max(equals - 12, 0), -1):
            token = tokens[back]
            if token.kind == "op" and token.text in (";", "{", "}", ","):
                break
            if (
                token.kind == "op"
                and token.text == ":"
                and tokens[back - 1].kind == "id"
                and self.profile.language == "rust"
            ):
                return tokens[back - 1]
        if equals >= 2 and tokens[equals - 2].kind == "op" and tokens[equals - 2].text == ".":
            return None
        return before

    def callee(self, opening: int) -> str:
        """The dotted name of the call whose parenthesis is at `opening`: `mcp.WithDescription`."""
        return self.path(opening)[0]

    def path(self, opening: int) -> tuple[str, int]:
        """The dotted name of a call (`Content::text` is `Content.text`) and where it begins."""
        tokens = self.tokens
        index = opening - 1
        if index < 0 or tokens[index].kind != "id":
            return "", opening
        parts = [tokens[index].text]
        while (
            index >= 2
            and tokens[index - 1].kind == "op"
            and tokens[index - 1].text in (".", "::")
            and tokens[index - 2].kind == "id"
        ):
            parts.append(tokens[index - 2].text)
            index -= 2
        return ".".join(reversed(parts)), index

    def arguments(self, opening: int) -> list[tuple[int, int]]:
        """The token ranges of the arguments of the call whose parenthesis is at `opening`."""
        tokens = self.tokens
        closing = self.close.get(opening, opening)
        out: list[tuple[int, int]] = []
        begin, depth = opening + 1, 0
        for index in range(opening + 1, closing):
            token = tokens[index]
            if token.kind == "op":
                if token.text in _OPEN:
                    depth += 1
                elif token.text in _CLOSE:
                    depth -= 1
                elif token.text == "," and depth == 0:
                    out.append((begin, index))
                    begin = index + 1
        if begin < closing:
            out.append((begin, closing))
        return out

    def handlers(self) -> list[tuple[int, int]]:
        """The token ranges of the bodies of the functions that take an MCP request."""
        tokens = self.tokens
        spans: list[tuple[int, int]] = []
        for index, token in enumerate(tokens):
            if token.kind != "id" or token.text != "func":
                continue
            params = self.parameters(index + 1)
            if params is None or not self.names_a_request(params):
                continue
            body = self.body_after(self.close.get(params, params) + 1)
            if body is not None:
                spans.append((body, self.close[body]))
        return spans

    def parameters(self, begin: int) -> int | None:
        """The `(` of the parameter list of the function whose `func` keyword is just before `begin`:
        `func(...)` (a literal), `func name(...)`, `func name[T any](...)` and, after a receiver,
        `func (r *T) name(...)`."""
        tokens = self.tokens
        if begin + 2 >= len(tokens):
            return None
        first = tokens[begin]
        if first.kind == "op" and first.text == "(":
            after = self.close.get(begin, begin) + 1
            if (
                after + 1 < len(tokens)
                and tokens[after].kind == "id"
                and tokens[after + 1].text in ("(", "[")
            ):
                return self.after_generics(after + 1)
            return begin
        if first.kind == "id" and tokens[begin + 1].text in ("(", "["):
            return self.after_generics(begin + 1)
        return None

    def after_generics(self, index: int) -> int | None:
        tokens = self.tokens
        if tokens[index].text == "[":
            index = self.close.get(index, index) + 1
        if index < len(tokens) and tokens[index].text == "(":
            return index
        return None

    def names_a_request(self, opening: int) -> bool:
        closing = self.close.get(opening, opening)
        return any(
            t.kind == "id" and t.text in self.profile.handlers for t in self.tokens[opening:closing]
        )

    def body_after(self, begin: int) -> int | None:
        """The `{` that opens a function's body, after its parameter list and result types."""
        tokens = self.tokens
        index = begin
        while index < len(tokens) and index < begin + 40:
            token = tokens[index]
            if token.kind == "op" and token.text == "{":
                return index if index in self.close else None
            if token.kind == "op" and token.text in ("(", "["):
                index = self.close.get(index, index)
            index += 1
        return None


class LexicalSurfaces:
    """The texts a Go (or other lexically read) MCP server hands the agent, once each."""

    @staticmethod
    def language(path: str) -> str | None:
        lowered = path.lower()
        return next((lang for suffix, lang in _SUFFIXES.items() if lowered.endswith(suffix)), None)

    @staticmethod
    def of(text: str, path: str) -> list[Served]:
        language = LexicalSurfaces.language(path)
        if language is None:
            return []
        profile = PROFILES[language]
        tokens = Lexer.tokens(text, language)
        if not tokens:
            return []
        flow = LexicalFlow(tokens, profile)
        out: list[Served] = []
        spans = flow.handlers() if any(a.scope == "handler" for a in profile.anchors) else []
        stack: list[tuple[int, str]] = []
        for index, token in enumerate(tokens):
            if token.kind == "id":
                if profile.throws and token.text == "throw":
                    LexicalSurfaces.throw(flow, text, index, out)
                continue
            if token.kind != "op":
                continue
            if token.text == "(":
                name = flow.callee(index)
                stack.append((index, name))
                LexicalSurfaces.call(flow, text, index, name, stack, spans, out)
            elif token.text == ")" and stack:
                stack.pop()
            elif token.text == "{":
                LexicalSurfaces.literal(flow, text, index, out)
            elif token.text in ("#", "@", "[") and profile.attributes:
                LexicalSurfaces.attribute(flow, text, index, out)
            if len(out) >= MAX_SERVED:
                break
        return out

    @staticmethod
    def call(
        flow: LexicalFlow,
        source: str,
        opening: int,
        name: str,
        stack: list[tuple[int, str]],
        spans: list[tuple[int, int]],
        out: list[Served],
    ) -> None:
        if not name:
            return
        for anchor in flow.profile.anchors:
            if name != anchor.callee and not name.endswith("." + anchor.callee):
                continue
            if anchor.scope == "handler" and not any(a < opening < b for a, b in spans):
                continue
            if anchor.new and not (
                flow.path(opening)[1] > 0 and flow.tokens[flow.path(opening)[1] - 1].text == "new"
            ):
                continue
            surface = anchor.surface
            if anchor.inside is not None and any(
                callee.endswith(anchor.inside[0]) for _, callee in stack[:-1]
            ):
                surface = anchor.inside[1]
            if anchor.skip_inside and any(
                callee.split(".")[-1] == anchor.skip_inside for _, callee in stack[:-1]
            ):
                continue
            ranges = flow.arguments(opening)
            wanted = (
                ranges
                if anchor.args is None
                else [ranges[i] for i in anchor.args if i < len(ranges)]
            )
            for begin, end in wanted:
                LexicalSurfaces.add(flow, source, surface, begin, end, out)

    @staticmethod
    def literal(flow: LexicalFlow, source: str, opening: int, out: list[Served]) -> None:
        """`Type{Key: text}`: the value of the key a profile names, in a literal of the type it names."""
        tokens = flow.tokens
        if opening == 0 or tokens[opening - 1].kind != "id":
            return
        kind = tokens[opening - 1].text
        for type_name, key, surface, separator in flow.profile.literals:
            if kind != type_name:
                continue
            closing = flow.close.get(opening)
            if closing is None:
                continue
            depth = 0
            for index in range(opening + 1, closing):
                token = tokens[index]
                if token.kind == "op" and token.text in _OPEN:
                    depth += 1
                elif token.kind == "op" and token.text in _CLOSE:
                    depth -= 1
                elif (
                    depth == 0
                    and token.kind == "id"
                    and token.text == key
                    and index + 1 < closing
                    and tokens[index + 1].text == separator
                ):
                    end = flow.end_of_statement(index + 2)
                    stop = min(end, closing)
                    cut = LexicalSurfaces.until_comma(flow, index + 2, stop)
                    LexicalSurfaces.add(flow, source, surface, index + 2, cut, out)

    @staticmethod
    def attribute(flow: LexicalFlow, source: str, index: int, out: list[Served]) -> None:
        """The text an attribute carries: Rust `#[tool(description = "...")]` (an argument's, with
        `param`, describes the argument), Java `@Tool(description = "...")`, C# `[Description("...")]`
        (on a parameter it describes the argument) and the text a C# method marked `[McpServerTool]`
        returns."""
        tokens = flow.tokens
        language = flow.profile.language
        if language == "csharp":
            if tokens[index].text == "[":
                LexicalSurfaces.csharp_attribute(flow, source, index, out)
            return
        if language == "rust" and tokens[index].text == "#":
            head = index + 2 if index + 1 < len(tokens) and tokens[index + 1].text == "[" else -1
        elif language == "java" and tokens[index].text == "@":
            head = index + 1
        else:
            return
        if head < 0 or head + 1 >= len(tokens):
            return
        if tokens[head].kind != "id" or tokens[head + 1].text != "(":
            return
        name, opening = tokens[head].text, head + 1
        closing = flow.close.get(opening)
        if closing is None:
            return
        argument = any(t.kind == "id" and t.text == "param" for t in tokens[opening:closing])
        for attribute, key, surface in flow.profile.attributes:
            if attribute != name:
                continue
            for begin, end in flow.arguments(opening):
                if end - begin >= 3 and tokens[begin].text == key and tokens[begin + 1].text == "=":
                    shown = "schema" if argument and surface == "description" else surface
                    LexicalSurfaces.add(flow, source, shown, begin + 2, end, out)

    @staticmethod
    def csharp_attribute(flow: LexicalFlow, source: str, index: int, out: list[Served]) -> None:
        """`[Description("...")]`: the first argument is a description of the method, or, inside a
        parameter list, of the argument; a method marked `[McpServerTool]` hands the agent what it
        returns."""
        tokens = flow.tokens
        closing = flow.close.get(index)
        if closing is None:
            return
        for position in range(index + 1, closing):
            token = tokens[position]
            if token.kind != "id":
                continue
            if token.text in _CSHARP_SERVES and position + 1 <= closing:
                LexicalSurfaces.returned(flow, source, closing + 1, _CSHARP_SERVES[token.text], out)
            elif (
                token.text == "Description"
                and position + 1 < closing
                and tokens[position + 1].text == "("
            ):
                ranges = flow.arguments(position + 1)
                if ranges:
                    shown = "schema" if flow.parameter_list(index) else "description"
                    LexicalSurfaces.add(flow, source, shown, ranges[0][0], ranges[0][1], out)

    @staticmethod
    def returned(
        flow: LexicalFlow, source: str, begin: int, surface: str, out: list[Served]
    ) -> None:
        """The text a method returns, for the method declared after the attribute that ends at
        `begin`: an expression body (`=> text;`) or each `return text;` of its block."""
        tokens = flow.tokens
        index = begin
        while index < len(tokens) and index < begin + 60:
            token = tokens[index]
            if token.kind == "op" and token.text == "[":
                index = flow.close.get(index, index) + 1
                continue
            if token.kind == "op" and token.text in ("{", ";", "=>"):
                return
            if token.kind == "op" and token.text == "(":
                break
            index += 1
        else:
            return
        after = flow.close.get(index, index) + 1
        while after < len(tokens) and tokens[after].kind == "id":
            after += 1  # `where T : ...` constraints
            while (
                after < len(tokens)
                and tokens[after].kind == "op"
                and tokens[after].text in (".", ":", ",")
            ):
                after += 2
        if after >= len(tokens):
            return
        if tokens[after].text == "=>":
            end = flow.end_of_statement(after + 1)
            LexicalSurfaces.add(flow, source, surface, after + 1, end, out)
            return
        if tokens[after].text != "{" or after not in flow.close:
            return
        for position in range(after + 1, flow.close[after]):
            if tokens[position].kind == "id" and tokens[position].text == "return":
                end = flow.end_of_statement(position + 1)
                LexicalSurfaces.add(flow, source, surface, position + 1, end, out)

    @staticmethod
    def throw(flow: LexicalFlow, source: str, index: int, out: list[Served]) -> None:
        """`throw new Type("...")`: the message of the exception."""
        tokens = flow.tokens
        if index + 2 >= len(tokens) or tokens[index + 1].text != "new":
            return
        position = index + 2
        while position < len(tokens) and position < index + 12:
            token = tokens[position]
            if token.kind == "op" and token.text == "(":
                for begin, end in flow.arguments(position):
                    LexicalSurfaces.add(flow, source, "error", begin, end, out)
                return
            if token.kind == "op" and token.text not in (".", "<", ">", ","):
                return
            position += 1

    @staticmethod
    def until_comma(flow: LexicalFlow, begin: int, end: int) -> int:
        depth = 0
        for index in range(begin, end):
            token = flow.tokens[index]
            if token.kind == "op":
                if token.text in _OPEN:
                    depth += 1
                elif token.text in _CLOSE:
                    depth -= 1
                elif token.text == "," and depth == 0:
                    return index
        return end

    @staticmethod
    def add(
        flow: LexicalFlow, source: str, surface: str, begin: int, end: int, out: list[Served]
    ) -> None:
        if end <= begin:
            return
        fold = _Fold(flow)
        text = fold.text(begin, end)
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT]
        if not text.strip():
            return
        first, last = flow.tokens[begin], flow.tokens[end - 1]
        via = fold.via or {"literal"}
        out.append(Served(surface, text, first.start, last.end, tuple(sorted(via))))


__all__ = ["PROFILES", "Anchor", "LexicalFlow", "LexicalSurfaces", "Profile"]
