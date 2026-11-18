"""The text a JavaScript or TypeScript MCP server's handlers serve to the agent (`served_flow.py`), folded
from Cordon's own syntax tree: constants, templates, joined arrays, names a handler appends to, decoded
literals (`atob`, `Buffer.from`, `String.fromCharCode`) and same-file helpers.

Nothing is imported or run: a closed table of string operations is evaluated on constants, and a value
that depends on the caller's input is a blank.
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import unquote

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax
from cordon_scanner.detect.agents.mcp_servers.served_flow import (
    FOLD_BUDGET,
    FOLD_DEPTH,
    HELPER_DEPTH,
    MAX_SERVED,
    MAX_TEXT,
    Decode,
    Served,
)

#: Beyond this the file is not read (`McpJsCode` reads no more).
MAX_CHARS: Final = 2_000_000
_FUNCTIONS: Final = frozenset(
    {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}
)
_NESTED: Final = _FUNCTIONS | {"ClassDeclaration", "ClassExpression", "MethodDefinition"}
#: The call that registers a handler for the agent, and what the handler serves.
_REGISTER: Final = {
    "tool": "result",
    "registerTool": "result",
    "addTool": "result",
    "prompt": "prompt",
    "registerPrompt": "prompt",
    "addPrompt": "prompt",
    "resource": "resource",
    "registerResource": "resource",
    "addResource": "resource",
    "addResourceTemplate": "resource",
    "resourceTemplate": "resource",
}
#: What `setRequestHandler(Schema, handler)` is told by its schema's name.
_REQUESTS: Final = (("CallTool", "result"), ("GetPrompt", "prompt"), ("ReadResource", "resource"))
#: The keys of a registration's object that hold served text itself.
_SERVED_KEYS: Final = frozenset({"text", "content", "contents", "messages"})
#: Methods that keep the text of the string they are called on.
_KEEPING: Final = frozenset(
    {
        "toString",
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toLocaleLowerCase",
        "toLocaleUpperCase",
        "replace",
        "replaceAll",
        "slice",
        "substring",
        "substr",
        "normalize",
        "padStart",
        "padEnd",
        "repeat",
        "at",
        "split",
        "reverse",
        "flat",
        "map",
        "filter",
    }
)
_APPENDERS: Final = frozenset(
    {"push", "unshift", "concat", "append", "add", "write", "set", "splice"}
)
_WRAPPER_NAME: Final = re.compile(
    r"(?i)(?:content|message|result|response|text|resource|prompt)s?$"
)
_LOGICAL: Final = frozenset({"||", "&&", "??"})


class _Tree:
    """Reading the syntax tree."""

    @staticmethod
    def callee(call: Node) -> tuple[str, Node | None]:
        """(the name a call is made by, the object it is called on): `a.b.join(...)` is
        (`join`, `a.b`)."""
        callee = call["callee"]
        if callee is None:
            return "", None
        if callee.type == "Identifier":
            return str(callee["name"]), None
        if callee.type == "MemberExpression":
            prop = callee["property"]
            if prop is not None and prop.type in ("Identifier", "PrivateIdentifier"):
                return str(prop["name"]), callee["object"]
            if prop is not None and prop.type == "Literal" and isinstance(prop["value"], str):
                return str(prop["value"]), callee["object"]
        return "", None

    @staticmethod
    def own(function: Node) -> list[Node]:
        """The nodes of a function's own body, not those of a function or class nested in it."""
        out: list[Node] = []
        stack = list(Syntax.children(function))
        while stack:
            node = stack.pop()
            out.append(node)
            if node.type in _NESTED:
                continue
            stack.extend(Syntax.children(node))
        return out

    @staticmethod
    def root(node: Node | None) -> str | None:
        """The identifier at the base of `a`, `a.b`, `a[0].c`."""
        while node is not None and node.type in ("MemberExpression", "ParenthesizedExpression"):
            node = node["object"] if node.type == "MemberExpression" else node["expression"]
        return str(node["name"]) if node is not None and node.type == "Identifier" else None

    @staticmethod
    def assigned(nodes: list[Node]) -> dict[str, list[Node]]:
        """For each name, every expression the nodes give it: `const x = e`, `x = e`, `x += e`,
        `x.text = e`, `x.push(e)` -- what the name may hold when it is returned."""
        out: dict[str, list[Node]] = {}
        for node in nodes:
            if node.type == "VariableDeclarator":
                target, value = node["id"], node["init"]
                if target is not None and target.type == "Identifier" and value is not None:
                    out.setdefault(str(target["name"]), []).append(value)
            elif node.type == "AssignmentExpression" and node["operator"] in ("=", "+="):
                name = _Tree.root(node["left"])
                if name is not None and node["right"] is not None:
                    out.setdefault(name, []).append(node["right"])
            elif node.type == "CallExpression":
                name, receiver = _Tree.callee(node)
                owner = _Tree.root(receiver)
                if owner is not None and name in _APPENDERS:
                    out.setdefault(owner, []).extend(node["arguments"] or [])
        return out


class _Folder:
    def __init__(self, flow: JsServed, local: dict[str, list[Node]], helpers: int) -> None:
        self.flow, self.local, self.helpers = flow, local, helpers
        self.via: set[str] = set()
        self.budget = FOLD_BUDGET

    def fold(self, node: Node | None, seen: frozenset[str] = frozenset(), level: int = 0) -> str:
        if node is None or self.budget <= 0 or level > FOLD_DEPTH:
            return " "
        self.budget -= 1
        text = self._fold(node, seen, level + 1)
        return text if len(text) <= MAX_TEXT else text[:MAX_TEXT]

    def _fold(self, node: Node, seen: frozenset[str], level: int) -> str:
        kind = node.type
        if kind == "Literal":
            value = node["value"]
            return value if isinstance(value, str) and node["kind"] == "string" else " "
        if kind == "TemplateLiteral":
            self.via.add("joined")
            quasis, expressions = node["quasis"] or [], node["expressions"] or []
            parts: list[str] = []
            for index, quasi in enumerate(quasis):
                parts.append(quasi["cooked"] or "")
                if index < len(expressions):
                    parts.append(self.fold(expressions[index], seen, level))
            return "".join(parts)
        if kind in ("BinaryExpression", "LogicalExpression"):
            operator = node["operator"]
            if operator == "+":
                self.via.add("joined")
                return self.fold(node["left"], seen, level) + self.fold(node["right"], seen, level)
            if operator in _LOGICAL:
                return (
                    self.fold(node["left"], seen, level)
                    + "\n"
                    + self.fold(node["right"], seen, level)
                )
            return " "
        if kind == "Identifier":
            return self._name(str(node["name"]), seen, level)
        if kind == "MemberExpression":
            return self._member(node, seen, level)
        if kind in ("ParenthesizedExpression", "TSAsExpression", "TSTypeAssertion", "TSAnnotated"):
            return self.fold(node["expression"], seen, level)
        if kind in ("AwaitExpression", "SpreadElement", "YieldExpression"):
            return self.fold(node["argument"], seen, level)
        if kind == "ConditionalExpression":
            return (
                self.fold(node["consequent"], seen, level)
                + "\n"
                + self.fold(node["alternate"], seen, level)
            )
        if kind == "ObjectExpression":
            return "\n".join(
                self.fold(p["value"] if p.type == "Property" else p, seen, level)
                for p in node["properties"] or []
            )
        if kind == "ArrayExpression":
            return "\n".join(self.fold(e, seen, level) for e in node["elements"] or [])
        if kind == "TaggedTemplateExpression":
            return self.fold(node["quasi"], seen, level)
        if kind == "AssignmentExpression":
            return self.fold(node["right"], seen, level)
        if kind == "SequenceExpression":
            items = node["expressions"] or []
            return self.fold(items[-1], seen, level) if items else " "
        if kind == "CallExpression":
            return self._call(node, seen, level)
        if kind == "NewExpression":
            return "\n".join(self.fold(a, seen, level) for a in node["arguments"] or [])
        return " "

    def _name(self, name: str, seen: frozenset[str], level: int) -> str:
        if name in seen:
            return " "
        expressions = self.local.get(name)
        if expressions is not None:
            self.via.add("appended" if len(expressions) > 1 else "variable")
        else:
            expressions = self.flow.constants.get(name)
            if expressions is None:
                return " "
            self.via.add("constant")
        return "\n".join(self.fold(e, seen | {name}, level) for e in expressions[:8])

    def _member(self, node: Node, seen: frozenset[str], level: int) -> str:
        """`CONFIG.note`, `this.NOTE`, `Class.NOTE`, `NOTES[0]`: a value the file defines."""
        target, prop = node["object"], node["property"]
        key = None
        if prop is not None and not node["computed"] and prop.type == "Identifier":
            key = str(prop["name"])
        elif prop is not None and prop.type == "Literal" and prop["kind"] == "string":
            key = str(prop["value"])
        if key is not None and key not in seen:
            members = self.flow.members.get(key)
            if members is not None and (
                target is not None
                and target.type in ("ThisExpression", "Identifier", "MemberExpression")
            ):
                self.via.add("constant")
                return "\n".join(self.fold(m, seen | {key}, level) for m in members[:8])
            if key == "length":
                return " "
        return self.fold(target, seen, level)

    def _call(self, node: Node, seen: frozenset[str], level: int) -> str:
        name, receiver = _Tree.callee(node)
        arguments: list[Node] = list(node["arguments"] or [])
        receiver_name = (
            str(receiver["name"]) if receiver is not None and receiver.type == "Identifier" else ""
        )
        if name == "atob" and receiver is None and arguments:
            self.via.add("decoded")
            return Decode.text(Decode.base64(self.fold(arguments[0], seen, level))) or " "
        if name == "from" and receiver_name == "Buffer" and arguments:
            return self._buffer(arguments, seen, level)
        if name in ("fromCharCode", "fromCodePoint") and receiver_name == "String":
            self.via.add("decoded")
            return self._chars(arguments)
        if (
            name in ("decodeURIComponent", "decodeURI", "unescape")
            and receiver is None
            and arguments
        ):
            self.via.add("decoded")
            return unquote(self.fold(arguments[0], seen, level))
        if name == "join" and receiver is not None:
            return self._join(receiver, arguments, seen, level)
        if name in ("stringify", "parse") and receiver_name == "JSON" and arguments:
            return self.fold(arguments[0], seen, level)
        if name == "resolve" and receiver_name == "Promise":
            return "\n".join(self.fold(a, seen, level) for a in arguments)
        if name in _KEEPING and receiver is not None:
            return " ".join(
                [self.fold(receiver, seen, level), *(self.fold(a, seen, level) for a in arguments)]
            )
        if name == "concat" and receiver is not None:
            return "\n".join(
                [self.fold(receiver, seen, level), *(self.fold(a, seen, level) for a in arguments)]
            )
        if name == "String" and receiver is None:
            return "\n".join(self.fold(a, seen, level) for a in arguments)
        helper = self._helper(node, name, receiver)
        if helper is not None:
            return self._helper_text(helper)
        if _WRAPPER_NAME.search(name):
            return "\n".join(self.fold(a, seen, level) for a in arguments)
        return " "

    def _buffer(self, arguments: list[Node], seen: frozenset[str], level: int) -> str:
        """`Buffer.from(text, "base64" | "hex")`: the bytes the encoding spells, as text."""
        content = self.fold(arguments[0], seen, level)
        encoding = self.fold(arguments[1], seen, level) if len(arguments) > 1 else ""
        decoded = Decode.named(encoding, content)
        if decoded is None:
            return content
        self.via.add("decoded")
        return decoded or " "

    def _chars(self, arguments: list[Node]) -> str:
        out: list[str] = []
        items: list[Node] = []
        for argument in arguments:
            items.extend(
                argument["elements"] or [] if argument.type == "ArrayExpression" else [argument]
            )
        for item in items[:MAX_TEXT]:
            if item.type != "Literal" or item["kind"] != "number":
                continue
            try:
                out.append(chr(int(float(str(item["value"])))))
            except (ValueError, OverflowError):
                return " "
        return "".join(out)

    def _join(self, receiver: Node, arguments: list[Node], seen: frozenset[str], level: int) -> str:
        self.via.add("joined")
        separator = self.fold(arguments[0], seen, level) if arguments else ","
        inner, name = receiver, ""
        if receiver.type == "CallExpression":
            name, source = _Tree.callee(receiver)
            inner = source if source is not None else receiver
        if name == "reverse" and inner is not None:
            # `text.split("").reverse().join("")`: a text written backwards.
            origin, spelt = inner, ""
            if inner.type == "CallExpression":
                spelt, base = _Tree.callee(inner)
                origin = base if base is not None else inner
            if spelt == "split":
                self.via.add("decoded")
                return self.fold(origin, seen, level)[::-1]
            return self.fold(inner, seen, level)
        if receiver.type == "ArrayExpression":
            return separator.join(self.fold(e, seen, level) for e in receiver["elements"] or [])
        return self.fold(receiver, seen, level)

    def _helper(self, node: Node, name: str, receiver: Node | None) -> Node | None:
        if self.helpers >= HELPER_DEPTH or not name:
            return None
        if receiver is None:
            return self.flow.functions.get(name)
        if receiver.type == "ThisExpression":
            return self.flow.methods.get(name)
        return None

    def _helper_text(self, helper: Node) -> str:
        self.via.add("helper")
        inner = _Folder(self.flow, _Tree.assigned(_Tree.own(helper)), self.helpers + 1)
        inner.budget = max(0, self.budget // 2)
        texts = [inner.fold(r) for r in JsServed.returned(helper)]
        self.via |= inner.via
        return "\n".join(texts)


class JsServed:
    """`JsServed.of(text, typescript)`: the texts the handlers of a JavaScript MCP server serve."""

    def __init__(self, program: Node) -> None:
        self.program = program
        self.constants: dict[str, list[Node]] = _Tree.assigned(_Tree.own(program))
        self.functions: dict[str, Node] = {}
        self.methods: dict[str, Node] = {}
        self.members: dict[str, list[Node]] = {}
        for node in Syntax.walk(program):
            if node.type == "FunctionDeclaration" and node["id"] is not None:
                self.functions[str(node["id"]["name"])] = node
            elif node.type == "MethodDefinition" and node["key"] is not None:
                if node["key"].type == "Identifier" and node["value"] is not None:
                    self.methods.setdefault(str(node["key"]["name"]), node["value"])
            elif node.type == "PropertyDefinition" and node["key"] is not None:
                if node["key"].type == "Identifier" and node["value"] is not None:
                    self.members.setdefault(str(node["key"]["name"]), []).append(node["value"])
            elif node.type == "VariableDeclarator" and node["id"] is not None:
                init = node["init"]
                if init is not None and node["id"].type == "Identifier" and init.type in _FUNCTIONS:
                    self.functions.setdefault(str(node["id"]["name"]), init)
                elif init is not None and init.type == "ObjectExpression":
                    for prop in init["properties"] or []:
                        key = prop["key"] if prop.type == "Property" else None
                        if (
                            key is not None
                            and key.type == "Identifier"
                            and prop["value"] is not None
                        ):
                            self.members.setdefault(str(key["name"]), []).append(prop["value"])

    @staticmethod
    def returned(function: Node) -> list[Node]:
        """What a function returns: its `return` values, or the body of an arrow with an expression."""
        if function.type == "ArrowFunctionExpression" and function["expression"]:
            return [function["body"]] if function["body"] is not None else []
        out = [
            n["argument"]
            for n in _Tree.own(function)
            if n.type == "ReturnStatement" and n["argument"] is not None
        ]
        out.reverse()
        return out

    def handlers(self, text: str) -> list[tuple[str, Node]]:
        """The functions registered to serve the agent, with what each serves."""
        found: dict[int, tuple[str, Node]] = {}

        def add(kind: str | None, function: Node | None) -> None:
            if kind and function is not None and function.type in _FUNCTIONS:
                found.setdefault(function.start, (kind, function))

        for node in Syntax.walk(self.program):
            if node.type != "CallExpression":
                continue
            name, _receiver = _Tree.callee(node)
            arguments: list[Node] = list(node["arguments"] or [])
            kind = _REGISTER.get(name)
            if name == "setRequestHandler" and arguments:
                label = text[arguments[0].start : arguments[0].end]
                kind = next((k for marker, k in _REQUESTS if marker in label), None)
            if kind is None:
                continue
            for argument in arguments:
                if argument.type in _FUNCTIONS:
                    add(kind, argument)
                elif argument.type == "Identifier":
                    add(kind, self.functions.get(str(argument["name"])))
                elif argument.type == "ObjectExpression":
                    for prop in argument["properties"] or []:
                        if prop.type == "Property" and prop["value"] is not None:
                            add(kind, prop["value"])
        return list(found.values())

    @classmethod
    def of(cls, text: str, typescript: bool = True) -> list[Served]:
        if len(text) > MAX_CHARS:
            return []
        # A parser that raises escapes to the engine's detector-failure gap, a blocking one: a file
        # crafted to crash it must not remove the check (the same stance as `McpJsCode`).
        flow = cls(Parser(text, typescript=typescript).program())
        out: list[Served] = []
        for kind, function in flow.handlers(text):
            local = _Tree.assigned(_Tree.own(function))
            for value in cls.returned(function):
                folder = _Folder(flow, local, 0)
                folded = folder.fold(value)
                out.append(
                    Served(
                        kind,
                        folded,
                        value.start,
                        value.end,
                        tuple(sorted(folder.via or {"literal"})),
                    )
                )
                if len(out) >= MAX_SERVED:
                    return out
        for node in Syntax.walk(flow.program):
            if node.type != "CallExpression":
                continue
            name, _receiver = _Tree.callee(node)
            registered = _REGISTER.get(name)
            if registered is None or registered not in ("resource", "prompt"):
                continue
            for argument in node["arguments"] or []:
                if argument.type != "ObjectExpression":
                    continue
                for prop in argument["properties"] or []:
                    key = prop["key"] if prop.type == "Property" else None
                    if (
                        key is None
                        or key.type != "Identifier"
                        or str(key["name"]) not in _SERVED_KEYS
                    ):
                        continue
                    if prop["value"] is None or prop["value"].type in _FUNCTIONS:
                        continue
                    folder = _Folder(flow, {}, 0)
                    folded = folder.fold(prop["value"])
                    out.append(
                        Served(
                            registered,
                            folded,
                            prop["value"].start,
                            prop["value"].end,
                            tuple(sorted(folder.via or {"literal"})),
                        )
                    )
        return out


__all__ = ["JsServed"]
