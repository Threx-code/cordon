"""The text a Python MCP server's handlers serve to the agent (`served_flow.py`), folded from the syntax
tree: constants, f-strings, joins, names a handler appends to, decoded literals and same-file helpers.

Nothing is run. A closed table of string operations is evaluated on constants and on names whose
definition is in the file; a value that depends on the caller's input is a blank.
"""

from __future__ import annotations

import ast
import re
from typing import Final

from cordon_scanner.detect.agents.mcp_servers.handlers import McpCode
from cordon_scanner.detect.agents.mcp_servers.served_flow import (
    FOLD_BUDGET,
    FOLD_DEPTH,
    HELPER_DEPTH,
    MAX_SERVED,
    MAX_TEXT,
    Decode,
    Served,
)

#: The decorator or registration name that makes a function serve the agent, and what it serves.
_KINDS: Final = {
    "tool": "result",
    "call_tool": "result",
    "add_tool": "result",
    "prompt": "prompt",
    "get_prompt": "prompt",
    "add_prompt": "prompt",
    "resource": "resource",
    "read_resource": "resource",
    "add_resource": "resource",
}
#: `Prompt.from_function(fn)` and kin: the class names the kind.
_FACTORY: Final = {
    "Tool": "result",
    "Prompt": "prompt",
    "Resource": "resource",
    "FunctionResource": "resource",
    "ResourceTemplate": "resource",
}
#: The low-level server's handler table: `server.request_handlers[types.GetPromptRequest] = fn`.
_REQUESTS: Final = {
    "CallToolRequest": "result",
    "GetPromptRequest": "prompt",
    "ReadResourceRequest": "resource",
}
#: Constructors whose arguments ARE the served text (result parts, messages, resource contents).
_WRAPPER_NAME: Final = re.compile(
    r"(?:Content|Contents|Message|Result|Response|Resource|Prompt|Part|Block|Text)s?$"
)
_STATIC_RESOURCES: Final = frozenset({"TextResource", "StaticResource", "TextResourceContents"})
#: Methods that keep the text of the string they are called on.
_KEEPING: Final = frozenset(
    {
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "swapcase",
        "expandtabs",
        "removeprefix",
        "removesuffix",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "dedent",
        "fill",
        "wrap",
        "strip_tags",
        "format",
        "format_map",
        "replace",
        "translate",
    }
)
#: Functions that return what they are given, as text.
_PASSING: Final = frozenset(
    {
        "str",
        "repr",
        "dedent",
        "dumps",
        "jsonify",
        "dict",
        "list",
        "tuple",
        "sorted",
        "reversed",
        "set",
    }
)
_BASE64: Final = {
    "b64decode": False,
    "standard_b64decode": False,
    "urlsafe_b64decode": True,
    "a2b_base64": False,
}
_HEX: Final = frozenset({"unhexlify", "a2b_hex", "fromhex", "b16decode"})
_INFLATE: Final = frozenset({"decompress"})
_APPENDERS: Final = frozenset(
    {"append", "extend", "insert", "add", "write", "appendleft", "update"}
)
_NESTED: Final = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")


class _Tree:
    """Reading the syntax tree."""

    @staticmethod
    def name_of(node: ast.expr) -> str:
        """The last name of a callee or decorator: `mcp.tool` and `tool` are `tool`."""
        if isinstance(node, ast.Call):
            return _Tree.name_of(node.func)
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Name):
            return node.id
        return ""

    @staticmethod
    def own(function: ast.AST) -> list[ast.AST]:
        """The nodes of a function's own body, not those of a function, lambda or class in it."""
        out: list[ast.AST] = []
        stack = list(ast.iter_child_nodes(function))
        while stack:
            node = stack.pop()
            out.append(node)
            if isinstance(node, _NESTED):
                continue
            stack.extend(ast.iter_child_nodes(node))
        return out

    @staticmethod
    def give(out: dict[str, list[ast.expr]], target: ast.expr, value: ast.expr | None) -> None:
        while isinstance(target, ast.Subscript | ast.Attribute):
            target = target.value
        if isinstance(target, ast.Name) and value is not None:
            out.setdefault(target.id, []).append(value)

    @staticmethod
    def assigned(nodes: list[ast.AST]) -> dict[str, list[ast.expr]]:
        """For each name, every expression the nodes give it: `x = e`, `x += e`, `x[k] = e`,
        `x.append(e)`, `x.update(e)` -- what the name may hold when it is returned."""
        out: dict[str, list[ast.expr]] = {}
        for node in nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    _Tree.give(out, target, node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                or (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add))
                or isinstance(node, ast.NamedExpr)
            ):
                _Tree.give(out, node.target, node.value)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _APPENDERS
            ):
                for argument in [*node.args, *(k.value for k in node.keywords)]:
                    _Tree.give(out, node.func.value, argument)
        return out

    @staticmethod
    def module_nodes(tree: ast.Module) -> list[ast.AST]:
        """The module's top-level statements, and the statements of the top-level `if`, `try` and
        `with` blocks they sit in (a constant defined under `try:` is still a constant)."""
        out: list[ast.AST] = []
        stack: list[ast.AST] = list(tree.body)
        while stack:
            node = stack.pop()
            out.append(node)
            if isinstance(node, ast.If | ast.Try | ast.With):
                stack.extend(ast.iter_child_nodes(node))
        return out


class _Folder:
    """The text of an expression, as far as the file says: strings of it joined, a value the caller
    decides left blank. `via` collects how the text was reached."""

    def __init__(self, flow: PythonServed, local: dict[str, list[ast.expr]], helpers: int) -> None:
        self.flow, self.local, self.helpers = flow, local, helpers
        self.via: set[str] = set()
        self.budget = FOLD_BUDGET

    def fold(self, node: ast.AST | None, seen: frozenset[str] = frozenset(), level: int = 0) -> str:
        if node is None or self.budget <= 0 or level > FOLD_DEPTH:
            return " "
        self.budget -= 1
        level += 1
        text = self._fold(node, seen, level)
        return text if len(text) <= MAX_TEXT else text[:MAX_TEXT]

    def _fold(self, node: ast.AST, seen: frozenset[str], level: int) -> str:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                return node.value.decode("utf-8", "replace")
            return " "
        if isinstance(node, ast.JoinedStr):
            self.via.add("joined")
            return "".join(self.fold(v, seen, level) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.fold(node.value, seen, level)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                self.via.add("joined")
                return self.fold(node.left, seen, level) + self.fold(node.right, seen, level)
            if isinstance(node.op, ast.Mod | ast.Mult):
                return self.fold(node.left, seen, level)
            return " "
        if isinstance(node, ast.Name):
            return self._name(node.id, seen, level)
        if isinstance(node, ast.Attribute):
            return self._attribute(node, seen, level)
        if isinstance(node, ast.Subscript):
            return self._subscript(node, seen, level)
        if isinstance(node, ast.IfExp):
            return self.fold(node.body, seen, level) + "\n" + self.fold(node.orelse, seen, level)
        if isinstance(node, ast.BoolOp):
            return "\n".join(self.fold(v, seen, level) for v in node.values)
        if isinstance(node, ast.Dict):
            return "\n".join(self.fold(v, seen, level) for v in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return "\n".join(self.fold(e, seen, level) for e in node.elts)
        if isinstance(node, ast.Await | ast.Starred | ast.NamedExpr):
            return self.fold(node.value, seen, level)
        if isinstance(node, ast.GeneratorExp | ast.ListComp | ast.SetComp):
            return self._comprehension(node, seen, level)
        if isinstance(node, ast.Call):
            return self._call(node, seen, level)
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

    def _attribute(self, node: ast.Attribute, seen: frozenset[str], level: int) -> str:
        """`self.NOTE`, `Config.NOTE`: a string the file's classes define."""
        expressions = self.flow.attributes.get(node.attr)
        if expressions is None or node.attr in seen:
            return " "
        self.via.add("constant")
        return "\n".join(self.fold(e, seen | {node.attr}, level) for e in expressions[:8])

    def _subscript(self, node: ast.Subscript, seen: frozenset[str], level: int) -> str:
        """`NOTES[0]` is one of the list; `text[::-1]` is the text reversed."""
        text = self.fold(node.value, seen, level)
        step = node.slice.step if isinstance(node.slice, ast.Slice) else None
        if isinstance(step, ast.UnaryOp) and isinstance(step.op, ast.USub):
            self.via.add("decoded")
            return text[::-1]
        return text

    def _comprehension(
        self, node: ast.GeneratorExp | ast.ListComp | ast.SetComp, seen: frozenset[str], level: int
    ) -> str:
        """`"".join(chr(c) for c in [..])` spells a text out of numbers."""
        element = node.elt
        if (
            len(node.generators) == 1
            and isinstance(element, ast.Call)
            and isinstance(element.func, ast.Name)
            and element.func.id == "chr"
            and isinstance(node.generators[0].iter, ast.List | ast.Tuple)
        ):
            self.via.add("decoded")
            return self._chars(node.generators[0].iter.elts)
        return self.fold(element, seen, level)

    @staticmethod
    def _chars(items: list[ast.expr]) -> str:
        out: list[str] = []
        for item in items[:MAX_TEXT]:
            if isinstance(item, ast.Constant) and isinstance(item.value, int):
                try:
                    out.append(chr(item.value))
                except (ValueError, OverflowError):
                    return " "
        return "".join(out)

    def _call(self, node: ast.Call, seen: frozenset[str], level: int) -> str:
        function = node.func
        name = _Tree.name_of(function)
        arguments = [*node.args, *(k.value for k in node.keywords)]
        if name in _BASE64 and node.args:
            raw = self.raw(node.args[0], seen, level)
            self.via.add("decoded")
            return Decode.text(Decode.base64(raw, urlsafe=_BASE64[name])) if raw else " "
        if name in _HEX and node.args:
            raw = self.raw(node.args[0], seen, level)
            self.via.add("decoded")
            return Decode.text(Decode.hexadecimal(raw)) if raw else " "
        if name in _INFLATE and node.args:
            raw = self.raw(node.args[0], seen, level)
            self.via.add("decoded")
            return Decode.text(Decode.inflate(raw)) if raw else " "
        if name == "decode" and isinstance(function, ast.Attribute):
            if isinstance(function.value, ast.Name) and function.value.id == "codecs":
                return self._codec(node, seen, level)
            raw = self.raw(function.value, seen, level)
            return Decode.text(raw) if raw else self.fold(function.value, seen, level)
        if name == "encode" and isinstance(function, ast.Attribute):
            return self.fold(function.value, seen, level)
        if name == "chr" and node.args:
            return self._chars(node.args[:1])
        if name in ("bytes", "bytearray") and node.args and isinstance(node.args[0], ast.List):
            self.via.add("decoded")
            return self._chars(node.args[0].elts)
        if name == "join" and isinstance(function, ast.Attribute):
            return self._join(function, node, seen, level)
        if name in _KEEPING and isinstance(function, ast.Attribute):
            return " ".join(
                [self.fold(function.value, seen, level)]
                + [self.fold(a, seen, level) for a in arguments]
            )
        if name in _PASSING:
            return "\n".join(self.fold(a, seen, level) for a in arguments)
        helper = self._helper(function, name)
        if helper is not None:
            return self._helper_text(helper)
        if _WRAPPER_NAME.search(name):
            return "\n".join(self.fold(a, seen, level) for a in arguments)
        return " "

    def _codec(self, node: ast.Call, seen: frozenset[str], level: int) -> str:
        """`codecs.decode(text, "rot13" | "hex" | "base64")`."""
        if len(node.args) < 2:
            return " "
        encoding = self.fold(node.args[1], seen, level)
        self.via.add("decoded")
        decoded = Decode.named(encoding, self.fold(node.args[0], seen, level))
        return decoded if decoded is not None else " "

    def _join(
        self, function: ast.Attribute, node: ast.Call, seen: frozenset[str], level: int
    ) -> str:
        self.via.add("joined")
        separator = function.value.value if isinstance(function.value, ast.Constant) else " "
        if not isinstance(separator, str):
            separator = " "
        items = node.args[0] if node.args else None
        if isinstance(items, ast.List | ast.Tuple | ast.Set):
            return separator.join(self.fold(e, seen, level) for e in items.elts)
        return self.fold(items, seen, level)

    def _helper(
        self, function: ast.expr, name: str
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        if self.helpers >= HELPER_DEPTH or not name:
            return None
        if isinstance(function, ast.Name):
            return self.flow.functions.get(name)
        if (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in ("self", "cls")
        ):
            return self.flow.methods.get(name)
        return None

    def _helper_text(self, helper: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        self.via.add("helper")
        inner = _Folder(self.flow, _Tree.assigned(_Tree.own(helper)), self.helpers + 1)
        inner.budget = max(0, self.budget // 2)
        texts = [inner.fold(r) for r in PythonServed.returned(helper)]
        self.via |= inner.via
        return "\n".join(texts)

    def raw(self, node: ast.AST, seen: frozenset[str], level: int) -> bytes:
        """The bytes of an expression a decoder is given: its text (for a decoder nested in
        another -- `zlib.decompress(base64.b64decode(..))` -- its decoded bytes)."""
        if isinstance(node, ast.Call):
            name = _Tree.name_of(node.func)
            if name in _BASE64 or name in _HEX or name in _INFLATE:
                self.via.add("decoded")
            if name in _BASE64 and node.args:
                inner = self.raw(node.args[0], seen, level + 1)
                return Decode.base64(inner, urlsafe=_BASE64[name]) or b"" if inner else b""
            if name in _HEX and node.args:
                inner = self.raw(node.args[0], seen, level + 1)
                return Decode.hexadecimal(inner) or b"" if inner else b""
            if name in _INFLATE and node.args:
                inner = self.raw(node.args[0], seen, level + 1)
                return Decode.inflate(inner) or b"" if inner else b""
            if name == "encode" and isinstance(node.func, ast.Attribute):
                return self.raw(node.func.value, seen, level + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            return node.value
        text = self.fold(node, seen, level)
        return text.strip().encode("utf-8", "replace") if text.strip() else b""


class PythonServed:
    """`PythonServed.of(text)`: the texts the handlers of a Python MCP server serve."""

    def __init__(self, tree: ast.Module, text: str) -> None:
        self.tree = tree
        self.constants: dict[str, list[ast.expr]] = _Tree.assigned(_Tree.module_nodes(tree))
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.attributes: dict[str, list[ast.expr]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for member in node.body:
                if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
                    self.methods.setdefault(member.name, member)
            for name, expressions in _Tree.assigned(list(node.body)).items():
                self.attributes.setdefault(name, []).extend(expressions)
        for statement in tree.body:
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions[statement.name] = statement
        self.starts = [0, *(m.end() for m in _LINE_BREAK.finditer(text))]
        self.lines = _LINE_BREAK.split(text)

    @staticmethod
    def returned(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.expr]:
        out: list[ast.expr] = []
        for node in _Tree.own(function):
            if isinstance(node, ast.Return | ast.Yield | ast.YieldFrom) and node.value is not None:
                out.append(node.value)
        out.reverse()
        return out

    def offset(self, line: int, column: int) -> int:
        """The character offset of an `ast` position (columns count UTF-8 bytes)."""
        index = min(max(line, 1), len(self.starts)) - 1
        text = self.lines[index] if index < len(self.lines) else ""
        return self.starts[index] + len(text.encode("utf-8")[:column].decode("utf-8", "ignore"))

    def span(self, node: ast.AST) -> tuple[int, int]:
        line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", line) or line
        return (
            self.offset(line, getattr(node, "col_offset", 0)),
            self.offset(end_line, getattr(node, "end_col_offset", 0) or 0),
        )

    @staticmethod
    def _add(
        found: dict[int, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
        kind: str | None,
        function: ast.AST | None,
    ) -> None:
        if kind and isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            found.setdefault(id(function), (kind, function))

    def _registered(
        self,
        node: ast.Call,
        found: dict[int, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    ) -> None:
        """`mcp.add_tool(handler)`, `mcp.tool()(handler)`, `Prompt.from_function(handler)`."""
        kind = _KINDS.get(_Tree.name_of(node.func))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_function":
            kind = _FACTORY.get(_Tree.name_of(node.func.value))
        for argument in [*node.args, *(k.value for k in node.keywords)]:
            if isinstance(argument, ast.Name):
                self._add(found, kind, self.functions.get(argument.id))

    def _tabled(
        self,
        node: ast.Assign,
        found: dict[int, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    ) -> None:
        """`server.request_handlers[types.GetPromptRequest] = handler`."""
        if not isinstance(node.value, ast.Name):
            return
        for target in node.targets:
            if not isinstance(target, ast.Subscript):
                continue
            key = ast.unparse(target.slice)
            for request, kind in _REQUESTS.items():
                if request in key:
                    self._add(found, kind, self.functions.get(node.value.id))

    def handlers(self) -> dict[int, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
        """The functions that serve the agent, by their position, with what each serves."""
        found: dict[int, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for decorator in node.decorator_list:
                    self._add(found, _KINDS.get(_Tree.name_of(decorator)), node)
            if isinstance(node, ast.Call):
                self._registered(node, found)
            if isinstance(node, ast.Assign):
                self._tabled(node, found)
        return found

    @classmethod
    def of(cls, text: str) -> list[Served]:
        tree = McpCode._parse(text)
        if tree is None:
            return []
        flow = cls(tree, text)
        out: list[Served] = []
        for kind, function in flow.handlers().values():
            local = _Tree.assigned(_Tree.own(function))
            for value in cls.returned(function):
                folder = _Folder(flow, local, 0)
                folded = folder.fold(value)
                start, end = flow.span(value)
                via = folder.via or {"literal"}
                out.append(Served(kind, folded, start, end, tuple(sorted(via))))
                if len(out) >= MAX_SERVED:
                    return out
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and _Tree.name_of(node.func) in _STATIC_RESOURCES
                and any(k.arg == "text" for k in node.keywords)
            ):
                folder = _Folder(flow, {}, 0)
                value = next(k.value for k in node.keywords if k.arg == "text")
                start, end = flow.span(value)
                out.append(
                    Served(
                        "resource",
                        folder.fold(value),
                        start,
                        end,
                        tuple(sorted(folder.via or {"literal"})),
                    )
                )
        return out


__all__ = ["PythonServed"]
