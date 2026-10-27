"""Which function each call in a JavaScript or TypeScript file reaches: the third stage of the front end.

The `kind: ast` rules ask for `child_process.exec` however a file spells it. This stage walks the
tree (`parser.Parser`) with real lexical scopes and answers with the `AstCall` records the rules
consume:

- Scopes: the module, every function (parameters and hoisted `var`s and functions), every block
  (`let`, `const`, `class`), `catch` parameters. A local binding shadows a module one, so
  `function f(cp) { cp.exec() }` is a call on the parameter, not on `child_process`.
- Aliases: `require` and every `import` form, TypeScript `import x = require(...)`, destructuring
  with renames and defaults, `const r = require` (then `r("m")` is a require), assignment chains
  (`const a = cp; a.exec()`), member aliases (`const run = cp.exec`), each resolved through the
  scope that declares it.
- Callees: `name(...)`, `a.b(...)`, `require("m").f(...)`, `o["f"](...)` with a constant key,
  `(0, o.f)(...)`, optional chaining, and the global object (`globalThis.eval` is `eval`).
- Values: a string literal, `+` of constants, a template without substitutions,
  `String.fromCharCode(...)` of numbers, `[...].join(...)` of constants, and a `const` bound once to
  a constant -- each folded, so `Buffer.from(b, "ba" + "se64")` reads `base64`.

A file given in statement segments (`segmented_parse`) is resolved a segment at a time: what a
segment's own scopes bind is resolved there, and only names bound at module level or not bound at
all wait for the end, against every segment's module bindings. Memory is one segment's tree.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax
from cordon_scanner.analysis.shared.content_memo import ContentMemo

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.analysis.python.pyast import AstCall


@dataclass
class Scope:
    """One lexical scope: what it declares, and what each declaration was bound to."""

    parent: Scope | None
    module: bool = False
    #: A function's own scope, where its `var`s and parameters live.
    function: bool = False
    #: name -> what it refers to: a module path (`child_process`, `child_process.exec`), the
    #: marker `REQUIRE` for `require` itself, a name to resolve further (`@name`), or "" (a local
    #: value whose origin is not a module).
    names: dict[str, str] = field(default_factory=dict)
    #: name -> a constant string it is bound to once.
    constants: dict[str, str] = field(default_factory=dict)

    def lookup(self, name: str) -> Scope | None:
        scope: Scope | None = self
        while scope is not None:
            if name in scope.names:
                return scope
            scope = scope.parent
        return None


@dataclass
class Pending:
    """A call whose callee waits for the module's bindings: its root name and the path after it."""

    offset: int
    line: int
    column: int
    root: str
    rest: tuple[str, ...]
    values: list[str]
    built: bool


class CallResolver:
    """`resolve_calls(source, typescript=...)`, and `resolve_parts(parts)` for a segmented file."""

    REQUIRE: ClassVar[str] = "\0require"
    GLOBALS: ClassVar[frozenset[str]] = frozenset({"globalThis", "window", "global", "self"})
    BUILT: ClassVar[frozenset[str]] = frozenset(
        {
            "BinaryExpression",
            "TemplateLiteral",
            "CallExpression",
            "MemberExpression",
            "ConditionalExpression",
            "TaggedTemplateExpression",
            "NewExpression",
            "LogicalExpression",
        }
    )
    MAX_CHAIN: ClassVar[int] = 16

    def __init__(self, *, typescript: bool = False) -> None:
        self.typescript = typescript

    #: A module member that is a global by another name: `Buffer` from `buffer` (and its npm polyfill
    #: `buffer/`, `safe-buffer`) is the `Buffer` every Node program has.
    GLOBAL_EXPORTS: ClassVar[dict[str, str]] = {
        f"{module}.Buffer": "Buffer"
        for module in ("buffer", "buffer/", "node:buffer", "safe-buffer")
    }

    @staticmethod
    def canonical(path: str) -> str:
        return CallResolver.GLOBAL_EXPORTS.get(path, path)

    @staticmethod
    def split(path: str) -> tuple[str, tuple[str, ...]]:
        root, *rest = path.split(".")
        return root, tuple(rest)

    def resolve_calls(self, source: str) -> list[AstCall]:
        """The file's calls, worked out once per process for each distinct text
        (`analysis.shared.content_memo`): they depend on the text and on `typescript` alone."""
        return CallResolver.MEMO.get(
            ("calls", self.typescript),
            source,
            lambda: [call for _, call in self.resolve_parts([(0, 0, 0, source)])],
        )

    MEMO: ClassVar[ContentMemo] = ContentMemo()

    def resolve_parts(
        self, parts: Iterable[tuple[int, int, int, Any]]
    ) -> list[tuple[int, AstCall]]:
        """The calls of a file given in parts, each `(byte offset, newlines before it, column of
        its start, its text or a sliceable view of its bytes)`, with each call's byte offset."""
        from cordon_scanner.analysis.python.pyast import AstCall

        module = Scope(None, module=True)
        done: list[tuple[int, int, int, str, list[str], bool]] = []
        pending: list[Pending] = []
        for offset, line, column, data in parts:
            text = data if isinstance(data, str) else CallResolver._text(data)
            program = self._program(text)
            places = _Places(
                text,
                offset,
                line,
                column,
                "surrogatepass" if isinstance(data, str) else "surrogateescape",
            )
            walker = _Walker(self, module, places)
            walker.declare(program, module)
            walker.calls(done, pending)
        for p in pending:
            name = self._resolve_root(module, p.root, p.rest)
            done.append((p.offset, p.line, p.column, name, p.values, p.built))
        return [
            (
                offset,
                AstCall(
                    name=name,
                    line=line,
                    column=column,
                    arguments=tuple(values),
                    keywords=(),
                    has_constructed_argument=built,
                ),
            )
            for offset, line, column, name, values, built in sorted(done, key=lambda d: d[0])
        ]

    def _program(self, text: str) -> Node:
        """The tree of one part. TypeScript is read without JSX (`<T>x` is an assertion there),
        and read again with it when that fails on a part with a `<` in it -- a `.tsx` file; the
        reading with fewer errors is kept."""
        parser = Parser(text, typescript=self.typescript, jsx=not self.typescript)
        program = parser.program()
        if self.typescript and parser.errors and "<" in text:
            again = Parser(text, typescript=True, jsx=True)
            other = again.program()
            if again.errors < parser.errors:
                return other
        return program

    def _resolve_root(self, scope: Scope, root: str, rest: tuple[str, ...]) -> str:
        """`root.rest...` through the bindings visible from `scope`, following chains."""
        for _ in range(CallResolver.MAX_CHAIN):
            owner = scope.lookup(root)
            if owner is None:
                break
            target = owner.names[root]
            if target.startswith("@"):  # bound to another name: follow it, from where it was bound
                parts = target[1:].split(".")
                root, rest = parts[0], (*parts[1:], *rest)
                scope = owner
                continue
            if target == CallResolver.REQUIRE:
                return ".".join(("require", *rest))
            if target:
                head, *more = target.split(".")
                for cut in range(len(more), 0, -1):
                    prefix = ".".join((head, *more[:cut]))
                    if prefix in CallResolver.GLOBAL_EXPORTS:
                        return ".".join((CallResolver.GLOBAL_EXPORTS[prefix], *more[cut:], *rest))
                return ".".join((target, *rest))
            break  # a local value: its own name
        if root in CallResolver.GLOBALS and rest:
            root, rest = rest[0], rest[1:]
        return ".".join((root, *rest))

    @staticmethod
    def _text(view: Any) -> str:
        chunks, at = [], 0
        while True:
            chunk = view.read(at)
            if not chunk:
                break
            chunks.append(chunk)
            at += len(chunk)
        # surrogateescape: a byte that is not UTF-8 stays one character, so offsets stay exact.
        return b"".join(chunks).decode("utf-8", "surrogateescape")


class _Places:
    """Character offsets in one part to its byte offset, line and byte column in the whole file.

    ASCII text maps characters to bytes one to one; otherwise a byte count is kept at every
    `STEP` characters, so a position costs at most `STEP` characters of encoding, never the file.
    """

    STEP: ClassVar[int] = 1024

    def __init__(
        self, text: str, offset: int, line: int, column: int, errors: str = "surrogatepass"
    ) -> None:
        self.text, self.offset, self.line, self.column, self.errors = (
            text,
            offset,
            line,
            column,
            errors,
        )
        self.ascii = text.isascii()
        self.starts = [0]
        at = text.find("\n")
        while at >= 0:
            self.starts.append(at + 1)
            at = text.find("\n", at + 1)
        self.marks: list[int] = []
        if not self.ascii:
            total = 0
            for at in range(0, len(text), _Places.STEP):
                self.marks.append(total)
                total += len(text[at : at + _Places.STEP].encode("utf-8", errors))

    def _bytes(self, at: int) -> int:
        if self.ascii:
            return at
        block = at // _Places.STEP
        base = block * _Places.STEP
        return (
            self.marks[block] + len(self.text[base:at].encode("utf-8", self.errors))
            if block < len(self.marks)
            else at
        )

    def of(self, at: int) -> tuple[int, int, int]:
        row = bisect.bisect_right(self.starts, at) - 1
        byte = self._bytes(at)
        col = byte - self._bytes(self.starts[row])
        return self.offset + byte, self.line + row + 1, col + (self.column if row == 0 else 0)


class _Walker:
    """Builds the scopes of one part and records its calls."""

    def __init__(self, resolver: CallResolver, module: Scope, places: _Places) -> None:
        self.resolver, self.module, self.places = resolver, module, places
        self.scopes: dict[int, Scope] = {}
        #: Every call met while declaring, with the scope it sits in: resolved once all bindings are known.
        self.found: list[tuple[Node, Scope]] = []

    # -- declarations ---------------------------------------------------------

    def declare(self, root: Node, scope: Scope) -> None:
        """Every binding under `root`, into the scope that owns it; by an explicit stack."""
        stack: list[tuple[Node, Scope]] = [(root, scope)]
        while stack:
            node, here = stack.pop()
            t = node.type
            inner = here
            if t == "CallExpression":
                self.found.append((node, here))
            if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                if t == "FunctionDeclaration" and node["id"] is not None:
                    here.names.setdefault(node["id"]["name"], "")
                inner = Scope(here, function=True)
                self.scopes[id(node)] = inner
                for param in node["params"] or []:
                    for name in _Walker.pattern_names(param):
                        inner.names[name] = ""
            elif (
                t
                in (
                    "BlockStatement",
                    "ForStatement",
                    "ForInStatement",
                    "ForOfStatement",
                    "SwitchStatement",
                    "StaticBlock",
                )
                and node is not root
            ):
                inner = Scope(here)
                self.scopes[id(node)] = inner
            elif t == "CatchClause":
                inner = Scope(here)
                self.scopes[id(node)] = inner
                if node["param"] is not None:
                    for name in _Walker.pattern_names(node["param"]):
                        inner.names[name] = ""
            elif t == "ClassDeclaration" and node["id"] is not None:
                here.names.setdefault(node["id"]["name"], "")
            elif t == "VariableDeclaration":
                owner = here if node["kind"] in ("let", "const") else self._function_scope(here)
                for decl in node["declarations"]:
                    self.bind(decl["id"], decl["init"], owner, constant=node["kind"] == "const")
            elif t == "ImportDeclaration":
                source = node["source"]["value"]
                for spec in node["specifiers"]:
                    local = spec["local"]["name"]
                    if spec.type == "ImportSpecifier":
                        imported = spec["imported"]
                        name = (
                            imported["name"] if imported.type == "Identifier" else imported["value"]
                        )
                        self.module.names[local] = CallResolver.canonical(f"{source}.{name}")
                    else:
                        self.module.names[local] = source
            elif t == "TSImportEquals":
                target = self.origin(node["value"], here)
                here.names[node["id"]["name"]] = target
            elif (
                t == "AssignmentExpression"
                and node["operator"] == "="
                and node["left"].type == "Identifier"
            ):
                name = node["left"]["name"]
                owner = here.lookup(name) or self.module
                target = self.origin(node["right"], here)
                if target and (name not in owner.names or not owner.names[name]):
                    owner.names[name] = target
            # In source order: a binding can name one declared above it (`const r = require`).
            stack.extend((child, inner) for child in reversed(list(Syntax.children(node))))

    @staticmethod
    def _function_scope(scope: Scope) -> Scope:
        """Where a `var` declared in `scope` lives: the nearest function's scope, or the module."""
        s: Scope = scope
        while s.parent is not None and not s.module and not s.function:
            s = s.parent
        return s

    def bind(self, target: Node, init: Node | None, scope: Scope, *, constant: bool) -> None:
        """A declaration's names, with what each is bound to: the origin of `init`, a member of
        it for each property a destructuring takes, or a constant string."""
        if target.type == "Identifier":
            name = target["name"]
            scope.names[name] = self.origin(init, scope) if init is not None else ""
            if constant and init is not None:
                value = self.fold(init, scope)
                if value is not None:
                    scope.constants[name] = value
            return
        base = self.origin(init, scope) if init is not None else ""
        if target.type == "ObjectPattern":
            for prop in target["properties"]:
                if prop.type == "RestElement":
                    for name in _Walker.pattern_names(prop):
                        scope.names[name] = ""
                    continue
                key = prop["key"]
                key_name = (
                    key["name"]
                    if key.type == "Identifier"
                    else key["value"]
                    if key.type == "Literal"
                    else None
                )
                value = prop["value"]
                if value.type == "AssignmentPattern":
                    value = value["left"]
                if value.type == "Identifier":
                    scope.names[value["name"]] = (
                        f"{base}.{key_name}" if base and key_name and not prop["computed"] else ""
                    )
                else:
                    self.bind(value, None, scope, constant=False)
        elif target.type == "ArrayPattern":
            for element in target["elements"]:
                if element is not None:
                    for name in _Walker.pattern_names(element):
                        scope.names[name] = ""
        elif target.type == "AssignmentPattern":
            self.bind(target["left"], init, scope, constant=constant)

    def origin(self, node: Node | None, scope: Scope) -> str:
        """What a value is, as an alias: a module path, `REQUIRE`, a name to follow (`@a.b`), or
        "" when it is not one of those."""
        if node is None:
            return ""
        node = _Walker.unwrap(node)
        t = node.type
        if t == "CallExpression":
            module = self.required(node, scope)
            if module:
                return CallResolver.canonical(module)
            # `createRequire(import.meta.url)`, from `module`: a real `require`, as ES modules make one.
            callee = _Walker.unwrap(node["callee"])
            path = (
                self.member_path(callee, scope)
                if callee.type == "MemberExpression"
                else (callee["name"] if callee.type == "Identifier" else None)
            )
            if path is not None:
                resolved = self.resolver._resolve_root(
                    scope, *CallResolver.split(path.lstrip("\0"))
                )
                if resolved.rsplit(".", 1)[-1] == "createRequire" and resolved.split(".")[0] in (
                    "module",
                    "node:module",
                    "createRequire",
                ):
                    return CallResolver.REQUIRE
            return ""
        if t == "ImportExpression":  # `await import("m")`
            source = self.fold(node["source"], scope)
            return CallResolver.canonical(source) if source else ""
        if t == "Identifier":
            name = node["name"]
            if name == "require" and scope.lookup("require") is None:
                return CallResolver.REQUIRE
            return f"@{name}"
        if t == "MemberExpression":
            path = self.member_path(node, scope)
            if path is None:
                return ""
            return path[1:] if path.startswith("\0") else f"@{path}"  # a module member, or a name
        if t == "AwaitExpression":
            return self.origin(node["argument"], scope)
        return ""

    def required(self, call: Node, scope: Scope) -> str | None:
        """The module a `require("m")`, `r("m")` (`r = require`) or `import("m")` names."""
        callee = _Walker.unwrap(call["callee"])
        if callee.type == "Identifier":
            owner = scope.lookup(callee["name"])
            is_require = (callee["name"] == "require" and owner is None) or (
                owner is not None and owner.names.get(callee["name"]) == CallResolver.REQUIRE
            )
            if is_require and call["arguments"]:
                return self.fold(call["arguments"][0], scope)
        return None

    def member_path(self, node: Node, scope: Scope) -> str | None:
        """`a.b.c` (and `a["b"]`, `require("m").b`) as a dotted path from its root, or None."""
        parts: list[str] = []
        current = node
        for _ in range(CallResolver.MAX_CHAIN):
            current = _Walker.unwrap(current)
            if current.type == "MemberExpression":
                prop = current["property"]
                if current["computed"]:
                    key = self.fold(prop, scope)
                    if key is None:
                        return None
                    parts.append(key)
                elif prop.type in ("Identifier", "PrivateIdentifier"):
                    parts.append(prop["name"])
                else:
                    return None
                current = current["object"]
                continue
            if current.type == "Identifier":
                parts.append(current["name"])
                return ".".join(reversed(parts))
            if current.type == "CallExpression":
                module = self.required(current, scope)
                if module is not None:
                    return "\0" + ".".join((module, *reversed(parts)))  # rooted at a module
            if current.type == "ThisExpression":
                parts.append("this")
                return ".".join(reversed(parts))
            return None
        return None

    # -- calls ----------------------------------------------------------------

    def calls(self, done: list[Any], pending: list[Pending]) -> None:
        """Each call `declare` met, now that every binding of the part is known."""
        for node, here in self.found:
            self.call(node, here, done, pending)

    def call(self, node: Node, scope: Scope, done: list[Any], pending: list[Pending]) -> None:
        callee = _Walker.unwrap(node["callee"])
        if callee.type == "SequenceExpression" and callee["expressions"]:  # `(0, o.f)(...)`
            callee = _Walker.unwrap(callee["expressions"][-1])
        values, built = self.arguments(node["arguments"], scope)
        byte, line, column = self.places.of(node.start)
        rest: tuple[str, ...] = ()
        if callee.type == "Identifier":
            root = callee["name"]
        elif callee.type == "MemberExpression":
            path = self.member_path(callee, scope)
            if path is None:
                return
            if path.startswith("\0"):
                done.append((byte, line, column, path[1:], values, built))
                return
            root, *tail = path.split(".")
            rest = tuple(tail)
        else:
            return
        owner = scope.lookup(root)
        if owner is not None and not owner.module:
            name = self.resolver._resolve_root(scope, root, rest)
            done.append((byte, line, column, name, values, built))
        else:
            pending.append(Pending(byte, line, column, root, rest, values, built))

    def arguments(self, args: list[Node], scope: Scope) -> tuple[list[str], bool]:
        values: list[str] = []
        built = False
        for arg in args:
            folded = self.fold(arg, scope)
            values.append(folded if folded is not None else "")
            if folded is None and _Walker.unwrap(arg).type in CallResolver.BUILT:
                built = True
        return values, built

    # -- values ---------------------------------------------------------------

    def fold(self, node: Node, scope: Scope, depth: int = 0) -> str | None:
        """A constant string value of `node`, or None."""
        if depth > CallResolver.MAX_CHAIN:
            return None
        node = _Walker.unwrap(node)
        t = node.type
        if t == "Literal" and node["kind"] == "string":
            return str(node["value"])
        if t == "TemplateLiteral" and not node["expressions"]:
            return "".join(q["cooked"] for q in node["quasis"])
        if t == "BinaryExpression" and node["operator"] == "+":
            left, right = (
                self.fold(node["left"], scope, depth + 1),
                self.fold(node["right"], scope, depth + 1),
            )
            return left + right if left is not None and right is not None else None
        if t == "Identifier":
            owner = scope.lookup(node["name"])
            return owner.constants.get(node["name"]) if owner is not None else None
        if t == "CallExpression":
            return self._fold_call(node, scope, depth)
        return None

    def _fold_call(self, node: Node, scope: Scope, depth: int) -> str | None:
        callee = _Walker.unwrap(node["callee"])
        args = node["arguments"]
        if callee.type != "MemberExpression" or callee["computed"]:
            return None
        prop = callee["property"]["name"] if callee["property"].type == "Identifier" else None
        obj = _Walker.unwrap(callee["object"])
        if prop == "fromCharCode" and obj.type == "Identifier" and obj["name"] == "String":
            codes: list[int] = []
            for arg in args:
                a = _Walker.unwrap(arg)
                if a.type != "Literal" or a["kind"] != "number":
                    return None
                try:
                    codes.append(int(str(a["value"]).replace("_", ""), 0))
                except ValueError:
                    return None
            return "".join(chr(c) for c in codes if 0 <= c <= 0x10FFFF)
        if prop == "join" and obj.type == "ArrayExpression":
            sep = self.fold(args[0], scope, depth + 1) if args else ","
            items = [
                self.fold(e, scope, depth + 1) if e is not None else "" for e in obj["elements"]
            ]
            if sep is None or any(i is None for i in items):
                return None
            return sep.join(i for i in items if i is not None)
        return None

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def unwrap(node: Node) -> Node:
        while node.type in (
            "ParenthesizedExpression",
            "TSAsExpression",
            "TSTypeAssertion",
            "TSAnnotated",
        ):
            node = node["expression"]
        return node

    @staticmethod
    def pattern_names(node: Node) -> list[str]:
        out: list[str] = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "Identifier":
                out.append(n["name"])
            elif n.type == "ObjectPattern":
                stack.extend(p["value"] if p.type == "Property" else p for p in n["properties"])
            elif n.type == "ArrayPattern":
                stack.extend(e for e in n["elements"] if e is not None)
            elif n.type == "AssignmentPattern":
                stack.append(n["left"])
            elif n.type == "RestElement":
                stack.append(n["argument"])
        return out


__all__ = ["CallResolver", "Scope"]
