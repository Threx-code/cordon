"""Reading the calls an MCP server makes to the client through the protocol (elicitation, sampling): the call, the
strings it is given, and the values a name in it stands for, in JavaScript or TypeScript and in Python.

Only what the call itself says is collected: its string literals, the keys of the objects it is given, and one level
of a name bound in the same file (a prompt or a schema kept in a constant, a model class). Read from text with the
tree each language's own front end gives; nothing is imported or run.
"""

from __future__ import annotations

import ast
from typing import Final

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax
from cordon_scanner.analysis.python.pysyntax import PythonSyntax

MAX_CHARS: Final = 2_000_000


class ProtocolReading:
    # -- JavaScript and TypeScript ---------------------------------------------------------------

    @staticmethod
    def program(text: str, typescript: bool) -> Node | None:
        """The syntax tree of a source file, or None when it is too large to read."""
        if len(text) > MAX_CHARS:
            return None
        return Parser(text, typescript=typescript).program()

    @staticmethod
    def js_callee(call: Node) -> str | None:
        """The name a call is made by: `f` for `f(...)`, `m` for `a.b.m(...)`."""
        callee = call["callee"]
        if callee is None:
            return None
        if callee.type == "Identifier":
            return str(callee["name"])
        if callee.type == "MemberExpression":
            prop = callee["property"]
            if prop is not None and prop.type in ("Identifier", "PrivateIdentifier"):
                return str(prop["name"])
        return None

    @staticmethod
    def js_literal(node: Node | None) -> str | None:
        """The text of a string literal or of a template with nothing in it, else None."""
        if node is None:
            return None
        if node.type == "Literal" and isinstance(node["value"], str):
            return str(node["value"])
        if node.type == "TemplateLiteral" and not node["expressions"]:
            return "".join(q["cooked"] or "" for q in node["quasis"] or [])
        return None

    @classmethod
    def js_key(cls, node: Node | None) -> str | None:
        """The name of an object key, written as a name or as a string."""
        if node is None:
            return None
        if node.type == "Identifier":
            return str(node["name"])
        return cls.js_literal(node)

    @classmethod
    def js_names_method(cls, call: Node, method: str) -> bool:
        """Whether a call is the raw request of a protocol method: `request({ method: "m", ... })` or `send("m", ...)`."""
        for argument in call["arguments"] or []:
            if cls.js_literal(argument) == method:
                return True
            if argument.type == "ObjectExpression":
                for prop in argument["properties"] or []:
                    if (
                        prop.type == "Property"
                        and cls.js_key(prop["key"]) == "method"
                        and cls.js_literal(prop["value"]) == method
                    ):
                        return True
        return False

    @staticmethod
    def js_bindings(program: Node) -> dict[str, Node]:
        """The value each name of the file is declared with (`const schema = {...}`)."""
        bound: dict[str, Node] = {}
        for node in Syntax.walk(program):
            if (
                node.type == "VariableDeclarator"
                and node["id"] is not None
                and node["id"].type == "Identifier"
                and node["init"] is not None
            ):
                bound.setdefault(str(node["id"]["name"]), node["init"])
        return bound

    @classmethod
    def js_strings(cls, node: Node, bound: dict[str, Node], out: list[str], depth: int = 0) -> None:
        """What a call argument says: its string literals, the keys of the objects in it, and the value a name in it
        is declared with (one level)."""
        for part in Syntax.walk(node):
            if part.type in ("Literal", "TemplateLiteral"):
                value = cls.js_literal(part)
                if value:
                    out.append(value)
            elif part.type == "Property":
                key = cls.js_key(part["key"])
                if key:
                    out.append(key)
            elif (
                part.type == "Identifier"
                and depth < 2
                and part["name"] in bound
                and part is not node
            ):
                cls.js_strings(bound[part["name"]], bound, out, depth + 1)
        if node.type == "Identifier" and depth < 2 and node["name"] in bound:
            cls.js_strings(bound[node["name"]], bound, out, depth + 1)

    @staticmethod
    def js_identifiers(node: Node) -> set[str]:
        """The names used anywhere under a node."""
        return {str(n["name"]) for n in Syntax.walk(node) if n.type == "Identifier" and n["name"]}

    # -- Python ----------------------------------------------------------------------------------

    @staticmethod
    def py_tree(text: str) -> ast.Module | None:
        """The syntax tree of a Python source file, or None when it does not parse or is too large."""
        if len(text) > MAX_CHARS:
            return None
        try:
            tree: ast.Module = PythonSyntax.parse(text)
            return tree
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # S2: a file that does not parse says nothing here; the engine records its own parse gap
            return None

    @staticmethod
    def py_name(call: ast.Call) -> str | None:
        """The name a call is made by: `f` for `f(...)`, `m` for `a.b.m(...)`."""
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    @staticmethod
    def py_arguments(call: ast.Call) -> list[ast.expr]:
        return [*call.args, *(k.value for k in call.keywords)]

    @classmethod
    def py_names_method(cls, call: ast.Call, method: str) -> bool:
        return any(
            isinstance(n, ast.Constant) and n.value == method
            for argument in cls.py_arguments(call)
            for n in ast.walk(argument)
        )

    @staticmethod
    def py_scope(tree: ast.Module) -> tuple[dict[str, ast.ClassDef], dict[str, ast.expr]]:
        """The classes of the file by name, and the value each plain assignment gives a name."""
        classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        values: dict[str, ast.expr] = {}
        for n in ast.walk(tree):
            if (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
            ):
                values.setdefault(n.targets[0].id, n.value)
        return classes, values

    @classmethod
    def py_strings(
        cls,
        node: ast.AST,
        scope: tuple[dict[str, ast.ClassDef], dict[str, ast.expr]],
        out: list[str],
        depth: int = 0,
    ) -> None:
        """What a call argument says: its strings, the fields of a model class it names, and the value a name in it
        is assigned (one level)."""
        classes, values = scope
        for part in ast.walk(node):
            match part:
                case ast.Constant(value=str() as text):
                    out.append(text)
                case ast.Name(id=name) if depth < 2:
                    if name in classes:
                        out.extend(cls.py_fields(classes[name]))
                    elif name in values and part is not node:
                        cls.py_strings(values[name], scope, out, depth + 1)
        if (
            isinstance(node, ast.Name)
            and depth < 2
            and node.id in values
            and node.id not in classes
        ):
            cls.py_strings(values[node.id], scope, out, depth + 1)

    @staticmethod
    def py_fields(definition: ast.ClassDef) -> list[str]:
        """The names of the fields a model class declares, and the strings in its body."""
        out: list[str] = []
        for member in ast.walk(definition):
            match member:
                case ast.AnnAssign(target=ast.Name(id=name)):
                    out.append(name)
                case ast.Assign(targets=targets):
                    out.extend(t.id for t in targets if isinstance(t, ast.Name))
                case ast.Constant(value=str() as text):
                    out.append(text)
        return out

    @staticmethod
    def py_names(node: ast.AST) -> set[str]:
        """The names used anywhere under a node."""
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


__all__ = ["MAX_CHARS", "ProtocolReading"]
