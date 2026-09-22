"""Per-language resolvers behind the `kind: ast` match kind.

The `ast` match kind resolves a call through imports, aliases, bindings and
folded constants, so a rule that names `child_process.exec` matches it however
the call site spells it. That resolution is language-specific, so it lives
behind a provider: the core ships the Python one (stdlib `ast`, always
available), and other languages are added by installing an optional extra that
carries a parser.

One shape, every language. A provider returns `AstCall` records -- the same
records the Python resolver produces and the same ones `AstQuery` consumes -- so
a single `kind: ast` rule applies to every language a provider exists for, with
no per-language rule authoring.

Absent is stated, never silent. A rule whose language has no installed provider
simply does not match there, and the capability detector records a coverage note
naming the extra to install, the same way a pruned directory or an untraced
sandbox run is reported. A missing provider is a smaller scan, and this project
does not let a smaller scan look like a clean one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cordon_scanner.detect.pyast import AstCall


class AstProvider(Protocol):
    """Resolves the calls in one language's source into `AstCall` records."""

    def resolve_calls(self, source: str) -> list[AstCall]: ...


class PythonAstProvider:
    """The built-in Python provider, over the stdlib `ast`.

    A thin adapter: `pyast.PythonAnalyzer.calls` already produces `AstCall`
    records with imports, aliases, bindings and folded constants resolved, so
    this only names it as the provider for `python`.
    """

    def resolve_calls(self, source: str) -> list[AstCall]:
        from cordon_scanner.detect.pyast import PythonAnalyzer

        return PythonAnalyzer.calls(source)


#: Languages the optional `[ast-js]` extra covers, mapped to the tree-sitter
#: grammar module that parses each. Kept here rather than in the provider so the
#: registry can answer "is there a provider for this language" without importing
#: tree-sitter.
_TREE_SITTER_LANGUAGES: dict[str, str] = {
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
}

_CACHE: dict[str, AstProvider | None] = {}


def ast_provider_for(language: str | None) -> AstProvider | None:
    """The provider for a language, or None when none is installed.

    None is a real answer: the caller reports it as a coverage limit rather than
    treating the language as scanned. Cached per language, including the None, so
    a missing extra costs one import attempt per process, not one per file.
    """
    if not language:
        return None
    if language in _CACHE:
        return _CACHE[language]

    provider: AstProvider | None
    if language == "python":
        provider = PythonAstProvider()
    elif language in _TREE_SITTER_LANGUAGES:
        provider = _build_tree_sitter_provider(language)
    else:
        provider = None
    _CACHE[language] = provider
    return provider


def missing_provider_language(language: str | None) -> str | None:
    """The name of the extra to install for a language that could have a provider
    but does not, or None. Lets the detector say what to install rather than only
    that something is missing."""
    if language in _TREE_SITTER_LANGUAGES and ast_provider_for(language) is None:
        return "ast-js"
    return None


def _build_tree_sitter_provider(language: str) -> AstProvider | None:
    try:
        return _TreeSitterProvider(language)
    except ImportError:
        return None


class _TreeSitterProvider:
    """A JS/TS provider over tree-sitter, resolving the same shapes the Python
    resolver does: a call's real target through `require`/`import` aliases and
    member access, its string arguments folded, and whether an argument is built
    at runtime rather than written whole.

    Constructed here rather than imported at module scope so the core never
    imports tree-sitter unless a JS/TS file is actually scanned with the extra
    installed.
    """

    def __init__(self, language: str) -> None:
        from tree_sitter import Language, Parser

        grammar_module = __import__(_TREE_SITTER_LANGUAGES[language])
        # tree-sitter-typescript exposes two grammars; the plain TypeScript one
        # parses the superset of ordinary code this needs.
        grammar = (
            grammar_module.language_typescript()
            if language == "typescript"
            else grammar_module.language()
        )
        self._parser = Parser(Language(grammar))

    def resolve_calls(self, source: str) -> list[AstCall]:
        from cordon_scanner.detect.pyast import AstCall

        data = source.encode("utf-8", "surrogatepass")
        try:
            tree = self._parser.parse(data)
        except (ValueError, RecursionError):
            return []
        root = tree.root_node

        # One walk, not two: a walk yields every named node in the file, and
        # aliases and calls are both found during it. Calls are collected here
        # and resolved below, after the walk, because an alias declared further
        # down the file still governs a call above it.
        aliases: dict[str, str] = {}
        calls: list[Any] = []
        for node in _descendants(root):
            kind = node.type
            if kind == "call_expression":
                calls.append(node)
            elif kind == "variable_declarator":
                self._alias_from_require(node, data, aliases)
            elif kind == "import_statement":
                self._alias_from_import(node, data, aliases)

        out: list[AstCall] = []
        for node in calls:
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            name = self._resolve_callee(func, data, aliases)
            if name is None:
                continue
            positional, constructed = self._arguments(args, data)
            out.append(
                AstCall(
                    name=name,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=tuple(positional),
                    keywords=(),
                    has_constructed_argument=constructed,
                )
            )
        return out

    #: Local name -> the module (or module member) it refers to, built during
    #: the single walk in `resolve_calls`. `const cp = require("child_process")`
    #: maps `cp` to `child_process`; `const { exec } = require("child_process")`
    #: maps `exec` to `child_process.exec`; the ESM `import` forms map the same
    #: way.

    def _alias_from_require(self, node: Any, data: bytes, aliases: dict[str, str]) -> None:
        value = node.child_by_field_name("value")
        module = self._require_target(value, data)
        if module is None:
            return
        target = node.child_by_field_name("name")
        if target is None:
            return
        if target.type == "identifier":
            aliases[_text(target, data)] = module
        elif target.type == "object_pattern":
            # `const { exec, spawn } = require("child_process")`
            for child in target.named_children:
                key = child.child_by_field_name("key") or child
                if key.type == "shorthand_property_identifier_pattern" or key.type == "identifier":
                    aliases[_text(key, data)] = f"{module}.{_text(key, data)}"

    def _require_target(self, value: Any, data: bytes) -> str | None:
        if value is None or value.type != "call_expression":
            return None
        func = value.child_by_field_name("function")
        if func is None or _text(func, data) != "require":
            return None
        args = value.child_by_field_name("arguments")
        for child in args.named_children if args else []:
            if child.type == "string":
                return _string_value(child, data)
        return None

    def _alias_from_import(self, node: Any, data: bytes, aliases: dict[str, str]) -> None:
        module: str | None = None
        clause = None
        for child in node.named_children:
            if child.type == "string":
                module = _string_value(child, data)
            elif child.type == "import_clause":
                clause = child
        if module is None or clause is None:
            return
        # The import_clause's DIRECT children are the forms; walking descendants
        # instead caught the identifiers nested inside a specifier and mapped a
        # named alias to the bare module. `import { spawn as sp }` must map `sp`
        # to `module.spawn`, not to `module`.
        for item in clause.named_children:
            if item.type == "identifier":
                # `import cp from "m"` -> cp -> m
                aliases[_text(item, data)] = module
            elif item.type == "namespace_import":
                # `import * as ns from "m"` -> ns -> m
                idents = [c for c in item.named_children if c.type == "identifier"]
                if idents:
                    aliases[_text(idents[-1], data)] = module
            elif item.type == "named_imports":
                for spec in item.named_children:
                    if spec.type != "import_specifier":
                        continue
                    idents = [c for c in spec.named_children if c.type == "identifier"]
                    if len(idents) == 1:
                        # `import { exec }` -> exec -> m.exec
                        aliases[_text(idents[0], data)] = f"{module}.{_text(idents[0], data)}"
                    elif len(idents) >= 2:
                        # `import { exec as e }` -> e -> m.exec
                        aliases[_text(idents[1], data)] = f"{module}.{_text(idents[0], data)}"

    def _resolve_callee(self, func: Any, data: bytes, aliases: dict[str, str]) -> str | None:
        if func is None:
            return None
        if func.type == "identifier":
            name = _text(func, data)
            return aliases.get(name, name)
        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            if obj.type == "identifier":
                base = aliases.get(_text(obj, data), _text(obj, data))
                return f"{base}.{_text(prop, data)}"
        return None

    def _arguments(self, args: Any, data: bytes) -> tuple[list[str], bool]:
        if args is None:
            return [], False
        values: list[str] = []
        constructed = False
        for child in args.named_children:
            if child.type == "comment":
                continue
            folded = _fold(child, data)
            values.append(folded or "")
            if folded is None and _is_built(child):
                constructed = True
        return values, constructed


def _descendants(node: Any) -> Any:
    """Every named node under `node`, including it.

    Named children only. Anonymous nodes are the grammar's punctuation -- every
    brace, parenthesis, semicolon and operator -- and they are leaves, so
    skipping them reaches exactly the same named nodes while walking roughly
    half the tree. The three types this module looks for are all named.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.named_children)


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _string_value(node: Any, data: bytes) -> str:
    """The content of a string literal, without its surrounding quotes."""
    raw = _text(node, data)
    if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
        return raw[1:-1]
    return raw


def _fold(node: Any, data: bytes) -> str | None:
    """A node's constant string value, or None if it is not a plain constant.

    Mirrors the Python resolver: a string literal folds to its content, a `+`
    of constants folds to their concatenation, and everything else -- a name, a
    call, a template with an expression -- is not constant.
    """
    if node.type == "string":
        return _string_value(node, data)
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        operator = node.child_by_field_name("operator")
        if operator is not None and _text(operator, data) == "+":
            lv, rv = _fold(left, data), _fold(right, data)
            if lv is not None and rv is not None:
                return lv + rv
    if node.type == "template_string" and not any(
        c.type == "template_substitution" for c in node.named_children
    ):
        return _text(node, data).strip("`")
    return None


def _is_built(node: Any) -> bool:
    """Whether a non-constant argument is built at runtime rather than a bare name."""
    return node.type in {
        "binary_expression",
        "template_string",
        "call_expression",
        "subscript_expression",
        "member_expression",
        "ternary_expression",
    }


__all__ = ["AstProvider", "PythonAstProvider", "ast_provider_for", "missing_provider_language"]
