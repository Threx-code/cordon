"""The token stream the JavaScript parser reads: one token of lookahead with snapshots to back up
to, the operator and statement tables, depth bounding, the literals and names every part of the
grammar reads, and the TypeScript types it passes over without building nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.javascript.front.lexer import Lexer, Token
from cordon_scanner.analysis.javascript.front.syntax import Node


class ParseError(Exception):
    """A construct the parser could not read; caught at the statement it is in."""


class TokenStream:
    """What every part of `front.parser.Parser`'s grammar reads through: the current token, how to
    move past it, and the shapes read the same way everywhere."""

    MAX_DEPTH: ClassVar[int] = 400
    LOOKAHEAD: ClassVar[int] = 512

    #: Binary operators by precedence, low to high.
    BINARY: ClassVar[dict[str, int]] = {
        "??": 1,
        "||": 2,
        "&&": 3,
        "|": 4,
        "^": 5,
        "&": 6,
        "==": 7,
        "!=": 7,
        "===": 7,
        "!==": 7,
        "<": 8,
        ">": 8,
        "<=": 8,
        ">=": 8,
        "instanceof": 8,
        "in": 8,
        "as": 8,
        "satisfies": 8,
        "<<": 9,
        ">>": 9,
        ">>>": 9,
        "+": 10,
        "-": 10,
        "*": 11,
        "/": 11,
        "%": 11,
        "**": 12,
    }
    ASSIGN: ClassVar[frozenset[str]] = frozenset(
        [
            "=",
            "+=",
            "-=",
            "*=",
            "/=",
            "%=",
            "**=",
            "<<=",
            ">>=",
            ">>>=",
            "&=",
            "|=",
            "^=",
            "&&=",
            "||=",
            "??=",
        ]
    )
    #: After these a `/` begins a regular expression.
    REGEX_AFTER_NAME: ClassVar[frozenset[str]] = frozenset(
        [
            "return",
            "typeof",
            "case",
            "in",
            "of",
            "delete",
            "void",
            "throw",
            "new",
            "else",
            "do",
            "yield",
            "await",
            "instanceof",
            "extends",
        ]
    )
    VALUE_END: ClassVar[frozenset[str]] = frozenset({")", "]", "}"})
    STATEMENT_START: ClassVar[frozenset[str]] = frozenset(
        [
            "var",
            "let",
            "const",
            "function",
            "class",
            "if",
            "for",
            "while",
            "do",
            "return",
            "throw",
            "try",
            "switch",
            "break",
            "continue",
            "import",
            "export",
            "async",
        ]
    )

    #: Tokens that, first on a line at bracket level, begin a statement rather than continue one.
    LINE_START_KINDS: ClassVar[frozenset[str]] = frozenset(
        {"name", "string", "number", "template", "template_head"}
    )

    def __init__(self, text: str, *, typescript: bool = False, jsx: bool = True) -> None:
        self.text = text
        self.typescript = typescript
        self.jsx = jsx
        self.lexer = Lexer(text)
        self.depth = 0
        self.errors = 0
        self.prev = Token("punct", ";", 0, 0, False)
        self.tok = self.lexer.next(regex=True)

    # -- token stream ---------------------------------------------------------

    def _regex_next(self) -> bool:
        """Whether a `/` after the current token begins a regular expression."""
        t = self.tok
        if t.kind in ("number", "string", "template", "template_tail", "regex", "private"):
            return False
        if t.kind == "name":
            return t.value in TokenStream.REGEX_AFTER_NAME
        return not (t.kind == "punct" and t.value in TokenStream.VALUE_END)

    def advance(self) -> Token:
        current = self.tok
        self.prev = current
        self.tok = self.lexer.next(regex=self._regex_next())
        return current

    def at(self, value: str) -> bool:
        return self.tok.kind in ("punct", "name") and self.tok.value == value

    def eat(self, value: str) -> bool:
        if self.at(value):
            self.advance()
            return True
        return False

    def expect(self, value: str) -> Token:
        if not self.at(value):
            raise ParseError(f"expected {value!r} at {self.tok.start}")
        return self.advance()

    def snapshot(self) -> tuple[Any, ...]:
        lx = self.lexer
        return (lx.pos, list(lx.braces), lx.newline, self.tok, self.prev)

    def restore(self, state: tuple[Any, ...]) -> None:
        lx = self.lexer
        lx.pos, braces, lx.newline, self.tok, self.prev = state
        lx.braces = list(braces)

    def semicolon(self) -> None:
        """A statement's end: `;`, or where automatic semicolon insertion puts one."""
        if self.eat(";") or self.at("}") or self.tok.kind == "eof" or self.tok.newline:
            return
        raise ParseError(f"expected ';' at {self.tok.start}")

    def node(self, type: str, start: int, **fields: Any) -> Node:
        return Node(type, start, self.prev.end, **fields)

    def _deeper(self) -> None:
        self.depth += 1
        if self.depth > TokenStream.MAX_DEPTH:
            raise ParseError("nested past the parser's depth")

    def _async_function(self) -> bool:
        state = self.snapshot()
        self.advance()
        yes = self.at("function") and not self.tok.newline
        self.restore(state)
        return yes

    def _next_is(self, value: str) -> bool:
        state = self.snapshot()
        self.advance()
        yes = self.at(value)
        self.restore(state)
        return yes

    def _accessor_follows(self) -> bool:
        """Whether a `get` or `set` here is an accessor's keyword: a property name follows it on
        the same line -- otherwise it is a member named `get`."""
        state = self.snapshot()
        self.advance()
        t = self.tok
        yes = not t.newline and (t.kind in ("name", "string", "number", "private") or self.at("["))
        self.restore(state)
        return yes

    @staticmethod
    def _is_async_name(node: Node) -> bool:
        return node.type == "Identifier" and node["name"] == "async"

    def _member_name(self) -> Node:
        t = self.tok
        if t.kind == "private":
            self.advance()
            return Node("PrivateIdentifier", t.start, t.end, name=t.value)
        if t.kind != "name":
            raise ParseError(f"a property name expected at {t.start}")
        self.advance()
        return Node("Identifier", t.start, t.end, name=t.value)

    def literal(self) -> Node:
        t = self.advance()
        if t.kind not in ("string", "number", "regex"):
            raise ParseError(f"a literal expected at {t.start}")
        return Node(
            "Literal", t.start, t.end, value=t.value, raw=self.text[t.start : t.end], kind=t.kind
        )

    def identifier(self) -> Node:
        t = self.tok
        if t.kind != "name":
            raise ParseError(f"a name expected at {t.start}")
        self.advance()
        return Node("Identifier", t.start, t.end, name=t.value)

    def _relex_at(self, pos: int) -> None:
        self.lexer.pos = pos
        self.lexer.newline = False
        self.tok = self.lexer.next(regex=False)

    def _next_kind_is(self, kind: str) -> bool:
        state = self.snapshot()
        self.advance()
        yes = self.tok.kind == kind and not self.tok.newline
        self.restore(state)
        return yes

    def _type_annotation(self) -> None:
        if self.typescript and self.eat(":"):
            self.skip_type()

    def _type_parameters(self) -> None:
        if self.typescript and self.at("<"):
            self._skip_balanced("<", ">")

    def _type_arguments_maybe(self) -> bool:
        """`f<T>(...)`, `new C<T>()`, `a<T>` before a template: type arguments when a balanced
        `<...>` of at most `LOOKAHEAD` tokens is followed by `(` or a template; otherwise `<` is
        less-than and nothing is consumed."""
        state = self.snapshot()
        try:
            self._skip_balanced("<", ">", limit=TokenStream.LOOKAHEAD)
        except ParseError:
            self.restore(state)
            return False
        if (
            self.at("(")
            or self.tok.kind in ("template", "template_head")
            or self.at(")")
            or self.at(",")
            or self.at(";")
        ):
            return True
        self.restore(state)
        return False

    def skip_type(self, *, arrow_ends: bool = False) -> None:
        """One type, passed over: tokens to the first `,`, `)`, `]`, `}`, `;`, `=`, `{` or `=>`
        outside every bracket -- extended past `=>` for a function type, past `extends ? :` for a
        conditional type, past `|`, `&`, `.`, `[]`, `<...>` and `keyof`/`typeof` operators."""
        level = 0
        moved = False
        while self.tok.kind != "eof":
            t = self.tok
            v = t.value if t.kind in ("punct", "name") else None
            if level == 0 and moved:
                if v in (",", ")", "]", "}", ";", "=") or (v == ">" and not self._type_continues()):
                    return
                if v == "{" and not self._type_object_allowed():
                    return
                if t.newline and v not in ("|", "&", "?", ":", "=>", "extends", "."):
                    return
                if v == "=>":
                    if arrow_ends:  # an arrow's return type ends where its body begins
                        return
                    self.advance()
                    moved = False
                    continue
                if v in ("as", "satisfies") and t.kind == "name":
                    return
            if v in ("(", "[", "{", "<"):
                level += 1
            elif v in (")", "]", "}", ">"):
                level -= 1
                if level < 0:
                    return
            elif v == ">>" and level >= 2:
                level -= 2
            elif v == ">>>" and level >= 3:
                level -= 3
            self.advance()
            moved = True
            if (
                level == 0
                and self.at("{")
                and self.prev.value
                in ("|", "&", ":", "=>", "<", ",", "(", "keyof", "typeof", "extends", "?")
            ):
                continue

    def _type_continues(self) -> bool:
        return False

    def _type_object_allowed(self) -> bool:
        return self.prev.value in (
            "|",
            "&",
            ":",
            "=>",
            "<",
            ",",
            "(",
            "extends",
            "?",
            "keyof",
            "typeof",
            "readonly",
            "as",
            "satisfies",
            "=",
            "is",
            "asserts",
        )

    def _skip_type_list(self) -> None:
        self.skip_type()
        while self.eat(","):
            self.skip_type()

    def _skip_balanced(
        self, open_: str, close: str, *, consumed_open: bool = False, limit: int | None = None
    ) -> None:
        if not consumed_open:
            self.expect(open_)
        level, steps, braces = 1, 0, 0
        while level > 0:
            if self.tok.kind == "eof":
                raise ParseError(f"unclosed {open_!r}")
            steps += 1
            if limit is not None and steps > limit:
                raise ParseError("past the lookahead")
            v = self.tok.value if self.tok.kind == "punct" else None
            if open_ == "<" and v in ("{", "}"):
                braces += 1 if v == "{" else -1
            if v == open_:
                level += 1
            elif v == close:
                level -= 1
            elif open_ == "<" and v == ">>":
                level -= 2
            elif open_ == "<" and v == ">>>":
                level -= 3
            elif open_ == "<" and v == ";" and braces <= 0 and limit is not None:
                raise ParseError("not type arguments")
            self.advance()

    if TYPE_CHECKING:
        # The grammar is one mutually recursive component: statements, declarations, expressions,
        # JSX and TypeScript all read each other. These declare, once, what each area calls in the
        # others; the one real definition of each is in its area's class, and mypy checks it
        # against this signature. Nothing here exists at run time.

        def assignment(self, *, no_in: bool = False) -> Node: ...

        def expression(self, *, no_in: bool = False) -> Node: ...

        def left_hand_side(self) -> Node: ...

        def statement(self) -> Node: ...
