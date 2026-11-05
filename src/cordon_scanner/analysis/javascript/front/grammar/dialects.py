"""The parts of the grammar beyond ECMAScript: JSX elements, whose attribute and child expressions
are parsed, and TypeScript's declarations and decorators, passed over exactly."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError, TokenStream
from cordon_scanner.analysis.javascript.front.syntax import Node


class Dialects(TokenStream):
    """JSX and TypeScript declarations, for `front.parser.Parser`."""

    # -- JSX -----------------------------------------------------------------

    def jsx_element(self) -> Node:
        """`<a b={x}>{y}</a>` and fragments: the expressions in attributes and children are parsed;
        the text between them is passed over."""
        start = self.expect("<").start
        if self.eat(">"):  # a fragment
            children = self._jsx_children()
            self.expect(">")
            return self.node("JSXFragment", start, children=children)
        name = self._jsx_name()
        if self.typescript and self.at("<"):
            self._type_arguments_maybe()
        attributes: list[Node] = []
        while not (self.at("/") or self.at(">") or self.tok.kind == "eof"):
            astart = self.tok.start
            if self.eat("{"):
                self.expect("...")
                attributes.append(
                    self.node("JSXSpreadAttribute", astart, argument=self.assignment())
                )
                self.expect("}")
                continue
            attr = self._jsx_name()
            value: Node | None = None
            if self.eat("="):
                if self.tok.kind == "string":
                    value = self.literal()
                elif self.eat("{"):
                    value = self.assignment()
                    self.expect("}")
                elif self.at("<"):
                    value = self.jsx_element()
            attributes.append(self.node("JSXAttribute", astart, name=attr, value=value))
        if self.eat("/"):
            self.expect(">")
            return self.node("JSXElement", start, name=name, attributes=attributes, children=[])
        self.expect(">")
        children = self._jsx_children()
        if not self.at(">"):
            self._jsx_name()
        self.expect(">")
        return self.node("JSXElement", start, name=name, attributes=attributes, children=children)

    def _jsx_name(self) -> Node:
        start = self.tok.start
        parts = [self.identifier()["name"]]
        while self.at(".") or self.at(":") or self.at("-"):
            parts.append(self.advance().value)
            if self.tok.kind == "name":
                parts.append(self.advance().value)
        return self.node("JSXName", start, name="".join(parts))

    def _jsx_children(self) -> list[Node]:
        """Children up to the closing `</`: text is skipped character by character in the source
        (it is not JavaScript), and `{...}` and nested elements are parsed."""
        children: list[Node] = []
        text, n = self.text, len(self.text)
        pos = self.tok.start
        while pos < n:
            c = text[pos]
            if c == "{":
                self._relex_at(pos)
                self.advance()
                if not self.at("}"):
                    children.append(self.expression())
                self.expect("}")
                pos = self.prev.end
            elif c == "<":
                if text.startswith("</", pos):  # the closing tag: read from the source, since
                    self._relex_at(pos + 2)  # after `<` a lexer would take `/div>` for a regex
                    return children
                self._relex_at(pos)
                children.append(self.jsx_element())
                pos = self.prev.end
            else:
                pos += 1
        self._relex_at(n)
        raise ParseError("an unclosed JSX element")

    # -- TypeScript ------------------------------------------------------------

    def _decorators(self) -> None:
        while self.at("@"):
            self.advance()
            self.left_hand_side()

    def _typescript_declaration(self) -> bool:
        """`interface`, `type X =`, `enum`, `declare ...`, `namespace` and `module`, `abstract
        class`: passed over (an enum and a namespace have bodies that run, read as blocks)."""
        v = self.tok.value
        if v == "interface" and self._next_kind_is("name"):
            self.advance()
            self.identifier()
            self._type_parameters()
            if self.eat("extends"):
                self._skip_type_list()
            self._skip_balanced("{", "}")
            return True
        if v == "type" and self._next_kind_is("name"):
            state = self.snapshot()
            self.advance()
            self.identifier()
            self._type_parameters()
            if not self.eat("="):
                self.restore(state)
                return False
            self.skip_type()
            self.semicolon()
            return True
        if v == "enum" or (v == "const" and self._next_is("enum")):
            self.eat("const")
            self.advance()
            self.identifier()
            self._skip_balanced("{", "}")
            return True
        if v == "declare" and self._next_kind_is("name"):
            self.advance()
            if self.at("global") or self.at("module") or self.at("namespace"):
                self.advance()
                if self.tok.kind in ("name", "string"):
                    self.advance()
                    while self.eat("."):
                        self.identifier()
                if self.at("{"):
                    self._skip_balanced("{", "}")
                else:
                    self.semicolon()
                return True
            self.statement()
            return True
        return False

    # -- TypeScript's type syntax, which the scanner skips: read past, never kept ----------------

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
