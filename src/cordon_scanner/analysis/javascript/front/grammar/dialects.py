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
