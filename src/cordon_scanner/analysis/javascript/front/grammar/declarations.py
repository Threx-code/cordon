"""What a JavaScript program declares: functions with their parameters and bodies, classes and
their members, and the patterns a name is bound through (destructuring, defaults, rest)."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError, TokenStream
from cordon_scanner.analysis.javascript.front.syntax import Node


class Declarations(TokenStream):
    """Functions, classes and binding patterns, for `front.parser.Parser`."""

    # -- functions and classes ----------------------------------------------

    def function(self, type: str, *, optional_name: bool = False) -> Node:
        start = self.tok.start
        is_async = self.eat("async")
        self.expect("function")
        generator = self.eat("*")
        name = None
        if self.tok.kind == "name" and not self.at("("):
            name = self.identifier()
        elif not optional_name and type == "FunctionDeclaration":
            raise ParseError("a function declaration needs a name")
        self._type_parameters()
        params = self.parameters()
        self._type_annotation()
        if self.typescript and not self.at("{"):  # an overload or `declare function`
            self.semicolon()
            return self.node("TSDeclaration", start)
        body = self.function_body()
        return self.node(
            type, start, id=name, params=params, body=body, generator=generator, is_async=is_async
        )

    def function_body(self) -> Node:
        self._deeper()
        try:
            return self.released(self.block())
        finally:
            self.depth -= 1

    def parameters(self) -> list[Node]:
        self.expect("(")
        params: list[Node] = []
        while not self.at(")") and self.tok.kind != "eof":
            self._decorators()
            while (
                self.typescript
                and self.tok.kind == "name"
                and self.tok.value
                in (
                    "public",
                    "private",
                    "protected",
                    "readonly",
                    "override",
                )
                and not self._next_is(",")
                and not self._next_is(")")
                and not self._next_is(":")
            ):
                self.advance()
            pstart = self.tok.start
            if self.eat("..."):
                target = self.binding_target()
                self.eat("?")
                self._type_annotation()
                params.append(self.node("RestElement", pstart, argument=target))
            else:
                target = self.binding_target()
                self.eat("?")
                self._type_annotation()
                if self.eat("="):
                    target = self.node(
                        "AssignmentPattern", pstart, left=target, right=self.assignment()
                    )
                params.append(target)
            if not self.eat(","):
                break
        self.expect(")")
        return params

    def class_(self, type: str, *, optional_name: bool = False) -> Node:
        start = self.tok.start
        self.expect("class")
        name = None
        if self.tok.kind == "name" and not (
            self.at("extends") or self.at("implements") or self.at("{")
        ):
            name = self.identifier()
        elif not optional_name and type == "ClassDeclaration":
            raise ParseError("a class declaration needs a name")
        self._type_parameters()
        superclass = None
        if self.eat("extends"):
            superclass = self.left_hand_side()
            self._type_arguments_maybe()
        if self.eat("implements"):
            self._skip_type_list()
        self.expect("{")
        members: list[Node] = []
        while not self.at("}") and self.tok.kind != "eof":
            if self.eat(";"):
                continue
            members.append(self.class_member())
        self.expect("}")
        return self.node(type, start, id=name, superclass=superclass, body=members)

    def class_member(self) -> Node:
        start = self.tok.start
        self._decorators()
        modifiers = {
            "static",
            "public",
            "private",
            "protected",
            "readonly",
            "abstract",
            "override",
            "declare",
            "accessor",
        }
        while (
            self.tok.kind == "name"
            and self.tok.value in modifiers
            and not self._next_is("(")
            and not self._next_is("=")
            and not self._next_is(";")
            and not self._next_is(":")
        ):
            if self.at("static") and self._next_is("{"):
                self.advance()
                return self.node("StaticBlock", start, body=self.function_body())
            self.advance()
        if self.typescript and self.at("["):  # an index signature, `[key: string]: T`
            state = self.snapshot()
            self.advance()
            if self.tok.kind == "name" and self._next_is(":"):
                self._skip_balanced("[", "]", consumed_open=True)
                self._type_annotation()
                self.semicolon()
                return self.node("TSDeclaration", start)
            self.restore(state)
        is_async = generator = False
        kind = "method"
        if self.at("async") and not self._next_is("(") and not self._next_is("="):
            self.advance()
            is_async = True
        if self.eat("*"):
            generator = True
        if (self.at("get") or self.at("set")) and self._accessor_follows():
            kind = self.advance().value
        key, computed = self.property_key()
        self.eat("?")
        self.eat("!")
        if self.at("(") or self.at("<"):
            self._type_parameters()
            params = self.parameters()
            self._type_annotation()
            if self.typescript and not self.at("{"):
                self.semicolon()
                return self.node("TSDeclaration", start)
            body = self.function_body()
            value = self.node(
                "FunctionExpression",
                start,
                id=None,
                params=params,
                body=body,
                generator=generator,
                is_async=is_async,
            )
            return self.node(
                "MethodDefinition", start, key=key, computed=computed, kind=kind, value=value
            )
        self._type_annotation()
        initial = self.assignment() if self.eat("=") else None
        self.semicolon()
        return self.node("PropertyDefinition", start, key=key, computed=computed, value=initial)

    def property_key(self) -> tuple[Node, bool]:
        start = self.tok.start
        if self.eat("["):
            key = self.assignment()
            self.expect("]")
            return key, True
        t = self.tok
        if t.kind in ("string", "number"):
            return self.literal(), False
        if t.kind == "private":
            self.advance()
            return Node("PrivateIdentifier", start, t.end, name=t.value), False
        if t.kind == "name":
            self.advance()
            return Node("Identifier", start, t.end, name=t.value), False
        raise ParseError(f"a property name expected at {t.start}")

    # -- patterns -------------------------------------------------------------

    def binding_target(self) -> Node:
        start = self.tok.start
        if self.at("[") or self.at("{"):
            expression = self.primary()
            return self.to_pattern(expression)
        if self.tok.kind != "name":
            raise ParseError(f"a binding name expected at {start}")
        return self.identifier()

    def to_pattern(self, node: Node) -> Node:
        """An expression reread as the pattern it was written as (destructuring, arrow params)."""
        t = node.type
        if t == "ObjectExpression":
            props = [self.to_pattern(p) for p in node["properties"]]
            return Node("ObjectPattern", node.start, node.end, properties=props)
        if t == "ArrayExpression":
            items = [self.to_pattern(e) if e is not None else None for e in node["elements"]]
            return Node("ArrayPattern", node.start, node.end, elements=items)
        if t == "Property":
            return Node(
                "Property",
                node.start,
                node.end,
                key=node["key"],
                value=self.to_pattern(node["value"]),
                computed=node["computed"],
                shorthand=node["shorthand"],
            )
        if t == "AssignmentExpression" and node["operator"] == "=":
            return Node(
                "AssignmentPattern",
                node.start,
                node.end,
                left=self.to_pattern(node["left"]),
                right=node["right"],
            )
        if t == "SpreadElement":
            return Node(
                "RestElement", node.start, node.end, argument=self.to_pattern(node["argument"])
            )
        if t == "TSAnnotated":  # `(a: T) =>` read as an annotated name
            return self.to_pattern(node["expression"])
        return node
