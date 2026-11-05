"""JavaScript expressions, by precedence climbing: assignment and arrows (a parenthesised list read
once and reread as parameters when `=>` follows), conditionals, binary and unary operators,
member chains and calls, and the literals."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError, TokenStream
from cordon_scanner.analysis.javascript.front.syntax import Node


class Expressions(TokenStream):
    """Expressions, for `front.parser.Parser`."""

    # -- expressions ----------------------------------------------------------

    def expression(self, *, no_in: bool = False) -> Node:
        start = self.tok.start
        first = self.assignment(no_in=no_in)
        if not self.at(","):
            return first
        items = [first]
        while self.eat(","):
            if self.at(")"):  # a trailing comma in arrow parameters
                break
            items.append(self.assignment(no_in=no_in))
        return self.node("SequenceExpression", start, expressions=items)

    def assignment(self, *, no_in: bool = False) -> Node:
        self._deeper()
        try:
            return self._assignment(no_in)
        finally:
            self.depth -= 1

    def _assignment(self, no_in: bool) -> Node:
        start = self.tok.start
        if self.at("yield") and self._in_generator_context():
            self.advance()
            delegate = self.eat("*")
            argument = None
            if not (
                self.tok.newline
                or self.at(")")
                or self.at("]")
                or self.at("}")
                or self.at(",")
                or self.at(";")
                or self.at(":")
                or self.tok.kind == "eof"
            ):
                argument = self.assignment(no_in=no_in)
            return self.node("YieldExpression", start, argument=argument, delegate=delegate)
        arrow = self._arrow_from_name()
        if arrow is not None:
            return arrow
        left = self.conditional(no_in=no_in)
        if left.type == "ArrowPending":
            return self._arrow_body(left, start)
        if self.tok.kind == "punct" and self.tok.value in TokenStream.ASSIGN:
            operator = self.advance().value
            target = self.to_pattern(left) if operator == "=" else left
            right = self.assignment(no_in=no_in)
            return self.node(
                "AssignmentExpression", start, operator=operator, left=target, right=right
            )
        return left

    def _in_generator_context(self) -> bool:
        # `yield` is a name outside generators; as an expression it reads the same either way for
        # what this front end resolves, so it is parsed as one whenever an operand follows.
        state = self.snapshot()
        self.advance()
        operand = not (
            self.at(")")
            or self.at("]")
            or self.at(",")
            or self.at(";")
            or self.at("=")
            or self.at(".")
        )
        self.restore(state)
        return operand

    def _arrow_from_name(self) -> Node | None:
        """`x => ...` and `async x => ...`."""
        if self.tok.kind != "name":
            return None
        state = self.snapshot()
        start = self.tok.start
        is_async = False
        if self.at("async") and not self._next_is("=>"):
            self.advance()
            if self.tok.kind != "name" or self.tok.newline:
                self.restore(state)
                return None
            is_async = True
        name = self.advance()
        if not self.at("=>") or self.tok.newline:
            self.restore(state)
            return None
        param = Node("Identifier", name.start, name.end, name=name.value)
        pending = Node("ArrowPending", start, name.end, params=[param], is_async=is_async)
        return self._arrow_body(pending, start)

    def _arrow_body(self, pending: Node, start: int) -> Node:
        self.expect("=>")
        if self.at("{"):
            body = self.function_body()
            expression = False
        else:
            body = self.assignment()
            expression = True
        return self.node(
            "ArrowFunctionExpression",
            start,
            params=pending["params"],
            body=body,
            expression=expression,
            is_async=pending["is_async"],
        )

    def conditional(self, *, no_in: bool = False) -> Node:
        start = self.tok.start
        test = self.binary(0, no_in=no_in)
        if test.type == "ArrowPending":
            return test
        if not self.at("?"):
            return test
        if self.typescript and (
            self._next_is(":") or self._next_is(",") or self._next_is(")") or self._next_is("=")
        ):
            return test  # `(x?: T)`: an optional parameter, read by the caller
        self.advance()
        consequent = self.assignment()
        self.expect(":")
        alternate = self.assignment(no_in=no_in)
        return self.node(
            "ConditionalExpression", start, test=test, consequent=consequent, alternate=alternate
        )

    def binary(self, minimum: int, *, no_in: bool = False) -> Node:
        start = self.tok.start
        left = self.unary()
        if left.type == "ArrowPending":
            return left
        while True:
            t = self.tok
            if t.kind not in ("punct", "name") or t.value not in TokenStream.BINARY:
                return left
            op = t.value
            if (
                (op == "in" and no_in)
                or (op in ("as", "satisfies") and not self.typescript)
                or (op in ("as", "satisfies") and t.newline)
            ):
                return left
            precedence = TokenStream.BINARY[op]
            if precedence <= minimum and not (op == "**" and precedence == minimum):
                return left
            self.advance()
            if op in ("as", "satisfies"):
                if self.eat("const"):
                    pass
                else:
                    self.skip_type()
                left = self.node("TSAsExpression", start, expression=left)
                continue
            right = self.binary(precedence - (1 if op == "**" else 0), no_in=no_in)
            kind = "LogicalExpression" if op in ("&&", "||", "??") else "BinaryExpression"
            left = self.node(kind, start, operator=op, left=left, right=right)

    def unary(self) -> Node:
        start = self.tok.start
        t = self.tok
        if t.kind == "punct" and t.value in ("!", "~", "+", "-"):
            self.advance()
            return self.node("UnaryExpression", start, operator=t.value, argument=self.unary())
        if t.kind == "punct" and t.value in ("++", "--"):
            self.advance()
            return self.node(
                "UpdateExpression", start, operator=t.value, prefix=True, argument=self.unary()
            )
        if t.kind == "name" and t.value in ("typeof", "void", "delete"):
            self.advance()
            return self.node("UnaryExpression", start, operator=t.value, argument=self.unary())
        if (
            t.kind == "name"
            and t.value == "await"
            and not self._next_is("=>")
            and not self._next_is(".")
        ):
            state = self.snapshot()
            self.advance()
            if (
                self.at(")")
                or self.at(";")
                or self.at(",")
                or self.at("]")
                or self.at("}")
                or self.tok.kind == "eof"
            ):
                self.restore(state)
            else:
                return self.node("AwaitExpression", start, argument=self.unary())
        if self.typescript and not self.jsx and t.kind == "punct" and t.value == "<":
            state = self.snapshot()
            try:  # `<T, E>(x) => ...`: a generic arrow function
                self._skip_balanced("<", ">", limit=TokenStream.LOOKAHEAD)
                if self.at("("):
                    return self.postfix()
            except ParseError:
                pass
            self.restore(state)
            self.advance()  # `<T>x`, the older type assertion
            self.skip_type()
            self.expect(">")
            return self.node("TSTypeAssertion", start, expression=self.unary())
        return self.postfix()

    def postfix(self) -> Node:
        start = self.tok.start
        expression = self.left_hand_side()
        if expression.type == "ArrowPending":
            return expression
        if self.tok.kind == "punct" and self.tok.value in ("++", "--") and not self.tok.newline:
            op = self.advance().value
            return self.node(
                "UpdateExpression", start, operator=op, prefix=False, argument=expression
            )
        return expression

    def left_hand_side(self) -> Node:
        start = self.tok.start
        expression = self._new() if self.at("new") else self.primary()
        if expression.type == "ArrowPending":
            return expression
        while True:
            t = self.tok
            if t.kind == "punct" and t.value == ".":
                self.advance()
                prop = self._member_name()
                expression = self.node(
                    "MemberExpression",
                    start,
                    object=expression,
                    property=prop,
                    computed=False,
                    optional=False,
                )
            elif t.kind == "punct" and t.value == "?.":
                expression = self._optional_link(start, expression)
            elif t.kind == "punct" and t.value == "[":
                self.advance()
                prop = self.expression()
                self.expect("]")
                expression = self.node(
                    "MemberExpression",
                    start,
                    object=expression,
                    property=prop,
                    computed=True,
                    optional=False,
                )
            elif (
                t.kind == "punct"
                and t.value == "("
                and self._is_async_name(expression)
                and not t.newline
            ):
                items = self._cover_items()
                if self.at("=>") and not self.tok.newline:
                    params = [self.to_pattern(i) for i in items]
                    return Node("ArrowPending", start, self.prev.end, params=params, is_async=True)
                expression = self.node(
                    "CallExpression", start, callee=expression, arguments=items, optional=False
                )
            elif t.kind == "punct" and t.value == "(":
                args = self.arguments()
                expression = self.node(
                    "CallExpression", start, callee=expression, arguments=args, optional=False
                )
                if (
                    self.at("=>")
                    and not self.tok.newline
                    and self._is_async_name(expression["callee"])
                ):
                    params = [self.to_pattern(a) for a in args]
                    return Node("ArrowPending", start, self.prev.end, params=params, is_async=True)
            elif t.kind in ("template", "template_head"):
                quasi = self.template()
                expression = self.node(
                    "TaggedTemplateExpression", start, tag=expression, quasi=quasi
                )
            elif t.kind == "punct" and t.value == "!" and self.typescript and not t.newline:
                self.advance()  # non-null assertion
            elif t.kind == "punct" and t.value == "<" and self.typescript:
                if not self._type_arguments_maybe():
                    return expression
            else:
                return expression

    def _optional_link(self, start: int, expression: Node) -> Node:
        """The link after `?.` in a member chain begun at `start`: an optional call, computed member
        or member of `expression`."""
        self.advance()
        if self.at("("):
            args = self.arguments()
            expression = self.node(
                "CallExpression", start, callee=expression, arguments=args, optional=True
            )
        elif self.eat("["):
            prop = self.expression()
            self.expect("]")
            expression = self.node(
                "MemberExpression",
                start,
                object=expression,
                property=prop,
                computed=True,
                optional=True,
            )
        else:
            prop = self._member_name()
            expression = self.node(
                "MemberExpression",
                start,
                object=expression,
                property=prop,
                computed=False,
                optional=True,
            )
        return expression

    def _new(self) -> Node:
        start = self.advance().start
        if self.eat("."):
            prop = self._member_name()  # `new.target`
            return self.node("MetaProperty", start, meta="new", property=prop)
        callee = self.primary() if not self.at("new") else self._new()
        while self.at(".") or self.at("["):
            if self.eat("."):
                prop = self._member_name()
                callee = self.node(
                    "MemberExpression",
                    start,
                    object=callee,
                    property=prop,
                    computed=False,
                    optional=False,
                )
            else:
                self.advance()
                prop = self.expression()
                self.expect("]")
                callee = self.node(
                    "MemberExpression",
                    start,
                    object=callee,
                    property=prop,
                    computed=True,
                    optional=False,
                )
        if self.typescript and self.at("<"):
            self._type_arguments_maybe()
        args = self.arguments() if self.at("(") else []
        return self.node("NewExpression", start, callee=callee, arguments=args)

    def arguments(self) -> list[Node]:
        self.expect("(")
        args: list[Node] = []
        while not self.at(")") and self.tok.kind != "eof":
            start = self.tok.start
            if self.eat("..."):
                args.append(self.node("SpreadElement", start, argument=self.assignment()))
            else:
                args.append(self.assignment())
            if not self.eat(","):
                break
        self.expect(")")
        return args

    def primary(self) -> Node:
        t = self.tok
        start = t.start
        if t.kind == "name":
            v = t.value
            if v == "function" or (v == "async" and self._async_function()):
                return self.function("FunctionExpression", optional_name=True)
            if v == "class":
                return self.class_("ClassExpression", optional_name=True)
            if v == "this":
                self.advance()
                return self.node("ThisExpression", start)
            if v == "super":
                self.advance()
                return self.node("Super", start)
            if v == "import":
                self.advance()
                if self.eat("."):
                    prop = self._member_name()
                    return self.node("MetaProperty", start, meta="import", property=prop)
                self.expect("(")
                source = self.assignment()
                if self.eat(",") and not self.at(")"):
                    self.assignment()
                    self.eat(",")
                self.expect(")")
                return self.node("ImportExpression", start, source=source)
            if v in ("true", "false", "null"):
                self.advance()
                return self.node("Literal", start, value=v, raw=v)
            return self.identifier()
        if t.kind in ("string", "number", "regex"):
            return self.literal()
        if t.kind in ("template", "template_head"):
            return self.template()
        if t.kind == "punct":
            if t.value == "(":
                return self._parenthesized()
            if t.value == "[":
                return self.array_literal()
            if t.value == "{":
                return self.object_literal()
            if t.value == "<" and self.jsx:
                return self.jsx_element()
            if t.value == "@":
                self._decorators()
                return self.primary()
            if t.value == "#" or t.kind == "private":
                pass
        if t.kind == "private":  # `#x in obj`
            self.advance()
            return Node("PrivateIdentifier", start, t.end, name=t.value)
        raise ParseError(f"an expression expected at {start}")

    def _parenthesized(self) -> Node:
        """`( ... )`: a grouped expression, or -- when `=>` follows -- an arrow's parameters,
        read once either way (the cover grammar)."""
        start = self.tok.start
        items = self._cover_items()
        if self.at("=>") and not self.tok.newline:
            params = [self.to_pattern(i) for i in items]
            return Node("ArrowPending", start, self.prev.end, params=params, is_async=False)
        if not items:
            raise ParseError(f"an empty group at {start}")
        inner = (
            items[0]
            if len(items) == 1
            else Node("SequenceExpression", items[0].start, items[-1].end, expressions=items)
        )
        return self.node("ParenthesizedExpression", start, expression=inner)

    def _cover_items(self) -> list[Node]:
        """What a `(...)` holds, read as expressions that may be arrow parameters -- annotated,
        optional, defaulted or rest -- and, after it, a return type when `=>` follows."""
        self.expect("(")
        items: list[Node] = []
        while not self.at(")") and self.tok.kind != "eof":
            istart = self.tok.start
            if self.eat("..."):
                item = self.node("SpreadElement", istart, argument=self.binding_target())
            else:
                item = self.assignment()
            if (
                self.typescript
                and self.at("?")
                and (self._next_is(":") or self._next_is(",") or self._next_is(")"))
            ):
                self.advance()
            if self.typescript and self.at(":"):
                self._type_annotation()
                item = self.node("TSAnnotated", istart, expression=item)
                if self.eat("="):  # `(x: T = d)`: annotated, then defaulted
                    default = self.assignment()
                    item = self.node(
                        "AssignmentExpression",
                        istart,
                        operator="=",
                        left=item["expression"],
                        right=default,
                    )
            items.append(item)
            if not self.eat(","):
                break
        self.expect(")")
        if self.typescript and self.at(":"):  # a return type: `(a): T =>`
            state = self.snapshot()
            try:
                self.advance()
                self.skip_type(arrow_ends=True)
            except ParseError:
                self.restore(state)
            if not self.at("=>"):
                self.restore(state)
        return items

    def array_literal(self) -> Node:
        start = self.expect("[").start
        elements: list[Node | None] = []
        while not self.at("]") and self.tok.kind != "eof":
            if self.at(","):
                self.advance()
                elements.append(None)
                continue
            estart = self.tok.start
            if self.eat("..."):
                elements.append(self.node("SpreadElement", estart, argument=self.assignment()))
            else:
                elements.append(self.assignment())
            if not self.eat(","):
                break
        self.expect("]")
        return self.node("ArrayExpression", start, elements=elements)

    def object_literal(self) -> Node:
        start = self.expect("{").start
        properties: list[Node] = []
        while not self.at("}") and self.tok.kind != "eof":
            properties.append(self.object_member())
            if not self.eat(","):
                break
        self.expect("}")
        return self.node("ObjectExpression", start, properties=properties)

    def object_member(self) -> Node:
        start = self.tok.start
        if self.eat("..."):
            return self.node("SpreadElement", start, argument=self.assignment())
        is_async = generator = False
        kind = "init"
        if self.at("async") and not (
            self._next_is(",")
            or self._next_is(":")
            or self._next_is("(")
            or self._next_is("}")
            or self._next_is("=")
        ):
            self.advance()
            is_async = True
        if self.eat("*"):
            generator = True
        if (self.at("get") or self.at("set")) and self._accessor_follows():
            kind = self.advance().value
        key, computed = self.property_key()
        if self.at("(") or self.at("<"):
            self._type_parameters()
            params = self.parameters()
            self._type_annotation()
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
                "Property",
                start,
                key=key,
                value=value,
                computed=computed,
                shorthand=False,
                kind=kind if kind != "init" else "method",
            )
        if self.eat(":"):
            value = self.assignment()
            return self.node(
                "Property",
                start,
                key=key,
                value=value,
                computed=computed,
                shorthand=False,
                kind="init",
            )
        if self.at("="):  # a shorthand with a default, only valid as a pattern
            self.advance()
            default = self.assignment()
            value = self.node("AssignmentExpression", start, operator="=", left=key, right=default)
            return self.node(
                "Property", start, key=key, value=value, computed=False, shorthand=True, kind="init"
            )
        return self.node(
            "Property", start, key=key, value=key, computed=False, shorthand=True, kind="init"
        )

    def template(self) -> Node:
        start = self.tok.start
        quasis: list[Node] = []
        expressions: list[Node] = []
        t = self.advance()
        quasis.append(Node("TemplateElement", t.start, t.end, cooked=t.value))
        if t.kind == "template":
            return self.node("TemplateLiteral", start, quasis=quasis, expressions=expressions)
        while True:
            expressions.append(self.expression())
            t = self.tok
            if t.kind not in ("template_middle", "template_tail"):
                raise ParseError(f"a template continued at {t.start}")
            self.advance()
            quasis.append(Node("TemplateElement", t.start, t.end, cooked=t.value))
            if t.kind == "template_tail":
                return self.node("TemplateLiteral", start, quasis=quasis, expressions=expressions)
