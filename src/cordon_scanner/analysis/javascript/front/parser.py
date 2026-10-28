"""The syntax tree of a JavaScript or TypeScript source, by Cordon's own parser.

The second stage of the front end (`reviews/self-improving/08-JS-FRONT-END.md`). Recursive descent
for statements, precedence climbing for expressions, ESTree node types (`syntax.Node`).

What makes it safe to point at an attacker's file:

- It never backtracks over unbounded input. A parenthesised expression is parsed once and, when
  `=>` follows, reread as parameters (the cover grammar real engines use), so nested parentheses
  cannot make it quadratic. The one speculative parse, TypeScript type arguments (`f<T>(x)`), reads
  at most `LOOKAHEAD` tokens before falling back to `<` as less-than.
- Nesting is bounded. Past `MAX_DEPTH` levels a statement is given up as an `Error` node and
  parsing resumes after it: no input exhausts the interpreter's stack.
- It recovers. A statement it cannot read becomes an `Error` node spanning to the next statement
  boundary, and the rest of the file is still parsed. It never raises.

What it reads: ECMAScript 2024 (modules, classes with private and static members and static
blocks, destructuring with defaults, rest and spread, async functions and generators, optional
chaining, nullish coalescing and logical assignment, templates and tagged templates, `import()` and
`import.meta`, labelled statements, automatic semicolon insertion); TypeScript syntax (annotations,
generics, `as` and `satisfies`, non-null `!`, interfaces, type aliases, enums, namespaces,
`declare`, parameter properties, decorators, `import x = require(...)`), which has no runtime
effect and is passed over exactly; and JSX elements, whose attribute and child expressions are
parsed.
"""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError, TokenStream
from cordon_scanner.analysis.javascript.front.syntax import Node


class Parser(TokenStream):
    """`Parser(text, typescript=..., jsx=...).program()` gives the `Program` node, always."""

    # -- program and statements --------------------------------------------

    def program(self) -> Node:
        body: list[Node] = []
        while self.tok.kind != "eof":
            body.append(self.statement_recovering())
        return Node("Program", 0, len(self.text), body=body)

    def statement_recovering(self) -> Node:
        start, state_depth = self.tok.start, self.depth
        try:
            return self.statement()
        except (ParseError, RecursionError):
            self.depth = state_depth
            self.errors += 1
            self._skip_statement()
            return Node("Error", start, max(start, self.prev.end))

    def _skip_statement(self) -> None:
        """Past the statement that failed: to its `;`, a line that starts a new statement -- a
        statement keyword, or at bracket level a name or literal beginning the line -- or the `}`
        closing the block it is in."""
        level = 0
        moved = False
        while self.tok.kind != "eof":
            if (
                moved
                and level <= 0
                and self.tok.newline
                and (
                    self.tok.value in Parser.STATEMENT_START
                    or self.tok.kind in Parser.LINE_START_KINDS
                )
            ):
                return
            if self.at("{") or self.at("(") or self.at("["):
                level += 1
            elif self.at("}") or self.at(")") or self.at("]"):
                if level <= 0:
                    if not moved:
                        self.advance()
                    return
                level -= 1
            elif self.at(";"):
                self.advance()
                # Resynchronised at a `;` -- inside an unclosed bracket too, when a statement
                # plainly begins after it: an unclosed `{` must not swallow the rest of the file.
                if level <= 0 or self.tok.value in Parser.STATEMENT_START:
                    return
                continue
            self.advance()
            moved = True

    def statement(self) -> Node:
        self._deeper()
        try:
            return self._statement()
        finally:
            self.depth -= 1

    def _statement(self) -> Node:
        t, start = self.tok, self.tok.start
        if t.kind == "punct":
            if t.value == "{":
                return self.block()
            if t.value == ";":
                self.advance()
                return self.node("EmptyStatement", start)
            if t.value == "@":
                self._decorators()
                return self._statement()
        if t.kind == "name":
            v = t.value
            if v in ("var", "const") or (v == "let" and self._let_declares()):
                decl = self.variable_declaration()
                self.semicolon()
                return decl
            if v == "function" or (v == "async" and self._async_function()):
                return self.function("FunctionDeclaration")
            if v == "class":
                return self.class_("ClassDeclaration")
            if v == "if":
                self.advance()
                self.expect("(")
                test = self.expression()
                self.expect(")")
                consequent = self.statement()
                alternate = self.statement() if self.eat("else") else None
                return self.node(
                    "IfStatement", start, test=test, consequent=consequent, alternate=alternate
                )
            if v == "for":
                return self.for_()
            if v == "while":
                self.advance()
                self.expect("(")
                test = self.expression()
                self.expect(")")
                return self.node("WhileStatement", start, test=test, body=self.statement())
            if v == "do":
                self.advance()
                body = self.statement()
                self.expect("while")
                self.expect("(")
                test = self.expression()
                self.expect(")")
                self.eat(";")
                return self.node("DoWhileStatement", start, body=body, test=test)
            if v in ("return", "throw"):
                self.advance()
                argument = None
                if not (self.at(";") or self.at("}") or self.tok.kind == "eof" or self.tok.newline):
                    argument = self.expression()
                self.semicolon()
                return self.node(
                    "ReturnStatement" if v == "return" else "ThrowStatement",
                    start,
                    argument=argument,
                )
            if v == "try":
                return self.try_()
            if v == "switch":
                return self.switch()
            if v in ("break", "continue"):
                self.advance()
                label = None
                if self.tok.kind == "name" and not self.tok.newline and not self.at(";"):
                    label = self.identifier()
                self.semicolon()
                return self.node(
                    "BreakStatement" if v == "break" else "ContinueStatement", start, label=label
                )
            if v == "import" and not self._import_call():
                return self.import_()
            if v == "export":
                return self.export()
            if v == "debugger":
                self.advance()
                self.semicolon()
                return self.node("DebuggerStatement", start)
            if v == "with":
                self.advance()
                self.expect("(")
                obj = self.expression()
                self.expect(")")
                return self.node("WithStatement", start, object=obj, body=self.statement())
            if self.typescript and v == "abstract" and self._next_is("class"):
                self.advance()
                return self.class_("ClassDeclaration")
            if self.typescript and v in ("namespace", "module") and self._next_kind_is("name"):
                self.advance()  # a namespace's body runs: read it as the block it is
                self.identifier()
                while self.eat("."):
                    self.identifier()
                return self.block()
            if self.typescript and self._typescript_declaration():
                return self.node("TSDeclaration", start)
            state = self.snapshot()
            name = self.advance()
            if self.at(":") and name.value not in Parser.REGEX_AFTER_NAME:
                self.advance()
                label = Node("Identifier", name.start, name.end, name=name.value)
                return self.node("LabeledStatement", start, label=label, body=self.statement())
            self.restore(state)
        expression = self.expression()
        self.semicolon()
        return self.node("ExpressionStatement", start, expression=expression)

    def block(self) -> Node:
        start = self.expect("{").start
        body: list[Node] = []
        while not self.at("}") and self.tok.kind != "eof":
            body.append(self.statement_recovering())
        self._close_or_end()
        return self.node("BlockStatement", start, body=body)

    def _close_or_end(self) -> None:
        """A block's `}` -- or the end of the file, counted as an error: an unclosed block keeps
        what it held instead of failing every statement around it."""
        if self.tok.kind == "eof":
            self.errors += 1
            return
        self.expect("}")

    def _let_declares(self) -> bool:
        state = self.snapshot()
        self.advance()
        declares = self.tok.kind == "name" or self.at("[") or self.at("{")
        self.restore(state)
        return declares

    def _import_call(self) -> bool:
        state = self.snapshot()
        self.advance()
        yes = self.at("(") or self.at(".")
        self.restore(state)
        return yes

    def variable_declaration(self, *, in_for: bool = False) -> Node:
        start = self.tok.start
        kind = self.advance().value
        declarations: list[Node] = []
        while True:
            dstart = self.tok.start
            target = self.binding_target()
            self.eat("!")
            self._type_annotation()
            init = None
            if self.eat("="):
                init = self.assignment(no_in=in_for)
            declarations.append(self.node("VariableDeclarator", dstart, id=target, init=init))
            if not self.eat(","):
                break
        return self.node("VariableDeclaration", start, kind=kind, declarations=declarations)

    def for_(self) -> Node:
        start = self.advance().start
        self.eat("await")
        self.expect("(")
        init: Node | None = None
        if self.at(";"):
            pass
        elif self.at("var") or self.at("const") or (self.at("let") and self._let_declares()):
            init = self.variable_declaration(in_for=True)
        else:
            init = self.expression(no_in=True)
        if self.at("of") or self.at("in"):
            kind = "ForOfStatement" if self.advance().value == "of" else "ForInStatement"
            right = self.assignment() if kind == "ForOfStatement" else self.expression()
            self.expect(")")
            return self.node(kind, start, left=init, right=right, body=self.statement())
        self.expect(";")
        test = None if self.at(";") else self.expression()
        self.expect(";")
        update = None if self.at(")") else self.expression()
        self.expect(")")
        return self.node(
            "ForStatement", start, init=init, test=test, update=update, body=self.statement()
        )

    def try_(self) -> Node:
        start = self.advance().start
        block = self.block()
        handler = finalizer = None
        if self.at("catch"):
            cstart = self.advance().start
            param = None
            if self.eat("("):
                param = self.binding_target()
                self._type_annotation()
                self.expect(")")
            handler = self.node("CatchClause", cstart, param=param, body=self.block())
        if self.eat("finally"):
            finalizer = self.block()
        return self.node("TryStatement", start, block=block, handler=handler, finalizer=finalizer)

    def switch(self) -> Node:
        start = self.advance().start
        self.expect("(")
        discriminant = self.expression()
        self.expect(")")
        self.expect("{")
        cases: list[Node] = []
        while not self.at("}") and self.tok.kind != "eof":
            cstart = self.tok.start
            test = None
            if self.eat("case"):
                test = self.expression()
            else:
                self.expect("default")
            self.expect(":")
            body: list[Node] = []
            while not (
                self.at("case") or self.at("default") or self.at("}") or self.tok.kind == "eof"
            ):
                body.append(self.statement_recovering())
            cases.append(self.node("SwitchCase", cstart, test=test, consequent=body))
        self._close_or_end()
        return self.node("SwitchStatement", start, discriminant=discriminant, cases=cases)

    # -- modules --------------------------------------------------------------

    def import_(self) -> Node:
        start = self.advance().start
        if self.typescript and (self.at("type") or self.at("typeof")):
            state = self.snapshot()
            self.advance()
            if self.tok.kind == "name" or self.at("{") or self.at("*"):
                pass  # `import type x from` -- types only, read the same way
            else:
                self.restore(state)
        if self.tok.kind == "string":
            source = self.literal()
            self._import_attributes()
            self.semicolon()
            return self.node("ImportDeclaration", start, specifiers=[], source=source)
        specifiers: list[Node] = []
        if self.tok.kind == "name" and not self.at("from"):
            local = self.identifier()
            if self.at("="):  # TypeScript: `import x = require("m")` or `import x = a.b`
                self.advance()
                value = self.assignment()
                self.semicolon()
                return self.node("TSImportEquals", start, id=local, value=value)
            specifiers.append(Node("ImportDefaultSpecifier", local.start, local.end, local=local))
            self.eat(",")
        if self.at("*"):
            sstart = self.advance().start
            self.expect("as")
            local = self.identifier()
            specifiers.append(self.node("ImportNamespaceSpecifier", sstart, local=local))
        elif self.at("{"):
            self.advance()
            while not self.at("}") and self.tok.kind != "eof":
                sstart = self.tok.start
                if self.typescript and self.at("type"):
                    state = self.snapshot()
                    self.advance()
                    if self.at(",") or self.at("}") or self.at("as"):
                        self.restore(state)
                imported = self.module_export_name()
                local = self.identifier() if self.eat("as") else imported
                specifiers.append(
                    self.node("ImportSpecifier", sstart, imported=imported, local=local)
                )
                if not self.eat(","):
                    break
            self.expect("}")
        self.expect("from")
        source = self.literal()
        self._import_attributes()
        self.semicolon()
        return self.node("ImportDeclaration", start, specifiers=specifiers, source=source)

    def _import_attributes(self) -> None:
        if (self.at("with") or self.at("assert")) and not self.tok.newline:
            self.advance()
            self.object_literal()

    def module_export_name(self) -> Node:
        if self.tok.kind == "string":
            return self.literal()
        return self.identifier()

    def export(self) -> Node:
        start = self.advance().start
        if self.eat("default"):
            if self.typescript and self.at("abstract") and self._next_is("class"):
                self.advance()
            if self.at("function") or (self.at("async") and self._async_function()):
                declaration = self.function("FunctionDeclaration", optional_name=True)
            elif self.at("class"):
                declaration = self.class_("ClassDeclaration", optional_name=True)
            else:
                declaration = self.assignment()
                self.semicolon()
            return self.node("ExportDefaultDeclaration", start, declaration=declaration)
        if self.at("*"):
            self.advance()
            exported = self.module_export_name() if self.eat("as") else None
            self.expect("from")
            source = self.literal()
            self._import_attributes()
            self.semicolon()
            return self.node("ExportAllDeclaration", start, exported=exported, source=source)
        if self.typescript and self.at("="):  # `export = x`
            self.advance()
            expression = self.assignment()
            self.semicolon()
            return self.node("TSExportAssignment", start, expression=expression)
        if self.typescript and self.at("type") and self._next_is("{"):
            self.advance()
        if self.at("{"):
            self.advance()
            specifiers: list[Node] = []
            while not self.at("}") and self.tok.kind != "eof":
                sstart = self.tok.start
                if self.typescript and self.at("type") and self._next_kind_is("name"):
                    self.advance()
                local = self.module_export_name()
                exported = self.module_export_name() if self.eat("as") else local
                specifiers.append(
                    self.node("ExportSpecifier", sstart, local=local, exported=exported)
                )
                if not self.eat(","):
                    break
            self.expect("}")
            reexported = self.literal() if self.eat("from") else None
            if reexported is not None:
                self._import_attributes()
            self.semicolon()
            return self.node(
                "ExportNamedDeclaration",
                start,
                declaration=None,
                specifiers=specifiers,
                source=reexported,
            )
        declaration = self.statement()
        return self.node(
            "ExportNamedDeclaration", start, declaration=declaration, specifiers=[], source=None
        )

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
            return self.block()
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
        if self.tok.kind == "punct" and self.tok.value in Parser.ASSIGN:
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
            if t.kind not in ("punct", "name") or t.value not in Parser.BINARY:
                return left
            op = t.value
            if (
                (op == "in" and no_in)
                or (op in ("as", "satisfies") and not self.typescript)
                or (op in ("as", "satisfies") and t.newline)
            ):
                return left
            precedence = Parser.BINARY[op]
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
                self._skip_balanced("<", ">", limit=Parser.LOOKAHEAD)
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


__all__ = ["ParseError", "Parser"]
