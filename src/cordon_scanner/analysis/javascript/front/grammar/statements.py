"""A JavaScript program's statements: the program itself, statements with recovery to the next
boundary when one cannot be read, blocks, declarations, loops, `try` and `switch`, and the
module statements `import` and `export`."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError, TokenStream
from cordon_scanner.analysis.javascript.front.syntax import Node


class Statements(TokenStream):
    """The program, its statements and its module statements, for `front.parser.Parser`."""

    # -- program and statements --------------------------------------------

    def program(self) -> Node:
        body: list[Node] = []
        while self.tok.kind != "eof":
            body.append(self.released(self.statement_recovering()))
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
                    self.tok.value in TokenStream.STATEMENT_START
                    or self.tok.kind in TokenStream.LINE_START_KINDS
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
                if level <= 0 or self.tok.value in TokenStream.STATEMENT_START:
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
            if (branch := self._branch_or_loop(v, start)) is not None:
                return branch
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
            if self.at(":") and name.value not in TokenStream.REGEX_AFTER_NAME:
                self.advance()
                label = Node("Identifier", name.start, name.end, name=name.value)
                return self.node("LabeledStatement", start, label=label, body=self.statement())
            self.restore(state)
        expression = self.expression()
        self.semicolon()
        return self.node("ExpressionStatement", start, expression=expression)

    def _branch_or_loop(self, v: str, start: int) -> Node | None:
        """The `if`, `for`, `while` or `do` statement keyword `v` begins at `start`; None for any
        other keyword."""
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
        return None

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
