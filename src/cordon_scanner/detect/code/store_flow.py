"""Whether what a file reads from a credential store can reach its network call.

`SUSPECT.EXFIL.CREDENTIAL_STORE.001` pairs a read of a credential store with an outbound call
within two hundred lines. Theft is the store's content carried into the call; a dotfiles script
that installs a tool with `curl | bash` forty lines after reading `~/.ssh/config` for a host name
carries nothing. Measured on the review-98 corpora: the rule was the only blocking finding on
181 of 227 benign units it fired on, and on 11 of 147 malware samples.

The test is textual and language-agnostic on purpose: it reads shell, Python, JavaScript, Go,
Ruby and Nix strings alike, and errs towards a flow. A name assigned on a line that reads the
store is tainted; a name assigned from a tainted one is tainted, as is a loop variable over one,
a `with ... as` target, a callback parameter, and a function that returns one. A flow is a
tainted name, or the store read itself, on the network call's line or the few lines its
arguments run on. Anything this cannot follow -- a name it never saw assigned -- is no flow,
and the finding is recorded below the gate rather than dropped.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Final

from cordon_scanner.analysis.python.scoped_taint import ScopedTaint

if TYPE_CHECKING:
    from collections.abc import Callable

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_ASSIGNED = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?|const\s+|let\s+|var\s+|my\s+)?"
    r"(?P<target>[A-Za-z_$][\w$.,\s{}\[\]'\"]{0,120}?)\s*(?::=|(?<![=!<>+\-*/%&|^])=(?![=>~]))"
)
"""What a line assigns: `x = ...`, `a, b := ...`, `const {a, b} = ...`, `name=$(cat ...)`."""

_BOUND = re.compile(
    r"\bas\s{1,4}(?P<as>[A-Za-z_]\w{0,60})"
    r"|\bfor\s{1,4}(?:\(\s{0,4}(?:const|let|var)\s{1,4})?"
    r"(?P<for>[A-Za-z_]\w{0,60}(?:\s{0,4},\s{0,4}[A-Za-z_]\w{0,60}){0,8})\s{1,4}(?:in|of)\b"
    r"|\(?\s{0,4}(?P<arrow>[A-Za-z_]\w{0,60}(?:\s{0,4},\s{0,4}[A-Za-z_]\w{0,60}){0,8})\s{0,4}\)?\s{0,4}=>"
    r"|\bfunction\s{0,4}\(\s{0,4}(?P<callback>[A-Za-z_]\w{0,60})"
    r"|\bread\s{1,4}(?:-\w{1,10}\s{1,4}){0,4}(?P<read>[A-Za-z_]\w{0,60})"
)
"""Names a line binds other than by assignment."""

_FUNCTION = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|func|sub)\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)"
    r"|^\s*(?P<shell>[A-Za-z_][\w-]*)\s*\(\s*\)\s*\{"
    r"|^\s*(?:const|let|var)\s+(?P<arrowfn>[A-Za-z_]\w*)\s*=[^)]*(?:\)\s*)?=>"
)
r"""Where a function's body begins, and its name.

The arrow function's tail is `=[^)]*(?:\)\s*)?=>`, which is `=\s*(?:async\s*)?\(?[^)]*\)?\s*=>`: what
the blanks, `async` and `(` before the parameters can take, `[^)]*` takes too, and so do the blanks
before `=>` when there is no `)`. As written out, the overlapping runs were cubic in blanks after
`const a=` (review 98, 27-PERFORMANCE)."""

_ARGUMENT = re.compile(r"(?<![\w.$])([A-Za-z_]\w*)(?![\w$]|\s*[.(])")
"""A bare name, not a callee (`f(`), not a receiver (`os.`), not an attribute (`.path`)."""

_FILLED = re.compile(
    r"(?<!\w)[^\WA-Za-z_]*+([A-Za-z_]\w*+)\s*\.\s*(?:append|extend|write|writelines|writerow|"
    r"writerows|update|add|insert|push|put|setdefault|set|concat|join)\s*\("
)
r"""The receiver of a call that puts something into it.

Group 1 is the receiver, as `([A-Za-z_]\w*)\s*\.` alone would give it. A match starts only where
a word starts (the lookbehind), past the word's leading digits: the plain form retried every
position of a long word that is not followed by such a call, quadratic in a line an attacker
writes (review 98, 27-PERFORMANCE)."""

_PATH_LITERAL = re.compile(
    r"\"([^\"\n:]{1,200}[./\\][^\"\n:]{1,200})\"|'([^'\n:]{1,200}[./\\][^'\n:]{1,200})'"
)
"""A quoted file name or path (no scheme, so no URL)."""

_LITERAL_MARK = "\x00"
"""Prefix that keeps a path literal apart from an identifier in the tainted set."""

_IMPORTED: Final = re.compile(
    r"^\s{0,8}(?:import\s{1,4}(?P<names>[\w${},\s*]{1,200}?)\s{1,4}from\b"
    r"|(?:const|let|var)\s{1,4}(?P<required>[\w${},\s]{1,200}?)\s{0,4}=\s{0,4}require\s{0,4}\("
    r"|from\s{1,4}[\w.]{1,100}\s{1,4}import\s{1,4}(?P<pyfrom>[\w,\s]{1,200})"
    r"|import\s{1,4}(?P<pyimport>[\w.,\s]{1,200})$)"
)
"""An import line, and the names it binds."""

_KEYWORDS = frozenset(
    {
        "if", "else", "for", "while", "in", "of", "return", "const", "let", "var", "def",
        "function", "func", "true", "false", "True", "False", "None", "null", "nil", "self",
        "this", "and", "or", "not", "is", "with", "as", "then", "do", "done", "fi", "echo",
        "local", "export", "await", "async", "new", "import", "from", "string", "str",
    }
)  # fmt: skip

CALL_SPAN = 4
"""Lines a network call's arguments may run on after the line it starts on."""


class StoreFlow:
    """The flow test. See the module docstring."""

    @staticmethod
    def reaches(
        text: str, store_lines: list[int], egress_lines: list[int], language: str | None = None
    ) -> bool:
        """Whether anything read on a store line (1-based) can reach a call on an egress line.
        Python is answered by value (`PythonStoreFlow`), where its tree can answer."""
        lines = text.split("\n")
        if not store_lines or not egress_lines:
            return False
        egress_lines = StoreFlow._calls_of_imports(lines, egress_lines)
        if language == "python":
            verdict = PythonStoreFlow.reaches(text, store_lines, egress_lines)
            if verdict is not None:
                return verdict
        # A call on the line that reads the store, or the line beside it: `cat ~/.aws/credentials |
        # curl -d @- ...`, `requests.post(u, files={"f": open(STORE)})`.
        if any(abs(s - e) <= 1 for s in store_lines for e in egress_lines):
            return True
        tainted: set[str] = set()
        for number in store_lines:
            if 1 <= number <= len(lines):
                tainted |= StoreFlow._names_bound(lines[number - 1])
                tainted |= StoreFlow._enclosing_function_if_returned(
                    lines, number, lines[number - 1]
                )
        for _ in range(6):
            grown = set(tainted)
            for index, line in enumerate(lines, start=1):
                if not StoreFlow._mentions(line, grown):
                    continue
                grown |= StoreFlow._names_bound(line)
                grown |= StoreFlow._enclosing_function_if_returned(lines, index, line)
            if grown == tainted:
                break
            tainted = grown
        if not tainted:
            return False
        for number in egress_lines:
            call = lines[max(0, number - 1) : min(len(lines), number + CALL_SPAN)]
            if any(StoreFlow._mentions(line, tainted) for line in call):
                return True
        return False

    @staticmethod
    def _calls_of_imports(lines: list[str], egress_lines: list[int]) -> list[int]:
        """Egress lines, with an import's call sites added: a network library is often labelled
        where it is imported (`import fetch from "node-fetch"`), and the request is made later."""
        out = set(egress_lines)
        for number in egress_lines:
            if not 1 <= number <= len(lines):
                continue
            found = _IMPORTED.search(lines[number - 1])
            if found is None:
                continue
            bound = next(g for g in found.groups() if g)
            names = {n for n in _IDENTIFIER.findall(bound) if n not in _KEYWORDS and len(n) > 2}
            if not names:
                continue
            call = re.compile(
                r"(?<![\w$.])(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\s{0,4}[.(]"
            )
            out.update(i for i, line in enumerate(lines, start=1) if call.search(line))
        return sorted(out)

    @staticmethod
    def _mentions(line: str, names: set[str]) -> bool:
        if not names:
            return False
        if any(token in names for token in _IDENTIFIER.findall(line)):
            return True
        return any(
            _LITERAL_MARK + (found.group(1) or found.group(2)) in names
            for found in _PATH_LITERAL.finditer(line)
        )

    @staticmethod
    def _names_bound(line: str) -> set[str]:
        names: set[str] = set()
        assigned = _ASSIGNED.match(line)
        if assigned:
            names |= set(_IDENTIFIER.findall(assigned.group("target")))
        for bound in _BOUND.finditer(line):
            for group in bound.groupdict().values():
                if group:
                    names |= set(_IDENTIFIER.findall(group))
        # And the plain names the line hands a call: `shutil.copy(profile, staging)` puts the
        # store's content in `staging`, `fs.writeFileSync(out, data)` in `out`. A callee, a
        # module or an attribute is not a value the line fills.
        for argument in _ARGUMENT.finditer(line):
            names.add(argument.group(1))
        # A collection or a file the line fills: `rows.append(row)`, `out.write(data)`.
        for receiver in _FILLED.finditer(line):
            names.add(receiver.group(1))
        # And a file named by a literal, which carries the content to whatever opens it later:
        # `open("passwords.txt", "w")` here, `files={"f": open("passwords.txt", "rb")}` there.
        for literal in _PATH_LITERAL.finditer(line):
            names.add(_LITERAL_MARK + (literal.group(1) or literal.group(2)))
        return {name for name in names if name not in _KEYWORDS}

    @staticmethod
    def _enclosing_function_if_returned(lines: list[str], number: int, line: str) -> set[str]:
        """The name of the function a line returns from, when it returns what it reads."""
        if not re.search(r"\breturn\b|\becho\b|\bprint\b|\bresolve\s*\(", line):
            return set()
        for index in range(number - 1, -1, -1):
            found = _FUNCTION.match(lines[index])
            if found:
                name = found.group("name") or found.group("shell") or found.group("arrowfn")
                return {name} if name and name not in _KEYWORDS else set()
        return set()


class PythonStoreFlow:
    """`StoreFlow.reaches` for a Python file, by value, on `ScopedTaint` (review 2026-11-10).

    The store's value is what an expression on a store line yields, or what a name imported on
    one gives (`import browser_cookie3` there, `browser_cookie3.chrome()` anywhere). It is carried
    by `ScopedTaint` -- assignments, returns, local calls' arguments, with-as, file written and
    read back by name -- and by the two fills no binding shows: the other plain names a call is
    handed beside the value (`shutil.copy(src, staged)`), and the receiver of a call that puts it
    in (`found.append(...)`, `f.write(...)`), with a literal path written then opened again. A
    flow is the value in the arguments of a call on an egress line. Words in strings and comments
    are never names.

    None, for the textual test to answer, where the tree cannot: the file does not parse, a store
    or egress line sits inside a string spanning lines (an embedded script), or no call is on any
    egress line.
    """

    #: Methods that put their argument into their receiver.
    FILLS: Final = frozenset(
        {"append", "extend", "write", "writelines", "writerow", "writerows", "update", "add",
         "insert", "put", "setdefault", "set"}
    )  # fmt: skip
    #: Rounds of spreading and filling before the answer is taken as it stands.
    ROUNDS: Final = 8

    #: Methods of an HTTP client whose first argument is the address (`request` has the verb first).
    REQUEST_METHODS: Final = frozenset(
        {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    )
    #: Keyword arguments that say where or how a request is made, not what it carries.
    REQUEST_SETTINGS: Final = frozenset(
        {"url", "auth", "timeout", "verify", "proxies", "allow_redirects", "stream", "cert"}
    )

    @classmethod
    def reaches(
        cls,
        text: str,
        store_lines: list[int],
        egress_lines: list[int],
        *,
        body_only: bool = False,
    ) -> bool | None:
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            # the guarded parse: no source warning reaches the output or, as an error, unparses it
            tree = PythonSyntax.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
            return None
        # Where the tree parses, a line that is only text inside a string -- a pattern table, a help
        # text naming `~/.aws/credentials` -- is not a read or a send (reviews/pypi-98/20, shape A).
        # A line where any expression starts is code, an f-string's `{...}` parts included.
        text_lines = PythonSyntax.text_only_lines(tree)
        store = {n for n in store_lines if n not in text_lines}
        egress = {n for n in egress_lines if n not in text_lines}
        if not store:
            return False
        calls = cls._calls_on(tree, egress)
        if not calls:
            # No call on any egress line: nothing is sent there.
            return False
        imported = cls._imported_on(tree, store)
        taint = ScopedTaint(tree)
        written: set[str] = set()

        def source(part: ast.AST) -> bool:
            if isinstance(part, ast.Name):
                return part.id in imported
            if isinstance(part, ast.Call) and cls._opens_literal(part) in written:
                return True
            return isinstance(part, ast.expr) and getattr(part, "lineno", 0) in store

        def touches(expr: ast.AST) -> bool:
            stack = [expr]
            while stack:
                part = stack.pop()
                if source(part):
                    return True
                verdict = taint.carries(part)
                if verdict is not None:
                    if verdict:
                        return True
                    continue
                stack.extend(ast.iter_child_nodes(part))
            return False

        for _ in range(cls.ROUNDS):
            taint.spread(touches)
            filled, literals = cls._filled(tree, touches)
            grew = taint.mark(filled)
            if not literals <= written:
                written |= literals
                grew = True
            if not grew:
                break
        return any(touches(argument) for call in calls for argument in cls._sinks(call, body_only))

    @classmethod
    def _sinks(cls, call: ast.Call, body_only: bool) -> list[ast.AST]:
        """The arguments of an egress call that a value reaches by. With `body_only`, a request method
        (`post`, `get`, `request`, ...) leaves out its address and the settings of how it is made: a
        token that only builds the address of the service it belongs to is not sent in the request's
        body (reviews/pypi-98/21, shape C)."""
        positional = list(call.args)
        keywords = list(call.keywords)
        if (
            body_only
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in cls.REQUEST_METHODS
        ):
            positional = positional[2 if call.func.attr == "request" else 1 :]
            keywords = [k for k in keywords if k.arg not in cls.REQUEST_SETTINGS]
        return [*positional, *(k.value for k in keywords)]

    @staticmethod
    def _calls_on(tree: ast.AST, egress: set[int]) -> list[ast.Call]:
        """The calls starting on an egress line, or where none starts there, those spanning it."""
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        starting = [c for c in calls if c.lineno in egress]
        started = {c.lineno for c in starting}
        spanning = [
            c
            for c in calls
            if any(c.lineno < e <= (c.end_lineno or c.lineno) for e in egress - started)
        ]
        return starting + spanning

    @staticmethod
    def _imported_on(tree: ast.AST, store: set[int]) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node.lineno in store:
                for alias in node.names:
                    names.add((alias.asname or alias.name).split(".")[0])
        return names

    @staticmethod
    def _opens_literal(call: ast.Call) -> str | None:
        """The literal path of `open("<path>", ...)`, or None."""
        func = call.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name != "open" or not call.args:
            return None
        first = call.args[0]
        return (
            first.value
            if isinstance(first, ast.Constant) and isinstance(first.value, str)
            else None
        )

    @classmethod
    def _filled(
        cls, tree: ast.AST, touches: Callable[[ast.AST], bool]
    ) -> tuple[list[ast.Name], set[str]]:
        """Names a call puts the value into, and literal paths it is written to."""
        filled: list[ast.Name] = []
        literals: set[str] = set()
        opened_as = {
            item.optional_vars.id: path
            for node in ast.walk(tree)
            if isinstance(node, (ast.With, ast.AsyncWith))
            for item in node.items
            if isinstance(item.optional_vars, ast.Name)
            and isinstance(item.context_expr, ast.Call)
            and (path := cls._opens_literal(item.context_expr)) is not None
        }
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            arguments = [*call.args, *(k.value for k in call.keywords)]
            if not any(touches(a) for a in arguments):
                continue
            filled += [a for a in arguments if isinstance(a, ast.Name)]
            func = call.func
            if isinstance(func, ast.Attribute) and func.attr in cls.FILLS:
                if isinstance(func.value, ast.Name):
                    filled.append(func.value)
                    if func.value.id in opened_as:
                        literals.add(opened_as[func.value.id])
                elif isinstance(func.value, ast.Call):
                    path = cls._opens_literal(func.value)
                    if path is not None:
                        literals.add(path)
        return filled, literals


class BoundClient:
    """A call made on a client the file built, to a host the caller configures (reviews/pypi-98/20 B2).

    `self.client = paramiko.SSHClient()` in `__init__` and `self.client.connect(host, key_filename=key)`
    forty lines on: the connect carries no mention of the client, so the text of the call alone
    cannot say whose it is. The tree can: the receiver is bound in this file to the family's client
    constructor. It is the user's own login only where the host is not written down in the package: a
    parameter, an attribute the caller set, an environment or argument read. A host that is a literal,
    or a name every binding of which is a literal, is one the package names, and a key sent there is
    not the user's own login.
    """

    #: What names the host of a connection, positional first and then by keyword.
    HOST_KEYWORDS: Final = ("hostname", "host", "address", "addr")

    @classmethod
    def configured(cls, text: str, line: int, client: re.Pattern[bytes]) -> bool:
        """Whether a call starting on `line` is a method of a receiver bound to a constructor that
        `client` names, and its host is not written down in the file. False where the file does not
        parse, no such call is there, or any call there is not that."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            tree = PythonSyntax.shared(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # S2: a fallback; a file that does not parse keeps the text reading of its calls
            return False
        calls = [c for c in PythonSyntax.of(tree, ast.Call) if c.lineno == line]
        bound = cls._bound(tree, client)
        methods = [c for c in calls if isinstance(c.func, ast.Attribute)]
        on_client = [c for c in methods if cls._dotted(c.func.value) in bound]  # type: ignore[attr-defined]
        return bool(on_client) and all(cls._host_is_configured(tree, c) for c in on_client)

    @classmethod
    def _bound(cls, tree: ast.AST, client: re.Pattern[bytes]) -> set[str]:
        """The names and attribute paths the file assigns the result of a constructor `client` names."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        found: set[str] = set()
        assigns = PythonSyntax.of(tree, ast.Assign)
        for node in assigns:
            if isinstance(node.value, ast.Call) and client.search(
                cls._dotted(node.value.func).encode("utf-8")
            ):
                found.update(cls._dotted(t) for t in node.targets)
        for _ in range(3):  # `self.client = ssh` after `ssh = paramiko.SSHClient()`
            grown = {
                cls._dotted(t)
                for node in assigns
                if cls._dotted(node.value) in found
                for t in node.targets
            }
            if grown <= found:
                break
            found |= grown
        found.discard("")
        return found

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return ""

    @classmethod
    def _host_is_configured(cls, tree: ast.AST, call: ast.Call) -> bool:
        host = call.args[0] if call.args else None
        if host is None:
            host = next((k.value for k in call.keywords if k.arg in cls.HOST_KEYWORDS), None)
        return host is not None and not cls._written_down(tree, host, 0)

    @classmethod
    def _written_down(cls, tree: ast.AST, host: ast.AST, depth: int) -> bool:
        """Whether the host is a literal: a string, a join of literals, or a name or attribute every
        assignment of which in the file is a literal. A name nothing assigns is a parameter."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        if isinstance(host, ast.Constant):
            return True
        if isinstance(host, ast.JoinedStr | ast.BinOp):
            parts = [
                n for n in ast.walk(host) if isinstance(n, ast.Name | ast.Attribute | ast.Call)
            ]
            return not parts
        name = cls._dotted(host)
        if not name or depth > 4:
            return False
        values: list[ast.AST] = []
        for node in PythonSyntax.of(tree, ast.Assign):
            for target in node.targets:
                if cls._dotted(target) == name:
                    values.append(node.value)
                elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                    for one, value in zip(target.elts, node.value.elts, strict=False):
                        if cls._dotted(one) == name:
                            values.append(value)
        return bool(values) and all(cls._written_down(tree, v, depth + 1) for v in values)
