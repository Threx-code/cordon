"""Stateless facts about Python source: the constant a string expression folds to, the calls a tree
makes and their dotted names, the lines a comment or docstring excuses, literals and patterns, what
a command list runs, and the hit and call records the analyser reports.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # from the source
    from collections.abc import Callable

# Dotted primitives, mapped to what they mean. The keys are what a resolved
# call must look like once aliases and bindings are unwound, so `go(...)` where
# `go` is `subprocess.run` arrives here as `subprocess.run`.


# Dotted primitives, mapped to what they mean. The keys are what a resolved
# call must look like once aliases and bindings are unwound, so `go(...)` where
# `go` is `subprocess.run` arrives here as `subprocess.run`.
PRIMITIVES: dict[str, Capability] = {
    "base64.b64decode": Capability.DECODE,
    "base64.b32decode": Capability.DECODE,
    "base64.b16decode": Capability.DECODE,
    "base64.urlsafe_b64decode": Capability.DECODE,
    "base64.decodebytes": Capability.DECODE,
    "base64.standard_b64decode": Capability.DECODE,
    "base64.b32hexdecode": Capability.DECODE,
    "base64.b85decode": Capability.DECODE,
    "base64.a85decode": Capability.DECODE,
    # Python 3.13's ZeroMQ alphabet; aiolrucache's loader decodes its bytecode with it.
    "base64.z85decode": Capability.DECODE,
    "binascii.a2b_base64": Capability.DECODE,
    "binascii.unhexlify": Capability.DECODE,
    "codecs.decode": Capability.DECODE,
    "zlib.decompress": Capability.DECOMPRESS,
    "lzma.decompress": Capability.DECOMPRESS,
    "bz2.decompress": Capability.DECOMPRESS,
    "gzip.decompress": Capability.DECOMPRESS,
    "bytes.fromhex": Capability.DECODE,
    # `marshal.loads` is deliberately absent. The pattern tier labels it `execute`
    # -- a marshal stream holds code objects, so loading one is an evaluation wearing
    # a serialisation format, and `CAP.PY.EXECUTE.001` argues it at length -- and
    # labelling it `decode` here as well handed `SUSPECT.DECODE_EXEC.001` both halves
    # out of one call. CPython's own `Lib/importlib/_bootstrap_external.py` was
    # reported for it: `_compile_bytecode`'s body is `code = marshal.loads(data)`, the
    # function every `.pyc` in the world is loaded by.
    #
    # Nothing is lost by dropping the second label. The two-call forms still report,
    # because their decode comes from the other call:
    # `marshal.loads(base64.b64decode(DATA))` is base64 decoding and marshal
    # executing, and `exec(marshal.loads(base64.b64decode(blob)))` is the same with a
    # third step. Only a lone `marshal.loads(data)` goes quiet, which is the importer.
    "pickle.loads": Capability.DESERIALIZE,
    "exec": Capability.EXECUTE,
    "eval": Capability.EXECUTE,
    "compile": Capability.EXECUTE,
    "os.system": Capability.SPAWN,
    "os.popen": Capability.SPAWN,
    "os.execv": Capability.SPAWN,
    "os.execve": Capability.SPAWN,
    "os.spawnv": Capability.SPAWN,
    "subprocess.run": Capability.SPAWN,
    "subprocess.call": Capability.SPAWN,
    "subprocess.check_call": Capability.SPAWN,
    "subprocess.check_output": Capability.SPAWN,
    "os.startfile": Capability.SPAWN,
    "subprocess.getoutput": Capability.SPAWN,
    "subprocess.getstatusoutput": Capability.SPAWN,
    "subprocess.Popen": Capability.SPAWN,
    "pty.spawn": Capability.SPAWN,
    "os.environ": Capability.CREDENTIAL,
    "os.getenv": Capability.CREDENTIAL,
    "os.environb": Capability.CREDENTIAL,
    "urllib.request.urlopen": Capability.EGRESS,
    # Who and where this is, through whatever name it was imported under.
    "socket.gethostname": Capability.RECONNAISSANCE,
    "socket.getfqdn": Capability.RECONNAISSANCE,
    "getpass.getuser": Capability.RECONNAISSANCE,
    "os.getlogin": Capability.RECONNAISSANCE,
    "platform.node": Capability.RECONNAISSANCE,
    "platform.uname": Capability.RECONNAISSANCE,
    "uuid.getnode": Capability.RECONNAISSANCE,
    "urllib.request.urlretrieve": Capability.EGRESS,
    "requests.get": Capability.EGRESS,
    "requests.post": Capability.EGRESS,
    "requests.put": Capability.EGRESS,
    "requests.patch": Capability.EGRESS,
    "requests.delete": Capability.EGRESS,
    "requests.request": Capability.EGRESS,
    "httpx.get": Capability.EGRESS,
    "httpx.post": Capability.EGRESS,
    "httpx.Client": Capability.EGRESS,
    # Socket creation and a bare DNS lookup are not egress on their own (census D): a server creates
    # a socket to bind and resolves its own name. Egress is `create_connection`, a `.connect(...)` on
    # a created socket (`_socket_connect`), or a runtime-built DNS name (DNS_CONSTRUCTED.AST).
    "socket.create_connection": Capability.EGRESS,
    "smtplib.SMTP": Capability.EGRESS,
    "ftplib.FTP": Capability.EGRESS,
    "http.client.HTTPConnection": Capability.EGRESS,
    "http.client.HTTPSConnection": Capability.EGRESS,
}


ENVIRONMENT = frozenset({"os.environ", "os.getenv", "os.environb"})
"""The environment primitives, which need a second question asked of them."""


MAX_FOLDED_CODES = 200_000


#: Calls that return this machine's own name; `get_hostname` is Ansible's callback helper.
OWN_HOST_CALLS = frozenset({"gethostname", "getfqdn", "node", "get_hostname"})


SCRIPT_LAUNCH = re.compile(
    r"(?i)(?:^|[\s\"'])[\w.@%\\/:$~-]{1,200}\.(?:exe|scr|com|bat|cmd|vbs|vbe|jse|wsf|hta|ps1|msi|sh|py|pl|rb)"
    r"(?:[\s\"']|$)"
)
"""A command that names a script or program file to run, rather than only a tool on PATH."""


DNS_LOOKUPS = frozenset(
    {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo", "socket.getfqdn"}
)


@dataclass(frozen=True, slots=True)
class AstHit:
    """One capability resolved from the tree, with where it was seen."""

    capability: Capability
    line: int
    detail: str
    column: int = 0
    """Byte offset of the call within its line, 0-based. Carried for the same
    reason as `AstCall.column`: a composite's byte-distance bound needs the true
    position, not the start of the line, or a minified one-line file collapses
    every hit to the same place."""
    command: str | None = None
    """The command string handed to a spawn primitive, when it is derivable.

    A shell command written as a Python string is data to every language pack:
    the Python rules see a string, and the shell rules never run on a `.py`
    file. Carrying it here is what lets the shell rules be applied to the one
    place in the file where a string is unambiguously a command."""

    fixed_command: bool = False
    """Whether EVERY part of that command was a literal in the source.

    `command` is filled in when any part resolves, because a partially resolved
    command is still worth matching shell rules against. This is the stricter
    question, and a different one: a spawn whose whole argv is written out cannot
    be running anything the file decoded or downloaded, because what it runs is
    visible in the file.

    False for a command mentioning a temporary or relative path, which is where a
    dropped payload lands: `subprocess.run(["/tmp/update"])` is a constant argv and
    is also the second half of a dropper."""


@dataclass(frozen=True, slots=True)
class Assembled:
    """A string value built by concatenation, and what it evaluates to.

    Carried separately from capabilities because it answers a different
    question: not what this code can do, but what value it contains that no
    contiguous pattern can see.
    """

    value: str
    line: int
    name: str | None
    """The name it was assigned to, when it was assigned to one."""

    assembled: bool = True
    """Whether the value was built from more than one piece.

    A plain literal is carried too, because Python joins adjacent literals with
    no operator and the byte scan cannot see the joined value. But the two are
    not equivalent evidence: the entropy heuristic's whole justification is that
    building a value out of pieces is not how a URL or an identifier is written,
    and applying it to every constant in a file reports every long URL as a
    credential. Provider shapes and known prefixes apply to both."""


@dataclass(frozen=True, slots=True)
class AstCall:
    """One call site, with its callee resolved and its arguments folded.

    The difference between this and the source text is the whole point of the
    `ast` match kind. `f = os.system; f(cmd)` produces `name="os.system"`, and
    so does `getattr(os, "sys" + "tem")(cmd)` -- neither of which any pattern
    over the bytes can see, because in the first the call site says `f` and in
    the second the primitive's name does not appear in the file at all.
    """

    name: str
    """The callee's dotted name, resolved through imports, aliases, local
    bindings and `getattr`. `""` when it could not be resolved."""

    line: int

    column: int = 0
    """Byte offset of the call within its line, 0-based.

    Carried so a composite's proximity check can measure the true distance
    between two call sites rather than treating both as the start of their line.
    On a minified bundle the whole file is one line, and without this every call
    collapses to the same position -- which is how a decode and an execution
    four thousand bytes apart came to satisfy a rule that asks for them in the
    same breath."""

    arguments: tuple[str, ...] = ()
    """Positional arguments folded to their constant values, in order.

    `""` for an argument that is not a derivable constant, so position is
    preserved -- a query about argument 1 must not silently read argument 2
    because argument 0 was a variable. A list or tuple argument folds to its
    elements joined by a space, which is how `["sh", "-c", "..."]` and
    `"sh -c ..."` become the same string to a rule author."""

    keywords: tuple[tuple[str, str], ...] = ()
    """Keyword arguments, folded the same way. Present so a rule can say
    `shell=True` without caring where in the call it was written."""

    has_constructed_argument: bool = False
    """Whether any argument is a BUILT expression rather than a literal or name.

    A concatenation, an f-string, a `.format()`, a slice, or a nested call.
    This is what separates `resolve("api.example.com")` -- a name written in
    the source -- from `resolve(blob[i:i+60] + ".exfil.invalid")`, where the
    hostname carries program data. The regex tier draws the same line by
    requiring a `+`, `%` or f-string after the resolver call; carrying it here
    lets an `ast` rule stay that precise while seeing through an aliased
    import, which the regex cannot."""

    @property
    def argument_text(self) -> str:
        """Every resolved argument as one string, for a pattern to run over."""
        parts = [a for a in self.arguments if a]
        parts.extend(f"{k}={v}" for k, v in self.keywords if v)
        return " ".join(parts)


class PythonFacts:
    """Stateless facts about Python source."""

    @staticmethod
    def literal_strings(node: ast.AST) -> list[str] | None:
        if not isinstance(node, ast.Tuple | ast.List) or not node.elts:
            return None
        values = [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        return values if len(values) == len(node.elts) else None

    #: `setup()` keywords that are a package's description, never something it does.
    SETUP_METADATA = frozenset(
        {
            "description",
            "long_description",
            "install_requires",
            "extras_require",
            "tests_require",
            "setup_requires",
            "requires",
            "keywords",
            "classifiers",
            "project_urls",
            "summary",
        }
    )

    #: `re` and `regex` functions whose first argument is a pattern: text to match against.
    PATTERN_CALLS = frozenset(
        {"compile", "match", "fullmatch", "search", "findall", "finditer", "sub", "subn", "split"}
    )

    @classmethod
    def _pattern_literals(cls, tree: ast.AST) -> frozenset[int]:
        """Lines of a regular expression written as literal text: `re.compile(r"/etc/rc\\.local|
        ~/\\.ssh")`. A pattern says what to look for; nothing reads or writes the paths it names.
        Cordon's own tool-call guard lists every persistence path it refuses, and the pattern
        tier read it as persistence (review 98) -- as it would any scanner, linter or guard. Only
        a pattern made of literals is covered: one built from a call or a variable keeps its hit."""
        lines: set[int] = set()
        for node in PythonSyntax.nodes(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("re", "regex")
                and node.func.attr in PythonFacts.PATTERN_CALLS
                and node.args
            ):
                continue
            pattern = node.args[0]
            if all(
                isinstance(part, ast.Constant | ast.BinOp | ast.operator)
                for part in ast.walk(pattern)
            ):
                first = getattr(pattern, "lineno", None)
                last = getattr(pattern, "end_lineno", None) or first
                if first is not None:
                    lines.update(range(first, (last or first) + 1))
        return frozenset(lines)

    @staticmethod
    def _persistence_not_reaching_a_write(
        source: str, tree: ast.AST, hits: list[AstHit]
    ) -> frozenset[int]:
        """Lines whose persistence location is named in a literal that never reaches a write
        (`analysis/python/py_persist.py`): a list of the profiles a key is read from, a scanner's
        pattern table, `crontab -l` saved as evidence. A line this tier itself read as persistence
        (a profile opened to append, its path folded from character codes) keeps its hit."""
        from cordon_scanner.analysis.python.py_persist import PythonPersistence

        written = PythonPersistence.written_lines(tree)
        if written is None:
            return frozenset()
        recorded = {hit.line for hit in hits if hit.capability is Capability.PERSIST}
        return PythonPersistence.named_only_lines(source) - written - recorded

    #: Calls that show text to a person: what a shell profile line is in them is advice.
    MESSAGE_CALLS = frozenset(
        {"print", "echo", "warn", "warning", "info", "debug", "error", "wrn", "inf", "dbg", "err"}
    )

    @classmethod
    def _persistence_named_not_written(cls, tree: ast.AST) -> frozenset[int]:
        """Lines where a profile, a crontab or a unit is only named: a `setup()` description or
        requirement (`'python-crontab'`, a README inlined as `long_description`), a docstring, a
        message printed or logged for a person (`log.wrn('add to ~/.bashrc')`). Nothing on such
        a line writes anywhere, and at install time the pattern tier read each as a foothold
        planted (review 98). A line that also writes keeps its hit: the excuse is per line, and
        a write is a call the line would also hold."""
        lines: set[int] = set()

        def cover(node: ast.AST) -> None:
            first = getattr(node, "lineno", None)
            last = getattr(node, "end_lineno", None) or first
            if first is not None:
                lines.update(range(first, (last or first) + 1))

        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Call):
                name = PythonFacts._call_name(node.func)
                if name == "setup":
                    for keyword in node.keywords:
                        if keyword.arg in PythonFacts.SETUP_METADATA:
                            cover(keyword.value)
                elif name in PythonFacts.MESSAGE_CALLS and not any(
                    isinstance(child, ast.Call)
                    and PythonFacts._call_name(child.func) not in PythonFacts.MESSAGE_CALLS
                    for argument in (*node.args, *(k.value for k in node.keywords))
                    for child in ast.walk(argument)
                ):
                    cover(node)
            elif isinstance(
                node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module
            ):
                body = getattr(node, "body", [])
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    cover(body[0])
        return frozenset(lines)

    @staticmethod
    def _call_name(func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    @staticmethod
    def _has_dotted_literal(node: ast.AST) -> bool:
        """Whether a built value carries a literal domain suffix: `x + ".lib.example.com"`."""
        return any(
            isinstance(part.value, str) and "." in part.value.strip(".")
            for part in PythonSyntax.within(node, ast.Constant)
        )

    @staticmethod
    def _is_constructed(node: ast.AST) -> bool:
        """Whether an argument is BUILT rather than named or written whole.

        A concatenation, an interpolation, a `.format()`, a slice or a nested
        call -- the shapes that carry runtime data into an argument. A plain
        literal, a bare name and an attribute access are not constructed: those
        are how ordinary code passes a fixed host or a variable.
        """
        # A folds-to-a-constant expression is a literal written in pieces, not a
        # value built at runtime: `"api." + ".example.com"` is the fixed string
        # `"api..example.com"`. Only an expression that pulls in a name, a call
        # or a slice carries runtime data, so a fully constant one is not
        # "constructed" for this purpose -- otherwise a resolver call with a
        # hostname spelled as two adjacent literals reads as exfiltration.
        if PythonFacts.constant(node) is not None:
            return False
        if PythonFacts._own_name_locally(node):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return True
        if isinstance(node, ast.JoinedStr | ast.Subscript):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"format", "join"}:
                return True
            # Resolving this machine's own name -- `gethostbyname(socket.gethostname())` -- is
            # how a program finds its address; xgboost's tracker and jupyter_client both do it.
            # The name was built by nobody.
            callee = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else ""
            )
            # Otherwise a nested call whose value becomes the argument -- `tohex(host())`.
            return callee not in OWN_HOST_CALLS
        return False

    LOCAL_SUFFIXES = (".local", ".localdomain", ".lan", ".home.arpa", ".internal")
    """Suffixes that name this machine on its own network and are never sent to a public
    resolver's operator: mDNS's `.local` and the reserved home and internal zones."""

    @staticmethod
    def _own_name_locally(node: ast.AST) -> bool:
        """`socket.gethostname() + ".local"` -- this machine's own name in a local-only zone, which
        jupyter_client resolves when the bare hostname maps to loopback. No data travels in it."""
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
            return False
        suffix = PythonFacts.constant(node.right)
        func = node.left.func if isinstance(node.left, ast.Call) else None
        callee = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else ""
        )
        return (
            callee in OWN_HOST_CALLS
            and suffix is not None
            and suffix.lower() in PythonFacts.LOCAL_SUFFIXES
        )

    @classmethod
    def assembled(cls, source: str) -> list[Assembled]:
        """String values built by concatenation, folded to what they evaluate to.

        A credential regex needs a contiguous literal, and `"ghp_" + "..."` is
        not one. The value is identical to the interpreter and invisible to the
        pattern, which makes splitting a token across a `+` the cheapest way to
        commit a live credential past a secret scanner.

        Returns every derivable string value, including plain literals. That
        looks redundant against the byte-level pattern pass and is not: adjacent
        string literals in Python concatenate with no operator, so `("ghp_"
        "rest")` is a single constant to the parser and two separate quoted runs
        in the file. Deduplication happens in the caller, which hashes the value
        rather than its spelling.
        """
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return []

        found: list[Assembled] = []

        for node in PythonSyntax.of(tree, ast.Assign, ast.AnnAssign, ast.AugAssign):
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                value: ast.AST | None = node.value
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign | ast.AugAssign):
                value = node.value
                targets = [node.target.id] if isinstance(node.target, ast.Name) else []
            else:
                continue

            if value is None:
                continue

            # Plain constants are included, and that is not redundant with the
            # byte scan. Python concatenates adjacent literals with no operator
            # at all -- `("ghp_" "rest")` is one `Constant` to the parser and
            # two separated literals in the source -- so the contiguous pattern
            # never sees the joined value while the interpreter only ever sees
            # the joined value. Anything the byte scan did find is already in
            # the caller's `seen` set and is dropped there.
            folded = PythonFacts.constant(value)
            if folded is None:
                continue

            found.append(
                Assembled(
                    value=folded,
                    line=getattr(value, "lineno", 1),
                    name=targets[0] if targets else None,
                    assembled=not isinstance(value, ast.Constant),
                )
            )

        return found

    @staticmethod
    def parses(source: str) -> bool:
        """Whether this is Python the analyzer could read.

        Asked separately so the caller can report a file it could not analyse
        rather than quietly treating an unreadable file as an uninteresting
        one."""
        try:
            PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return False
        return True

    @classmethod
    def is_literal_strings(cls, node: ast.AST) -> bool:
        """Whether this expression is a list, tuple or set of string literals.

        Not a general evaluator: only the written-out form, where reading the file is
        reading the values. A name bound to a list elsewhere is not followed, because
        the next thing to follow would be a list that is appended to, and then one
        built from a network response.
        """
        if not isinstance(node, ast.List | ast.Tuple | ast.Set):
            return False
        return bool(node.elts) and all(
            isinstance(element, ast.Constant) and isinstance(element.value, str)
            for element in node.elts
        )

    @classmethod
    def constant(cls, node: ast.AST) -> str | None:
        """The string an expression evaluates to, if it is derivable statically.

        Handles the shapes that hide a name: adjacent literals, `+` chains,
        `"".join([...])` and f-strings whose parts are all constant. Anything
        else returns None, which is the signal that the target is genuinely
        computed at runtime.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # A `+` chain nests to the left, and an obfuscated file writes thousands of terms:
            # `"a" + "b" + ...`. Walked with a stack rather than by recursion, so its length cannot
            # exhaust Python's -- a RecursionError here once lost the whole file's analysis.
            parts: list[str] = []
            stack: list[ast.AST] = [node]
            while stack:
                current = stack.pop()
                if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                    stack.append(current.right)
                    stack.append(current.left)
                    continue
                value = PythonFacts.constant(current)
                if value is None:
                    return None
                parts.append(value)
            return "".join(parts)
        if isinstance(node, ast.JoinedStr):
            pieces = [PythonFacts.constant(value) for value in node.values]
            return (
                None if any(part is None for part in pieces) else "".join(p or "" for p in pieces)
            )
        if isinstance(node, ast.FormattedValue):
            return PythonFacts.constant(node.value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
        ):
            joined = PythonFacts._joined(node)
            if joined is not None:
                return joined
        # `chr(102)`, one character at a time.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "chr"
            and len(node.args) == 1
        ):
            code = PythonFacts._code_point(node.args[0])
            if code is not None:
                return chr(code)
        return None

    @classmethod
    def _joined(cls, node: ast.Call) -> str | None:
        """`sep.join(...)` over constant pieces, or over character codes spelled as a list or map:
        the string it builds, or None when a piece is not constant."""
        if not isinstance(node.func, ast.Attribute):  # the caller's test, restated for the type
            return None
        separator = PythonFacts.constant(node.func.value)
        elements = node.args[0]
        if separator is not None and isinstance(elements, ast.List | ast.Tuple):
            pieces = [PythonFacts.constant(element) for element in elements.elts]
            if all(part is not None for part in pieces):
                return separator.join(part or "" for part in pieces)
        # `"".join([chr(x) for x in [47, 101, ...]])`: the same, as a comprehension.
        if (
            separator is not None
            and isinstance(elements, ast.ListComp | ast.GeneratorExp)
            and len(elements.generators) == 1
            and not elements.generators[0].ifs
            and isinstance(elements.generators[0].target, ast.Name)
            and isinstance(elements.generators[0].iter, ast.List | ast.Tuple)
            and len(elements.generators[0].iter.elts) <= MAX_FOLDED_CODES
            and isinstance(elements.elt, ast.Call)
            and isinstance(elements.elt.func, ast.Name)
            and elements.elt.func.id == "chr"
            and len(elements.elt.args) == 1
            and isinstance(elements.elt.args[0], ast.Name)
            and elements.elt.args[0].id == elements.generators[0].target.id
        ):
            codes = [PythonFacts._code_point(e) for e in elements.generators[0].iter.elts]
            if all(c is not None for c in codes):
                return separator.join(chr(c) for c in codes if c is not None)
        # `"".join(map(chr, [102, 114, 111, 109, ...]))`: code spelled as character codes.
        if (
            separator is not None
            and isinstance(elements, ast.Call)
            and isinstance(elements.func, ast.Name)
            and elements.func.id == "map"
            and len(elements.args) == 2
            and isinstance(elements.args[0], ast.Name)
            and elements.args[0].id == "chr"
            and isinstance(elements.args[1], ast.List | ast.Tuple)
            and len(elements.args[1].elts) <= MAX_FOLDED_CODES
        ):
            codes = [PythonFacts._code_point(e) for e in elements.args[1].elts]
            if all(c is not None for c in codes):
                return separator.join(chr(c) for c in codes if c is not None)
        return None

    @staticmethod
    def _code_point(node: ast.AST) -> int | None:
        if (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and 0 <= node.value <= 0x10FFFF
        ):
            return node.value
        return None

    WRITABLE_TARGET = re.compile(
        r"""(?:^|[\s"'=])(?:\./|\.\\|/tmp/|/var/tmp/|/dev/shm/|%TEMP%|\$TMPDIR|\$HOME/\.)""",
    )
    """Paths a dropper writes its payload to.

    A constant argv naming one of these is not the reassurance the rest of
    `fixed_command` is: the command is fixed and the FILE it runs is not, because
    whatever ran before it created that file."""

    BARE_SHELL = re.compile(
        r"""(?ix)
        ^[ \t]*
        (?:[\w.-]{0,40}[/\\]){0,4}
        (?:sh|bash|zsh|ksh|dash|ash|csh|tcsh|fish|cmd|powershell|pwsh)
        (?:\.exe)?
        (?:[ \t]{1,4}-{1,2}[il]{1,2}\b){0,3}
        [ \t]*$
        """,
    )
    """A constant argv that is a shell and nothing else.

    The discount `fixed_command` applies rests on one claim: a spawn whose whole
    command is visible cannot be running something decoded or downloaded. That
    holds for `["git", "rev-parse", "HEAD"]` and fails completely for
    `["/bin/sh", "-i"]`, where the literal IS the act -- what such a shell runs
    arrives over whatever its file descriptors were wired to, which is the whole
    construction of a reverse shell.

    Measured: `subprocess.call(["/bin/sh", "-i"])` next to
    `socket.connect(("<literal ip>", 4444))` produced no finding at all, because
    the spawn half was discounted here and `MALWARE.REVERSE_SHELL.001` needs
    both. The pattern tier's hit on the same line was dropped with it, by line.

    `sh -c "<command>"` is deliberately NOT this shape: it carries its command,
    the embedded-shell tier extracts it, and the discount stays correct there."""

    @classmethod
    def fixed_command(cls, node: ast.Call) -> bool:
        """Whether every argument of this spawn was written out in the source."""
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple):
            parts = [PythonFacts.constant(element) for element in first.elts]
            if not parts or any(part is None for part in parts):
                return False
            resolved = " ".join(part for part in parts if part is not None)
        else:
            single = PythonFacts.constant(first)
            if single is None:
                return False
            resolved = single
        if PythonFacts.BARE_SHELL.match(resolved):
            return False
        if SCRIPT_LAUNCH.search(resolved):
            # `os.system("start main.cpython-39.vbs")`: literal, and what it runs is a file whose
            # content is not in the command -- where a dropper that brought its payload with it
            # puts it. `subprocess.run(["git", "rev-parse"])` names a tool, not a file.
            return False
        return PythonFacts.WRITABLE_TARGET.search(resolved) is None

    @staticmethod
    def parameter_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        return [a.arg for a in (*function.args.posonlyargs, *function.args.args)]

    @staticmethod
    def opened_path(call: ast.AST) -> ast.AST | None:
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "open"
            and call.args
        ):
            return call.args[0]
        return None

    @staticmethod
    def carried(
        tree: ast.AST, is_source: Callable[[ast.AST], bool], kind: type
    ) -> Callable[..., bool]:
        """Whether an expression holds what `is_source` finds: the source itself, a name assigned
        from it, or a call to a function of this file that returns it. The last is how a collector
        is written -- `def collect(): return json.dumps({"host":
        socket.gethostname(), ...})` in one function, `requests.post(URL, data=collect())` in
        another (review 98: eight MalSkillBench beacons). Names resolve per scope (`name_scope`), and
        an argument's load passes to the parameter it binds, call after call (`passed`).
        """
        scope = PythonSyntax.name_scope(tree)
        passed = PythonSyntax.passed(tree)
        functions = PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        carrying: set[tuple[int, str]] = set()
        returning: set[str] = set()

        def callee(call: ast.Call) -> str | None:
            func = call.func
            if isinstance(func, ast.Name):
                return func.id
            # `self.collect()` and `Collector.collect()`: a method of a class in this file.
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                return func.attr
            return None

        def holds(node: ast.AST, *, deep: bool = True) -> bool:
            parts = PythonSyntax.within(node, kind, ast.Call, ast.Name) if deep else [node]
            return any(
                is_source(part)
                or (isinstance(part, ast.Name) and (scope(part, part.id), part.id) in carrying)
                or (isinstance(part, ast.Call) and callee(part) in returning)
                for part in parts
            )

        for _ in range(3):
            carrying.update((function, param) for arg, function, param in passed if holds(arg))
            for node in PythonSyntax.nodes(tree):
                if isinstance(node, ast.Assign) and holds(node.value):
                    carrying.update(
                        (scope(t, t.id), t.id) for t in node.targets if isinstance(t, ast.Name)
                    )
            for function in functions:
                if function.name not in returning and any(
                    isinstance(part, ast.Return) and part.value is not None and holds(part.value)
                    for part in PythonSyntax.within(function, ast.Return)
                ):
                    returning.add(function.name)
        return holds

    @staticmethod
    def url_literal(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "://" in node.value:
            return node.value
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and "://" in first.value
            ):
                return first.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return PythonFacts.url_literal(node.left)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return PythonFacts.url_literal(node.func.value)
        return None

    @staticmethod
    def is_local_read(node: ast.AST) -> bool:
        """`open(<no URL>)`, optionally `.read()`/`.readlines()`/`.strip()` on it, or
        `<path>.read_text()`."""
        current = node
        while (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and (
                current.func.attr
                in ("read", "readlines", "strip", "splitlines", "decode", "read_text")
            )
        ):
            if current.func.attr == "read_text":
                return True
            current = current.func.value
        if not (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "open"
        ):
            return False
        literals = [
            n.value for n in PythonSyntax.within(current, ast.Constant) if isinstance(n.value, str)
        ]
        return not any("://" in value for value in literals)

    @staticmethod
    def unsafe_model_option(node: ast.Call, dotted: str | None) -> str:
        """A model loader called with its safety switch turned off: Keras's `safe_mode=False`
        (Lambda layers run arbitrary Python), NumPy's `allow_pickle=True` (an object array is a
        pickle), each written out as a constant."""
        name = (dotted or "").rsplit(".", 1)[-1]
        for keyword in node.keywords:
            if not isinstance(keyword.value, ast.Constant):
                continue
            if keyword.arg == "safe_mode" and keyword.value.value is False and name == "load_model":
                return "safe_mode=False"
            if keyword.arg == "allow_pickle" and keyword.value.value is True and name == "load":
                return "allow_pickle=True"
        return ""


__all__ = [
    "DNS_LOOKUPS",
    "ENVIRONMENT",
    "MAX_FOLDED_CODES",
    "OWN_HOST_CALLS",
    "PRIMITIVES",
    "SCRIPT_LAUNCH",
    "Assembled",
    "AstCall",
    "AstHit",
    "PythonFacts",
]
