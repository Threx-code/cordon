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
    "zlib.decompress": Capability.DECODE,
    "bytes.fromhex": Capability.DECODE,
    "marshal.loads": Capability.DECODE,
    "pickle.loads": Capability.EXECUTE,
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
    command: str | None = None
    """The command string handed to a spawn primitive, when it is derivable.

    A shell command written as a Python string is data to every language pack:
    the Python rules see a string, and the shell rules never run on a `.py`
    file. Carrying it here is what lets the shell rules be applied to the one
    place in the file where a string is unambiguously a command."""


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
    def assembled(cls, source: str) -> list[Assembled]:
        """String values built by concatenation, folded to what they evaluate to.

        A credential regex needs a contiguous literal, and `"ghp_" + "..."` is
        not one. The value is identical to the interpreter and invisible to the
        pattern, which makes splitting a token across a `+` the cheapest way to
        commit a live credential past a secret scanner.

        Only assembled values are returned. A plain literal is already a
        contiguous run of bytes and the ordinary pattern pass has seen it;
        repeating it here would double every finding.
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

            if value is None or isinstance(value, ast.Constant):
                continue

            folded = cls.constant(value)
            if folded is None:
                continue

            found.append(
                Assembled(
                    value=folded,
                    line=getattr(value, "lineno", 1),
                    name=targets[0] if targets else None,
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
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
                self._invoked[id(node.func)] = node

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._call(node)
            elif isinstance(node, ast.Attribute | ast.Name):
                # `os.environ` is a primitive without being called.
                dotted = self._dotted(node)
                if dotted in PRIMITIVES and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                    self._record(PRIMITIVES[dotted], node, dotted)
            elif isinstance(node, ast.Subscript):
                self._subscript(node)

    def _call(self, node: ast.Call) -> None:
        dotted = self._dotted(node.func)
        if dotted and dotted in PRIMITIVES:
            self._record(PRIMITIVES[dotted], node, dotted, command=self._command(node))
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
            if imported is None and node.args:
                self._dynamic(node, "__import__ with a computed module name")
            return

        if attribute is not None and namespace:
            resolved = f"{namespace}.{attribute}"
            if resolved in PRIMITIVES:
                callsite = self._invoked.get(id(node), node)
                self._record(PRIMITIVES[resolved], node, resolved, command=self._command(callsite))
                return
        if len(node.args) > 1 and attribute is None and namespace in DANGEROUS_NAMESPACES:
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

        if container in DANGEROUS_NAMESPACES or container in {"globals", "vars", "locals"}:
            self._dynamic(node, f"{container}[...] with a computed key")

    # -- Recording -------------------------------------------------------

    def _record(
        self,
        capability: Capability,
        node: ast.AST,
        detail: str,
        command: str | None = None,
    ) -> None:
        keep = command if capability is Capability.SPAWN else None
        self._hits.append(
            AstHit(
                capability=capability,
                line=getattr(node, "lineno", 1),
                detail=detail,
                command=keep,
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
                detail=detail,
            )
        )


def resolve(source: str) -> Iterator[AstHit]:
    """Capabilities this source resolves to. Convenience over `PythonAnalyzer`."""
    yield from PythonAnalyzer.analyse(source)


__all__ = ["PRIMITIVES", "Assembled", "AstHit", "PythonAnalyzer", "resolve"]
