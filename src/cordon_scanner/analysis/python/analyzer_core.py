"""The Python analyser's state and its core: the name tables a tree binds, dotted names resolved
through them, callees resolved through aliases, and hits recorded. Its flows build on this.
"""

from __future__ import annotations

import ast

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
        # Local name -> dotted primitive, from `f = os.system`.
        self._bindings: dict[str, str] = {}
        # Inner call -> the call that invokes its result. `getattr(os, "system")`
        # resolves to a primitive, but the command it is handed belongs to the
        # enclosing `(...)`, so the two nodes have to be related to read it.
        self._invoked: dict[int, ast.Call] = {}
        # Names whose every possible value is written in the file. See `_enumerated`.
        self._enumerated: set[str] = set()
        self._follow_literals = True
        # Name -> the string literal it is bound to, for names bound exactly once.
        self._strings: dict[str, str | None] = {}
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
        if isinstance(node, ast.Name):
            return self._aliases.get(node.id) or self._bindings.get(node.id) or node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted(node.value)
            if base in BUILTIN_MODULES:
                # `builtins.exec` is `exec`: the module is how the name is reached, not part of it.
                return node.attr
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call) and node.args:
            # `__import__("base64")` and `importlib.import_module("base64")` evaluate to the module,
            # so `__import__("base64").b64decode` is `base64.b64decode` -- the spelling droppers use
            # to keep `import base64` and `exec(` off the same page.
            callee = self._dotted(node.func)
            if callee in ("__import__", "importlib.import_module"):
                module = PythonFacts.constant(node.args[0])
                if module:
                    return module
            if callee == "eval":
                return self._evaluated_name(node.args[0])
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
        except (SyntaxError, ValueError, RecursionError):
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
