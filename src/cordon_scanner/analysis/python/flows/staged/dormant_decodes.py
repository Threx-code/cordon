"""A value decoded and then left unused: the carried or fetched half of a dropper, run step absent.

ethercheck 1.1.1's `__init__.py` fetches two pages at import, cuts a key and a payload out of their
text, hex-decodes both and XORs one with the other into a name nothing ever reads. spellcheckerpy
1.0.0's `SpellChecker.__init__` takes one value by a literal key from a gzip+JSON file it ships,
base64-decodes it into a local, and never reads it. A decode is work done to recover a value; code
that recovers one and discards it is carrying the value, encoded, for something else to use: a
later version, a second stage, a run step a reviewer would have seen.

`decoded and left unused: <decoder>`: in a function, or at module level, an assignment whose value
decodes data the caller did not hand in (no parameter, `self` or `cls` reaches it through the
function's own bindings: a response, a shipped file, a literal) (base64, base32, base16, base85, hex, `unhexlify`, `codecs.decode`) or XORs decoded data,
where nothing reads the result except further assignments that are themselves never read. At module
level a read anywhere in the file counts as a use, and only fetched data counts (another file may
import a decoded constant). `_` and names starting with `_unused` are an
author's explicit discard and are left alone.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class DormantDecodes(AnalyzerCore):
    """`_dormant_decodes` and what it needs."""

    #: Final names of the calls that decode.
    DECODERS: ClassVar[frozenset[str]] = frozenset(
        {"b64decode", "urlsafe_b64decode", "standard_b64decode", "b32decode", "b16decode",
         "b85decode", "a85decode", "decodebytes", "fromhex", "unhexlify", "a2b_hex", "a2b_base64"}
    )  # fmt: skip

    def _dormant_decodes(self, tree: ast.AST) -> None:
        functions = [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
        ]
        module_reads = self._reads(tree)
        for scope in [*functions, tree]:
            statements = self._own_assignments(scope)
            reads = module_reads if scope is tree else self._reads(scope)
            self._scope_dormant(
                statements, reads, self._parameters(scope), fetched_only=scope is tree
            )

    @staticmethod
    def _parameters(scope: ast.AST) -> set[str]:
        """What the caller hands the function: its parameters, `self` and `cls` among them."""
        args = getattr(scope, "args", None)
        if args is None:
            return set()
        named = [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
        return {a.arg for a in named if a is not None}

    @staticmethod
    def _own_assignments(scope: ast.AST) -> list[ast.Assign]:
        """Assignments to one plain name made by the scope itself, not by a function inside it."""
        found: list[ast.Assign] = []
        pending = list(ast.iter_child_nodes(scope))
        while pending:
            node = pending.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
                continue
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                found.append(node)
            pending.extend(ast.iter_child_nodes(node))
        return sorted(found, key=lambda a: (a.lineno, a.col_offset))

    @staticmethod
    def _reads(scope: ast.AST) -> list[ast.Name]:
        return [
            n
            for n in PythonSyntax.nodes(scope)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        ]

    def _decoder(self, value: ast.AST, decoded: set[str]) -> str | None:
        """The decoder an expression applies, or `xor` over a decoded name; None otherwise."""
        for node in PythonSyntax.nodes(value):
            if isinstance(node, ast.Call):
                dotted = self._dotted(node.func) or ""
                if dotted.rsplit(".", 1)[-1] in self.DECODERS or dotted == "codecs.decode":
                    return dotted
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.BitXor)
                and any(
                    isinstance(n, ast.Name) and n.id in decoded for n in PythonSyntax.nodes(node)
                )
            ):
                return "xor"
        return None

    #: Calls that read a file, the package's own data among them.
    FILE_READS: ClassVar[frozenset[str]] = frozenset(
        {"open", "io.open", "gzip.open", "bz2.open", "lzma.open", "pkgutil.get_data"}
    )

    def _package_data(self, value: ast.AST) -> bool:
        """Whether a value is data the package fetches, ships or writes down: a request's
        response, a file read, a bare function called with literals only (spellcheckerpy's
        `test_file("…", "…", "<key>")`), or a literal. An SDK client's method result is not:
        AWS's Secrets Manager snippet decodes `get_secret_value()` into a local it leaves for the
        reader to use."""
        if isinstance(value, ast.Constant) and isinstance(value.value, str | bytes):
            return True
        for node in PythonSyntax.nodes(value):
            if not isinstance(node, ast.Call):
                continue
            dotted = self._dotted(node.func) or ""
            if (
                self._fetches(node)
                or dotted in self.FILE_READS
                or dotted.endswith((".read_text", ".read_bytes"))
            ):
                return True
            if (
                isinstance(node.func, ast.Name)
                and node.args
                and all(
                    isinstance(a, ast.Constant)
                    for a in [*node.args, *(k.value for k in node.keywords)]
                )
            ):
                return True
        return False

    #: Builtins that reshape the data they are handed.
    _RESHAPE: ClassVar[frozenset[str]] = frozenset(
        {"len", "str", "bytes", "bytearray", "list", "range", "int", "ord", "chr"}
    )

    def _works_on(self, value: ast.AST, data: set[str]) -> bool:
        """Whether every call in a value works on the data itself (its own methods, a decoder, a
        reshaping builtin), so the result is still that data. Handing it to another object's
        method (`client.get_secret_value(SecretId=name)`) gets back something else."""
        for node in PythonSyntax.nodes(value):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in self._RESHAPE:
                continue
            dotted = self._dotted(func) or ""
            if dotted.rsplit(".", 1)[-1] in self.DECODERS:
                continue
            receiver = func.value if isinstance(func, ast.Attribute) else None
            while isinstance(receiver, ast.Attribute | ast.Subscript | ast.Call):
                receiver = receiver.func if isinstance(receiver, ast.Call) else receiver.value
            if isinstance(receiver, ast.Name) and receiver.id in data:
                continue
            return False
        return True

    def _fetches(self, value: ast.AST) -> bool:
        return any(
            isinstance(n, ast.Call)
            and (resolved := self._resolve_callee(n)) is not None
            and PRIMITIVES.get(resolved[0]) is Capability.EGRESS
            for n in PythonSyntax.nodes(value)
        )

    def _scope_dormant(
        self,
        statements: list[ast.Assign],
        reads: list[ast.Name],
        given: set[str],
        *,
        fetched_only: bool,
    ) -> None:
        """At module level a name can be imported by another file this one cannot see, so a
        constant decoded there may well be used: only data the module fetches counts."""
        decoded: dict[str, tuple[ast.Assign, str]] = {}
        derived: set[str] = set()
        handed = set(given)
        fetched: set[str] = set()
        carried: set[str] = set()
        for statement in statements:
            names = {n.id for n in PythonSyntax.nodes(statement.value) if isinstance(n, ast.Name)}
            target_name = statement.targets[0].id  # type: ignore[attr-defined]
            if self._fetches(statement.value) or names & fetched:
                fetched.add(target_name)
            if self._package_data(statement.value) or (
                names & carried and self._works_on(statement.value, carried | fetched)
            ):
                carried.add(target_name)
            if not names & (fetched if fetched_only else carried):
                continue
            target = statement.targets[0].id  # type: ignore[attr-defined]
            if any(
                isinstance(n, ast.Name) and n.id in handed
                for n in PythonSyntax.nodes(statement.value)
            ):
                # A value the caller handed in, decoded and dropped, is sloppy code; a payload is
                # fetched, shipped in a file or written in the source (cordon-a9, 2026-11-11).
                handed.add(target)
                continue
            decoder = self._decoder(statement.value, set(decoded) | derived)
            if decoder is not None:
                decoded.setdefault(target, (statement, decoder))
            elif any(
                isinstance(n, ast.Name) and n.id in decoded.keys() | derived
                for n in PythonSyntax.nodes(statement.value)
            ):
                derived.add(target)
        if not decoded:
            return
        carried = set(decoded) | derived
        inside = {
            id(n)
            for statement in statements
            if statement.targets[0].id in carried  # type: ignore[attr-defined]
            for n in PythonSyntax.nodes(statement.value)
        }
        if any(read.id in carried and id(read) not in inside for read in reads):
            return
        for name, (statement, decoder) in decoded.items():
            if name != "_" and not name.startswith("_unused"):
                self._record(Capability.DECODE, statement, f"decoded and left unused: {decoder}")
                return


__all__ = ["DormantDecodes"]
