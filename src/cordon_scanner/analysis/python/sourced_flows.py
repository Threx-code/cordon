"""Where the code a Python file runs comes from: what reached `exec`, `eval`, `compile` or a
deserializer, and what a process started with a program on its command line was handed.

A name is bound from a value by an assignment, by `with ... as`, by a `for` target or by `:=`.
Following only assignments missed `with urlopen(url) as resp: exec(resp.read(), ns)`, the commonest
way a fetched module is run (chimera-sandbox-extensions), so every binding form is followed here,
for the network flow (`_received_and_run`) and for the sinks below alike.

`sourced_sinks` answers the question `SUSPECT.DROPPER.001` asks of a sink: is what it runs what
arrived over the network, or what was decoded? A sink handed a local file's text (`exec` of the
package's own `version.py`), an environment value, or a parsed config is not running anything that
was fetched, and the dropper's pairing of it with a request elsewhere in the file was proximity,
not flow. Fail-closed: a sink whose argument the analysis cannot follow counts as sourced.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES, PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.vocabulary import (
    FETCH_TOOL,
    INTERPRETER_NAMES,
    SHELL_NAMES,
)
from cordon_scanner.foundation.capabilities import Capability


class BindingForms:
    """Each way Python binds a name to a value, read by the node's type."""

    @staticmethod
    def assign(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.Assign):
            return
        yield [t.id for t in node.targets if isinstance(t, ast.Name)], node.value

    @staticmethod
    def annotated(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.AnnAssign | ast.AugAssign):
            return
        if node.value is not None and isinstance(node.target, ast.Name):
            yield [node.target.id], node.value

    @staticmethod
    def walrus(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.NamedExpr):
            return
        yield [node.target.id], node.value

    @staticmethod
    def with_items(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.With | ast.AsyncWith):
            return
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                yield [item.optional_vars.id], item.context_expr

    @staticmethod
    def for_target(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.For | ast.AsyncFor):
            return
        if isinstance(node.target, ast.Name):
            yield [node.target.id], node.iter

    READERS: ClassVar[dict[type, Callable[[ast.AST], Iterator[tuple[list[str], ast.AST]]]]] = {}


BindingForms.READERS.update(
    {
        ast.Assign: BindingForms.assign,
        ast.AnnAssign: BindingForms.annotated,
        ast.AugAssign: BindingForms.annotated,
        ast.NamedExpr: BindingForms.walrus,
        ast.With: BindingForms.with_items,
        ast.AsyncWith: BindingForms.with_items,
        ast.For: BindingForms.for_target,
        ast.AsyncFor: BindingForms.for_target,
    }
)


class SourcedFlows(AnalyzerCore):
    """The Python analyser's view of where executed code and commands come from."""

    #: Flags after which a shell or an interpreter takes a program, in an argument list.
    PROGRAM_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {"-c", "-e", "--eval", "-p", "--print", "-command", "/c", "-r"}
    )
    #: A command line that downloads and pipes the download straight into something that runs it:
    #: `curl ... | sh`, `irm ... | iex`. Bounded at every repeat.
    FETCH_RUN_TEXT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,500}"
        r"\|[ \t]{0,8}(?:iex|invoke-expression|bash|sh|zsh|dash|python3?|node|perl|ruby)\b"
    )
    SINKS: ClassVar[frozenset[Capability]] = frozenset({Capability.EXECUTE, Capability.DESERIALIZE})
    ROUNDS: ClassVar[int] = 4

    @staticmethod
    def _binding_forms(tree: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        """(names bound, the value they are bound from), for every binding form."""
        for node in PythonSyntax.nodes(tree):
            read = BindingForms.READERS.get(type(node))
            if read is not None:
                yield from read(node)

    def _fetching_process(self, node: ast.AST) -> bool:
        """A process started to download: `subprocess.run(["curl", url], capture_output=True)`."""
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN or not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple) and first.elts:
            word = PythonFacts.constant(first.elts[0])
        else:
            word = PythonFacts.constant(first)
        return isinstance(word, str) and FETCH_TOOL.search(word) is not None

    def _arrived(self, node: ast.AST) -> bool:
        """A call whose value is what the network sent."""
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        if resolved is not None and PRIMITIVES.get(resolved[0]) is Capability.EGRESS:
            return True
        if self._fetching_process(node):
            return True
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("recv", "recvfrom")
            and bool(node.args)
        )

    def _decoded(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        return resolved is not None and PRIMITIVES.get(resolved[0]) in (
            Capability.DECODE,
            Capability.DECOMPRESS,
        )

    def _touches(self, expr: ast.AST, names: set[str], *, decoded: bool) -> bool:
        for part in PythonSyntax.within(expr, ast.Name, ast.Call):
            if isinstance(part, ast.Name) and part.id in names:
                return True
            if self._arrived(part) or (decoded and self._decoded(part)):
                return True
        return False

    def _bound_from(self, tree: ast.AST, *, decoded: bool) -> set[str]:
        """Names whose value came from the network (and, with `decoded`, from a decode)."""
        names: set[str] = set()
        bindings = list(self._binding_forms(tree))
        for _ in range(self.ROUNDS):
            before = len(names)
            for targets, value in bindings:
                if self._touches(value, names, decoded=decoded):
                    names.update(targets)
            if len(names) == before:
                break
        return names

    def sourced_sinks(self, tree: ast.AST) -> tuple[frozenset[int], frozenset[int]]:
        """(lines of every execute or deserialize call, lines of those whose input was fetched or
        decoded). A sink with no positional argument, or one the analysis cannot read, is sourced."""
        names = self._bound_from(tree, decoded=True)
        parents = PythonSyntax.parents(tree)
        every: set[int] = set()
        sourced: set[int] = set()
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) not in self.SINKS:
                continue
            every.add(node.lineno)
            if (
                not node.args
                or self._touches(node.args[0], names, decoded=True)
                or not self._followable(node.args[0])
                or self._uses_a_parameter(node.args[0], node, parents)
            ):
                sourced.add(node.lineno)
        return frozenset(every), frozenset(sourced)

    @staticmethod
    def _uses_a_parameter(expr: ast.AST, call: ast.AST, parents: dict[int, ast.AST]) -> bool:
        """Whether the argument reads a parameter of a function the call is in: a caller anywhere
        could hand it what was fetched, which this file-local view cannot rule out."""
        params: set[str] = set()
        node = parents.get(id(call))
        while node is not None:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                args = node.args
                params |= {x.arg for x in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
                params |= {x.arg for x in (args.vararg, args.kwarg) if x is not None}
            node = parents.get(id(node))
        return any(isinstance(n, ast.Name) and n.id in params for n in ast.walk(expr))

    @staticmethod
    def _followable(expr: ast.AST) -> bool:
        """Whether the argument is built from things this analysis reads: names, attributes,
        literals and calls. A starred or lambda-built argument is not, and so stays sourced."""
        return not any(
            isinstance(part, ast.Starred | ast.Lambda | ast.GeneratorExp) for part in ast.walk(expr)
        )

    def _received_into_process(self, tree: ast.AST) -> None:
        """A process handed a program that arrived over the network, in an argument list: a shell
        given `curl ... | sh` as its command, or an interpreter given a fetched value after `-e`/`-c`
        (`subprocess.run(["node", "-e", r.stdout])` where `r` was a `curl` run)."""
        network = self._bound_from(tree, decoded=False)
        # The flows before this one may have found the same run already (`_evaluates_output`).
        known = {h.line for h in self._hits if h.capability is Capability.FETCH_EXEC}
        for node in PythonSyntax.of(tree, ast.Call):
            if node.lineno in known:
                continue
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            argv = node.args[0] if node.args else None
            if not isinstance(argv, ast.List | ast.Tuple) or not argv.elts:
                continue
            program = PythonFacts.constant(argv.elts[0])
            name = program.rsplit("/", 1)[-1].lower() if isinstance(program, str) else ""
            if (
                name not in SHELL_NAMES
                and name not in INTERPRETER_NAMES
                and name not in {"node", "nodejs"}
            ):
                continue
            for flag, value in zip(argv.elts, argv.elts[1:], strict=False):
                if str(PythonFacts.constant(flag) or "").lower() not in self.PROGRAM_FLAGS:
                    continue
                text = PythonFacts.constant(value)
                if isinstance(text, str) and self.FETCH_RUN_TEXT.search(text):
                    self._record(
                        Capability.FETCH_EXEC,
                        node,
                        f"{name} runs a command that downloads and runs",
                    )
                    break
                if self._touches(value, network, decoded=False):
                    self._record(
                        Capability.FETCH_EXEC,
                        node,
                        f"{name} runs a program received over the network",
                    )
                    break


__all__ = ["BindingForms", "SourcedFlows"]
