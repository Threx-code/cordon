"""What runs in every Python process once a package is installed: a `.pth` file's import lines and the
files they reach (`ScanContext.startup_closure_paths`). Two facts beside the hits the file already has.

`AST.PY.STARTUP_NETWORK`: a request or a download in that closure. Something that reaches the network
each time any interpreter starts has an implant's shape, whatever it sends today
(data_proxy_for_test 0.1.1: `import mcp_proxy.caching`, which downloads at module level).

`AST.PY.STARTUP_CODE`: a `.pth` import line that calls anything outside import machinery. The machinery
is what the benign census of 17,337 packages' `.pth` lines does (2026-11-11, cordon-ef-results
/security/pth): imports, the distutils-precedence shim, `_virtualenv`, the namespace-package lines,
`sys.path` edits, `site.addsitedir`, importlib finders, and `exec` of a string literal (pytest-cov's
and coverage's shims, whose code the analyser reads as it reads any literal). chroma_client 0.5.7's
line resets the process umask in every interpreter.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.detect.code.capability.hits import CapabilityHit
    from cordon_scanner.foundation.content import FileContent


class StartupHooks:
    """The startup facts."""

    NETWORK_FACT: ClassVar[str] = "AST.PY.STARTUP_NETWORK"
    CODE_FACT: ClassVar[str] = "AST.PY.STARTUP_CODE"
    #: What reaching the network is, for a hit in the startup closure.
    NETWORK: ClassVar[frozenset[Capability]] = frozenset({Capability.EGRESS, Capability.FETCH_EXEC})
    #: Calls a `.pth` line makes to set up imports, by dotted name.
    MACHINERY: ClassVar[frozenset[str]] = frozenset(
        {
            "__import__",
            "os.environ.get",
            "os.path.exists",
            "os.path.join",
            "os.path.dirname",
            "os.path.abspath",
            "os.path.isdir",
            "sys._getframe",
            "sys.modules.setdefault",
            "sys.modules.get",
            "types.ModuleType",
            "setattr",
            "getattr",
            "hasattr",
            "len",
            "sys.path.insert",
            "sys.path.append",
            "sys.path.extend",
            "sys.path.remove",
            "sys.meta_path.insert",
            "sys.meta_path.append",
            "site.addsitedir",
            "importlib.import_module",
            "importlib.util.find_spec",
            "importlib.util.spec_from_file_location",
            "importlib.util.module_from_spec",
            "importlib.machinery.PathFinder.find_spec",
        }
    )
    #: Methods the machinery calls on what it just made: `__import__('_distutils_hack').add_shim()`,
    #: `m.__dict__.setdefault('__path__', [])`, `mp.append(p)` on that list.
    MACHINERY_METHODS: ClassVar[frozenset[str]] = frozenset({"add_shim", "setdefault", "append"})

    @classmethod
    def network(
        cls, hits: list[CapabilityHit], path: str, ctx: ScanContext | None
    ) -> list[CapabilityHit]:
        """A network hit on a line the startup runs, in a file a `.pth` hook reaches, as the startup
        network fact. A request in a function nothing on the startup path calls is not made at
        every start (`ScanContext.startup_reaches`: what importing the `.pth`'s modules runs): fattummy's inference adapters, imported by its `.pth`, call out only when asked."""
        import dataclasses

        if ctx is None or not ctx.in_startup_closure(path):
            return []
        return [
            dataclasses.replace(hit, rule_id=cls.NETWORK_FACT)
            for hit in hits
            if hit.capability in cls.NETWORK and ctx.startup_reaches(path, hit.line)
        ]

    @classmethod
    def hits(
        cls,
        hits: list[CapabilityHit],
        content: FileContent,
        ctx: ScanContext | None,
        span: Callable[[FileContent, int], tuple[int, int]],
    ) -> list[CapabilityHit]:
        """Both startup facts for one file: the network fact on its hits, and the code fact on a
        `.pth`'s lines. FLOW is a capability of its own, which no install composite pairs (PERSIST
        would also raise MALWARE.INSTALL.PERSIST.001 for the same line)."""
        from cordon_scanner.detect.code.capability.hits import CapabilityHit

        found = cls.network(hits, content.path, ctx)
        if content.path.endswith(".pth"):
            found += [
                CapabilityHit(
                    capability=Capability.FLOW,
                    rule_id=cls.CODE_FACT,
                    byte_start=span(content, line)[0],
                    byte_end=span(content, line)[1],
                    line=line,
                    resolved=True,
                )
                for line in cls.code_lines(content.text)
            ]
        return found

    @classmethod
    def code_lines(cls, text: str) -> list[int]:
        """Lines of a `.pth` whose import statement calls something outside import machinery."""
        lines: list[int] = []
        for number, line in enumerate(text.split("\n"), start=1):
            stripped = line.strip()
            if not stripped.startswith(("import ", "import\t")):
                continue
            try:
                tree = PythonSyntax.parse(stripped)
            except (SyntaxError, ValueError, RecursionError):
                # S2: a `.pth` import line that does not parse fails at interpreter start (site
                # reports it and skips the file); it runs nothing to judge.
                continue
            if any(
                not cls._machinery(call) for call in ast.walk(tree) if isinstance(call, ast.Call)
            ):
                lines.append(number)
        return lines

    @classmethod
    def _machinery(cls, call: ast.Call) -> bool:
        func = call.func
        dotted = cls._dotted(func)
        if dotted in cls.MACHINERY:
            return True
        if dotted in ("exec", "eval"):
            # A literal's code is read where it is (`PythonAnalyzer`'s literal reading); a value
            # computed at startup is not import machinery.
            return bool(call.args) and isinstance(call.args[0], ast.Constant)
        return (
            isinstance(func, ast.Attribute)
            and func.attr in cls.MACHINERY_METHODS
            and (
                isinstance(func.value, ast.Name | ast.Call | ast.Attribute)
                and not cls._dotted(func.value).startswith(
                    ("os.", "subprocess", "socket", "shutil")
                )
            )
        )

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        elif isinstance(node, ast.Call):
            parts.append(StartupHooks._dotted(node.func) + "()")
        return ".".join(reversed(parts))


__all__ = ["StartupHooks"]
