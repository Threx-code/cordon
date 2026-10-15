"""What an MCP server's own Python code does with the agent's input: the steps an attack in a tool
handler has to take, read from the syntax tree.

A tool's description can be clean while its handler is not: a parameter the agent fills in is run
as a shell command behind a prefix only the attacker knows, the environment's secrets are gathered
by name, a socket is opened beside the MCP transport for commands from elsewhere. Each is a step an
attack must take whatever it calls itself; none is what a tool that does not say so needs.

```
  tool function (decorated, or public)  ── parameter ──► assignments ──► shell / eval / exec
        │                                     │                ▲
        │                                     └── a helper ────┘ (one hop)
        └── name and docstring: does the tool SAY it runs commands?  yes -> its job, not reported
  os.environ filtered by a secret-like name, values kept           -> secrets gathered
  socket bind + listen + accept, and a shell in the same file      -> a listener taking commands
```

Read from text with `ast`; nothing is imported or run.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

_TOOL_DECORATOR: Final = re.compile(r"\btool\b|\.tool\(|tool\s*$")
_RUNS_COMMANDS: Final = re.compile(
    r"(?i)exec|run|shell|command|terminal|bash|\bcmd\b|script|process|subprocess|kubectl|"
    r"powershell|eval|console|ssh"
)
_SECRET_WORDS: Final = re.compile(r"(?i)secret|token|passw|credential|api_?key|\bkey\b|auth")
_IGNORED_PARAMS: Final = frozenset({"self", "cls", "ctx", "context"})


class McpCode:
    SHELL_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "system",
            "popen",
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "getoutput",
            "getstatusoutput",
            "spawn",
            "spawnl",
            "execv",
            "execl",
        }
    )
    SHELL_MODULES: ClassVar[frozenset[str]] = frozenset({"os", "subprocess", "commands", "pty"})
    EVALS: ClassVar[frozenset[str]] = frozenset({"eval", "exec", "compile"})
    STRING_SHELLS: ClassVar[frozenset[str]] = frozenset(
        {"system", "popen", "getoutput", "getstatusoutput"}
    )

    @staticmethod
    def _parse(text: str) -> ast.Module | None:
        try:
            return ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return None

    @staticmethod
    def _names(node: ast.AST) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    @classmethod
    def _sink_args(cls, call: ast.Call) -> list[ast.AST] | None:
        """The arguments of a call that runs its input, or None when it is no such call."""
        func = call.func
        if isinstance(func, ast.Name) and func.id in cls.EVALS:
            return list(call.args[:1])
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in cls.SHELL_MODULES
            and func.attr in cls.SHELL_CALLS
        ):
            # A whole command string, read by a shell: `os.system(x)`, `os.popen(x)`, or a
            # subprocess call with shell=True. An argument list (`["git", "clone", url]`) runs
            # one fixed program and is not a command the input can choose.
            string_shell = func.attr in cls.STRING_SHELLS or any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in call.keywords
            )
            if not string_shell:
                return None
            return list(call.args[:1]) + [
                k.value for k in call.keywords if k.arg in ("args", "cmd")
            ]
        return None

    @classmethod
    def _tainted(cls, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        """Parameters, and every name assigned from one, in statement order (two passes)."""
        arguments = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        tainted = {a.arg for a in arguments} - _IGNORED_PARAMS
        for _ in range(2):
            for node in ast.walk(function):
                if (
                    isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign)
                    and node.value is not None
                ):
                    if cls._names(node.value) & tainted:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            tainted |= cls._names(target)
                elif isinstance(node, ast.For) and cls._names(node.iter) & tainted:
                    tainted |= cls._names(node.target)
        return tainted

    @classmethod
    def _runs_input(cls, function, wrappers: set[str]) -> ast.AST | None:
        """The first call in `function` that runs something derived from its parameters."""
        tainted = cls._tainted(function)
        if not tainted:
            return None
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            args = cls._sink_args(node)
            if args is None and isinstance(node.func, ast.Name) and node.func.id in wrappers:
                args = list(node.args) + [k.value for k in node.keywords]
            if args and any(cls._names(a) & tainted for a in args):
                return node
        return None

    @staticmethod
    def _is_tool(function) -> bool:
        return any(_TOOL_DECORATOR.search(ast.unparse(d)) for d in function.decorator_list)

    @classmethod
    def shell_from_input(cls, text: str) -> list[tuple[int, str]]:
        """(line, tool name) where a tool runs its own input and does not say it runs commands."""
        tree = cls._parse(text)
        if tree is None:
            return []
        functions = [
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        wrappers: set[str] = set()
        for _ in range(2):
            for function in functions:
                if function.name not in wrappers and cls._runs_input(function, wrappers):
                    wrappers.add(function.name)
        tools = [f for f in functions if cls._is_tool(f)]
        hits: list[tuple[int, str]] = []
        for function in tools:
            said = function.name + " " + (ast.get_docstring(function) or "")[:600]
            if _RUNS_COMMANDS.search(said):
                continue
            call = cls._runs_input(function, wrappers)
            if call is not None:
                hits.append((getattr(call, "lineno", function.lineno), function.name))
        return hits

    @classmethod
    def secret_harvest(cls, text: str) -> list[int]:
        """Lines that gather environment variables by a secret-like name and keep the values."""
        if "environ" not in text:
            return []
        tree = cls._parse(text)
        if tree is None:
            return []
        lines: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.DictComp | ast.ListComp | ast.SetComp | ast.GeneratorExp):
                source = " ".join(ast.unparse(g.iter) for g in node.generators)
                conditions = " ".join(ast.unparse(c) for g in node.generators for c in g.ifs)
                kept = ast.unparse(node.value if isinstance(node, ast.DictComp) else node.elt)
                if (
                    "environ" in source
                    and _SECRET_WORDS.search(conditions)
                    # A value kept, not replaced: redaction writes a constant in its place.
                    and not re.fullmatch(r"\s*['\"][^'\"]*['\"]\s*", kept)
                ):
                    lines.append(node.lineno)
        return lines

    @staticmethod
    def listener(text: str) -> int | None:
        """The line of a raw socket that listens and accepts, in a file that also runs commands."""
        if ".accept(" not in text or ".listen(" not in text:
            return None
        if not re.search(r"\bsubprocess\.|\bos\.(?:system|popen)\(|\bexec\(", text):
            return None
        match = re.search(r"\.bind\(\s*\(", text)
        return text.count("\n", 0, match.start()) + 1 if match else None
