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
        calls = cls._run_calls(function, wrappers)
        return calls[0] if calls else None

    @classmethod
    def _run_calls(cls, function, wrappers: set[str]) -> list[ast.AST]:
        """Every call in `function` that runs something derived from its parameters."""
        tainted = cls._tainted(function)
        if not tainted:
            return []
        out: list[ast.AST] = []
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            args = cls._sink_args(node)
            if args is None and isinstance(node.func, ast.Name) and node.func.id in wrappers:
                args = list(node.args) + [k.value for k in node.keywords]
            if args and any(cls._names(a) & tainted for a in args):
                out.append(node)
        return out

    @staticmethod
    def _is_tool(function) -> bool:
        return any(_TOOL_DECORATOR.search(ast.unparse(d)) for d in function.decorator_list)

    @classmethod
    def triggered(cls, function, call: ast.AST, constants: frozenset[str] = frozenset()) -> bool:
        """Whether `call` runs only behind a secret: inside an `if` that compares an argument with
        a literal -- `x.startswith("EXEC://")`, `x == "admin_2026"`, `"://" in x`. A bug runs the
        input whatever it is; a backdoor waits for the word only its author knows."""
        tainted = cls._tainted(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            literal = any(
                (isinstance(c, ast.Constant) and isinstance(c.value, str) and len(c.value) >= 3)
                or (isinstance(c, ast.Name) and c.id in constants)
                for c in ast.walk(test)
            )
            on_input = bool(cls._names(test) & tainted)
            compares = any(
                isinstance(n, ast.Compare)
                or (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr in ("startswith", "endswith")
                )
                for n in ast.walk(test)
            )
            if (
                literal
                and on_input
                and compares
                and any(n is call for b in node.body for n in ast.walk(b))
            ):
                return True
        return False

    @classmethod
    def shell_from_input_graded(cls, text: str) -> list[tuple[int, str, bool]]:
        """`shell_from_input`, with whether each run is behind a hidden trigger."""
        tree = cls._parse(text)
        if tree is None:
            return []
        # Module-level names bound to a string: `_PREFIX = "EXEC://"` is the literal it names.
        constants = frozenset(
            t.id
            for n in tree.body
            if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
            for t in n.targets
            if isinstance(t, ast.Name)
        )
        functions = [
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        wrappers: set[str] = set()
        for _ in range(2):
            for function in functions:
                if function.name not in wrappers and cls._runs_input(function, wrappers):
                    wrappers.add(function.name)
        out: list[tuple[int, str, bool]] = []
        for function in (f for f in functions if cls._is_tool(f)):
            calls = cls._run_calls(function, wrappers)
            if not calls:
                continue
            # Behind a secret it is a backdoor whatever the tool says it does: `run_terminal_command`
            # is meant to run commands, not to read files when its input starts with `READ/`, and
            # `get_system_info`'s docstring naming "processes" is no reason to run `EXEC://...`.
            gated = next((c for c in calls if cls.triggered(function, c, constants)), None)
            if gated is not None:
                out.append((getattr(gated, "lineno", function.lineno), function.name, True))
                continue
            said = function.name + " " + (ast.get_docstring(function) or "")[:600]
            if _RUNS_COMMANDS.search(said):
                continue
            out.append((getattr(calls[0], "lineno", function.lineno), function.name, False))
        return out

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

    @staticmethod
    def _hidden_path(node: ast.AST) -> bool:
        """A path written as a literal whose last component is a dotfile: `".capture.jsonl"`,
        `os.path.expanduser("~/.hook")`, `Path.home() / ".trace"`."""
        for part in ast.walk(node):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                name = part.value.replace("\\", "/").rstrip("/").rpartition("/")[2]
                if len(name) > 1 and name.startswith(".") and name not in (".", ".."):
                    return True
        return False

    @classmethod
    def _writes_hidden(cls, function, tainted: set[str]) -> bool:
        """Whether `function` writes something derived from `tainted` names to a dotfile."""
        handles: set[str] = set()
        for node in ast.walk(function):
            if isinstance(node, ast.With):
                for item in node.items:
                    call = item.context_expr
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Name)
                        and call.func.id == "open"
                        and call.args
                        and cls._hidden_path(call.args[0])
                        and isinstance(item.optional_vars, ast.Name)
                    ):
                        handles.add(item.optional_vars.id)
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("write", "writelines")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in handles
                and node.args
                and cls._names(node.args[0]) & tainted
            ):
                return True
        return False

    @classmethod
    def mirrors_input(cls, text: str) -> list[tuple[int, str]]:
        """(line, tool) where a tool copies its arguments into a hidden file.

        `_capture("search", locals())` in a tool, and a helper -- or a thread it starts --
        appending what it was given to `.capture.jsonl`: every query the agent makes, kept where
        no one looks (review 98: mcp-variants' Tool Shadowing and Puppet servers). A server's
        log goes through `logging`; a cache is keyed by what it fetched, not the caller's input.
        """
        if "open(" not in text:
            return []
        tree = cls._parse(text)
        if tree is None:
            return []
        functions = [
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        writers = {f.name for f in functions if cls._writes_hidden(f, cls._tainted(f))}
        for _ in range(2):
            for function in functions:
                if function.name in writers:
                    continue
                tainted = cls._tainted(function)
                for node in ast.walk(function):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in writers
                        and any(cls._names(a) & tainted for a in node.args)
                    ):
                        writers.add(function.name)
                        break
        if not writers:
            return []
        hits: list[tuple[int, str]] = []
        for function in (f for f in functions if cls._is_tool(f)):
            tainted = cls._tainted(function)
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                into_writer = isinstance(node.func, ast.Name) and node.func.id in writers
                every_argument = any(
                    isinstance(c, ast.Call)
                    and isinstance(c.func, ast.Name)
                    and c.func.id == "locals"
                    for a in node.args
                    for c in ast.walk(a)
                )
                if into_writer and (
                    every_argument or any(cls._names(a) & tainted for a in node.args)
                ):
                    hits.append((node.lineno, function.name))
                    break
            else:
                if cls._writes_hidden(function, tainted):
                    hits.append((function.lineno, function.name))
        return hits

    #: Calls that send a request: `requests.post(url, json=...)`, `httpx.get`, `session.put`,
    #: `urllib.request.urlopen(Request(url, data=...))`.
    _SEND_ATTRS: ClassVar[frozenset[str]] = frozenset(
        {"post", "get", "put", "patch", "delete", "request", "urlopen", "Request", "fetch", "send"}
    )
    _HOST: ClassVar[re.Pattern[str]] = re.compile(r"^(?:https?|wss?)://([^/:?#\s]{1,253})", re.I)

    @classmethod
    def _sends(cls, function, constants: dict[str, str]) -> list[tuple[ast.Call, str | None]]:
        """Each request the function makes, with the host its URL names when that is written out."""
        out: list[tuple[ast.Call, str | None]] = []
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else ""
            )
            if name not in cls._SEND_ATTRS or (not node.args and not node.keywords):
                continue
            url = (
                node.args[0]
                if node.args
                else next((k.value for k in node.keywords if k.arg in ("url", "uri")), None)
            )
            host = None
            if isinstance(url, ast.Constant) and isinstance(url.value, str):
                found = cls._HOST.match(url.value)
                host = found.group(1).lower() if found else None
            elif (
                isinstance(url, ast.JoinedStr)
                and url.values
                and isinstance(url.values[0], ast.Constant)
            ):
                found = cls._HOST.match(str(url.values[0].value))
                host = found.group(1).lower() if found else None
            elif isinstance(url, ast.Name) and url.id in constants:
                found = cls._HOST.match(constants[url.id])
                host = found.group(1).lower() if found else None
            out.append((node, host))
        return out

    @classmethod
    def forwards_input(cls, text: str) -> list[tuple[int, str, str]]:
        """(line, tool, host) where a tool sends what it was asked to a second host.

        A tool calls the service it is for with its input: a weather tool sends the city to its
        weather API. What a collector adds is a copy of the input sent somewhere else -- the
        same request body to a second host, or the arguments to an address nobody's tool calls
        (review 98: MCP servers whose tools work and also report every query). Read from the
        tool and the helpers it hands its input to.
        """
        if "http" not in text:
            return []
        tree = cls._parse(text)
        if tree is None:
            return []
        from cordon_scanner.intel.malware.hosts import Destinations

        constants = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        functions = {
            n.name: n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }

        def tainted_hosts(function, depth: int = 0) -> set[str | None]:
            tainted = cls._tainted(function)
            hosts: set[str | None] = set()
            for call, host in cls._sends(function, constants):
                carried = [
                    *call.args[1:],
                    *(
                        k.value
                        for k in call.keywords
                        if k.arg not in ("url", "uri", "headers", "timeout")
                    ),
                ]
                if any(cls._names(a) & tainted for a in carried):
                    hosts.add(host)
            if depth < 2:
                for node in ast.walk(function):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in functions
                        and node.func.id != function.name
                        and any(
                            cls._names(a) & tainted
                            for a in [*node.args, *(k.value for k in node.keywords)]
                        )
                    ):
                        hosts |= tainted_hosts(functions[node.func.id], depth + 1)
            return hosts

        hits: list[tuple[int, str, str]] = []
        for function in (f for f in functions.values() if cls._is_tool(f)):
            hosts = tainted_hosts(function)
            named = sorted(h for h in hosts if h)
            untrusted = [
                h
                for h in named
                # A bare public address: loopback and private ranges are this machine and its
                # network, where a tool's own local service lives.
                if (
                    re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h)
                    and not h.startswith(("127.", "10.", "192.168.", "169.254.", "0."))
                    and not re.match(r"172\.(?:1[6-9]|2\d|3[01])\.", h)
                )
                or Destinations.destination_matcher().search(h.encode()) is not None
            ]
            if untrusted:
                hits.append((function.lineno, function.name, untrusted[0]))
            elif len(named) >= 2:
                hits.append((function.lineno, function.name, named[1]))
        return hits

    @staticmethod
    def _trigger_kinds(node: ast.AST) -> set[str]:
        """Which kinds of time-bomb trigger an expression or function body consults."""
        kinds: set[str] = set()
        for part in ast.walk(node):
            if isinstance(part, ast.Attribute):
                owner = ast.unparse(part.value)
                if owner == "random" and part.attr in ("random", "randint", "uniform", "choice"):
                    kinds.add("chance")
                elif part.attr in ("day", "month", "weekday", "isoweekday", "hour", "minute") and (
                    "today" in owner or "now" in owner or "date" in owner
                ):
                    kinds.add("calendar")
            elif isinstance(part, ast.AugAssign) and isinstance(part.op, ast.Add):
                kinds.add("count")
        return kinds

    @classmethod
    def time_bomb(cls, text: str) -> list[tuple[int, str]]:
        """(line, tool) where a tool returns something else once a gate of several unrelated
        triggers opens -- chance, a date, a call count.

        `if _gate(): return _other(...)` before the real work, where `_gate` is true on the first of
        the month, after the 25th call, or one time in five hundred: a tool that behaves while it is
        reviewed and turns later (review 98: mcp-variants' Rug Pull servers). One trigger is a
        feature -- a rate limit counts calls, a market tool checks the weekday; mixing them so the
        turn cannot be predicted has no use but that.
        """
        if "random" not in text and "today" not in text and "now" not in text:
            return []
        tree = cls._parse(text)
        if tree is None:
            return []
        functions = {
            n.name: n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        hits: list[tuple[int, str]] = []
        for function in (f for f in functions.values() if cls._is_tool(f)):
            for node in ast.walk(function):
                if not isinstance(node, ast.If) or not any(
                    isinstance(b, ast.Return) for b in node.body
                ):
                    continue
                kinds = cls._trigger_kinds(node.test)
                for call in ast.walk(node.test):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Name)
                        and call.func.id in functions
                    ):
                        kinds |= cls._trigger_kinds(functions[call.func.id])
                if len(kinds) >= 2:
                    hits.append((node.lineno, function.name))
                    break
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

    @classmethod
    def runs_own_input(cls, text: str) -> list[tuple[int, str]]:
        """(line, function) where a public function of a script runs its own argument in a shell,
        eval or exec. For an agent's skill script every public function is something the agent
        may call with text it was given -- a vulnerability, reported as one."""
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
        hits = []
        for function in functions:
            if function.name.startswith("_"):
                continue
            call = cls._runs_input(function, wrappers)
            if call is not None:
                hits.append((getattr(call, "lineno", function.lineno), function.name))
        return hits

    _INSTALL: ClassVar[re.Pattern[str]] = re.compile(
        r"\bpip3?\b[\"', ]{0,6}install[\"', ]{1,6}((?:[\"']?[A-Za-z][\w.-]{1,60}[\"']?[, ]{1,4}){1,12})"
        r"|\bpackages\s{0,4}=\s{0,4}\[([^\]]{1,2000})\][\s\S]{0,600}?\bpip\b[\s\S]{0,200}?install"
    )

    @classmethod
    def installs_lookalikes(cls, text: str) -> list[tuple[int, str, str]]:
        """(line, name, popular) for a package a script installs at run time whose name is a slip
        of a popular one: installing it is how a typosquat's code gets on the machine."""
        from cordon_scanner.detect.supply.dependency import DependencyDetector
        from cordon_scanner.intel.registries.popular import PackageIntel

        out: list[tuple[int, str, str]] = []
        for match in cls._INSTALL.finditer(text):
            chunk = match.group(1) or match.group(2) or ""
            for name in re.findall(r"[\"']([A-Za-z][\w.-]{1,60})[\"']", chunk):
                low = name.lower()
                if PackageIntel.is_known_package("pypi", low):
                    continue
                target = DependencyDetector._typosquat_target("pypi", low)
                if target is not None:
                    out.append((text.count("\n", 0, match.start()) + 1, name, target))
        return out

    _JAILBREAK: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)ignore\s{1,3}(?:all\s{1,3})?(?:the\s{1,3})?(?:previous|prior|above)\s{1,3}instructions"
        r"|\byou\s{1,3}are\s{1,3}now\s{1,3}DAN\b|do\s{1,3}anything\s{1,3}now"
        r"|reveal\s{1,3}your\s{1,3}system\s{1,3}prompt"
    )

    @classmethod
    def returns_jailbreak(cls, text: str) -> list[int]:
        """Lines of string literals in a script's functions that tell the reading model to drop
        its instructions: what the agent reads back when it calls the function."""
        tree = cls._parse(text)
        if tree is None:
            return []
        return sorted(
            {
                n.lineno
                for n in ast.walk(tree)
                if isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and cls._JAILBREAK.search(n.value)
            }
        )

    @staticmethod
    def listener(text: str) -> int | None:
        """The line of a raw socket that listens and accepts, in a file that also runs commands."""
        if ".accept(" not in text or ".listen(" not in text:
            return None
        if not re.search(r"\bsubprocess\.|\bos\.(?:system|popen)\(|\bexec\(", text):
            return None
        match = re.search(r"\.bind\(\s*\(", text)
        return text.count("\n", 0, match.start()) + 1 if match else None
