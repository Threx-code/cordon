"""What a JavaScript or TypeScript MCP server's own code does with the agent's input: `McpCode`'s
shell from input, for the servers most MCP servers are (reviews/mcp-98/01: TS/JS 4 caught of 18).

```
  tool handler  server.tool(name, description, ..., fn) · registerTool(name, {description}, fn)
                setRequestHandler(CallToolRequestSchema, fn)
        │
        └── parameter ──► declarations, assignments ──► a shell from child_process
                              │                 ▲       (exec · execSync · spawn/execFile with shell: true
                              └── a function ───┘        · spawn("sh", ["-c", x]) · eval · new Function · vm.run*)
  behind an `if` comparing an argument with a literal or a module constant  -> a backdoor (gated)
  otherwise, a tool that does not say it runs commands                       -> an injection bug
```

Choosing a tool by its name (`request.params.name === "build"`) is dispatch, not a secret, and a shell
is what `child_process` gives the file -- `RegExp.prototype.exec` is not one. Read with Cordon's own
front end (`analysis/javascript/front`); nothing is imported or run.
"""

from __future__ import annotations

from typing import Any, Final

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax
from cordon_scanner.detect.agents.mcp_servers.handlers import _RUNS_COMMANDS

MAX_CHARS: Final = 2_000_000
_FUNCTIONS: Final = frozenset(
    {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}
)
_STRING_SHELLS: Final = frozenset({"exec", "execSync"})
_ARGUMENT_SHELLS: Final = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})
_SHELL_PROGRAMS: Final = frozenset(
    {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
)
_VM_RUNS: Final = frozenset(
    {"runInNewContext", "runInThisContext", "runInContext", "compileFunction"}
)
_REGISTER: Final = frozenset({"tool", "registerTool", "addTool"})
_COMPARES: Final = frozenset(
    {"startsWith", "endsWith", "includes", "has", "test", "match", "indexOf"}
)
#: What names the tool rather than its input.
_TOOL_NAMES: Final = frozenset({"name", "toolName", "tool_name", "tool"})
_ASSIGNS: Final = frozenset({"AssignmentExpression", "ForOfStatement", "ForInStatement"})
_IGNORED_PARAMS: Final = frozenset({"this", "extra", "context", "ctx", "signal"})


class McpJsCode:
    """`shell_from_input_graded(text)`: (offset, gated) for each tool handler that runs its own input."""

    def __init__(self, program: Node) -> None:
        self.program = program
        self.shells, self.spaces = self._shell_bindings()
        self.constants: set[str] = set()
        self.functions: dict[str, Node] = {}
        self._index()
        self.wrappers: set[str] = set()
        for _ in range(3):
            for name, function in self.functions.items():
                if name not in self.wrappers and self._run_calls(function):
                    self.wrappers.add(name)

    @classmethod
    def shell_from_input_graded(cls, text: str, typescript: bool = True) -> list[tuple[int, bool]]:
        """(character offset, behind a secret) for each tool handler that runs its own input."""
        if len(text) > MAX_CHARS:
            return []
        try:
            program = Parser(text, typescript=typescript).program()
        except Exception:  # noqa: BLE001 -- an unread file is read by the other rules, not here
            return []
        code = cls(program)
        out: list[tuple[int, bool]] = []
        for function, said in code._handlers(text):
            calls = code._run_calls(function)
            gated = next((c for c in calls if code._gated(function, c)), None)
            if gated is not None:
                out.append((gated.start, True))
            elif calls and said and not _RUNS_COMMANDS.search(said):
                out.append((calls[0].start, False))
        return out

    # -- reading the tree ------------------------------------------------------------------------

    @staticmethod
    def _ids(node: Node | None) -> set[str]:
        if node is None:
            return set()
        return {n["name"] for n in Syntax.walk(node) if n.type == "Identifier" and n["name"]}

    @staticmethod
    def _callee(call: Node) -> str | None:
        callee = call["callee"]
        if callee is None:
            return None
        if callee.type == "Identifier":
            return str(callee["name"])
        if callee.type == "MemberExpression":
            prop = callee["property"]
            if prop is not None and prop.type in ("Identifier", "PrivateIdentifier"):
                return str(prop["name"])
        return None

    @staticmethod
    def _literal(node: Node | None) -> Any:
        if node is None:
            return None
        if node.type == "Literal":
            return node["value"]
        if node.type == "TemplateLiteral" and not node["expressions"]:
            return "".join(q["cooked"] or "" for q in node["quasis"] or [])
        return None

    @classmethod
    def _is_child_process(cls, node: Node | None) -> bool:
        value = cls._literal(node)
        return isinstance(value, str) and value.removeprefix("node:") == "child_process"

    # -- what the file binds ---------------------------------------------------------------------

    def _shell_bindings(self) -> tuple[set[str], set[str]]:
        """(functions bound from child_process, names bound to the module itself)."""
        shells: set[str] = set()
        spaces: set[str] = set()
        for node in Syntax.walk(self.program):
            if node.type == "ImportDeclaration" and self._is_child_process(node["source"]):
                for spec in node["specifiers"] or []:
                    local, imported = spec["local"], spec["imported"]
                    if local is None:
                        continue
                    if spec.type != "ImportSpecifier":
                        spaces.add(local["name"])
                    elif (
                        imported is not None
                        and imported["name"] in _STRING_SHELLS | _ARGUMENT_SHELLS
                    ):
                        shells.add(local["name"])
            elif node.type == "VariableDeclarator" and self._requires_child_process(node["init"]):
                target = node["id"]
                if target is not None and target.type == "Identifier":
                    spaces.add(target["name"])
                elif target is not None and target.type == "ObjectPattern":
                    for prop in target["properties"] or []:
                        if prop.type == "Property" and self._ids(prop["key"]) & (
                            _STRING_SHELLS | _ARGUMENT_SHELLS
                        ):
                            shells |= self._ids(prop["value"])
        self._promisified(shells, spaces)
        return shells, spaces

    def _requires_child_process(self, init: Node | None) -> bool:
        return (
            init is not None
            and init.type == "CallExpression"
            and self._callee(init) == "require"
            and bool(init["arguments"])
            and self._is_child_process(init["arguments"][0])
        )

    def _promisified(self, shells: set[str], spaces: set[str]) -> None:
        """`const run = promisify(exec)` is a shell too."""
        for node in Syntax.walk(self.program):
            if (
                node.type != "VariableDeclarator"
                or node["id"] is None
                or node["id"].type != "Identifier"
            ):
                continue
            init = node["init"]
            if init is None or init.type != "CallExpression" or self._callee(init) != "promisify":
                continue
            wrapped = (init["arguments"] or [None])[0]
            if wrapped is None:
                continue
            if (wrapped.type == "Identifier" and wrapped["name"] in shells) or (
                wrapped.type == "MemberExpression" and self._ids(wrapped["object"]) & spaces
            ):
                shells.add(node["id"]["name"])

    def _index(self) -> None:
        """Functions by name, and the names bound to a string (or a list or set of strings)."""
        for node in Syntax.walk(self.program):
            if node.type == "FunctionDeclaration" and node["id"] is not None:
                self.functions[node["id"]["name"]] = node
            elif (
                node.type == "MethodDefinition"
                and node["key"] is not None
                and node["value"] is not None
            ):
                if node["key"].type == "Identifier":
                    self.functions[node["key"]["name"]] = node["value"]
            elif (
                node.type == "VariableDeclarator"
                and node["id"] is not None
                and node["id"].type == "Identifier"
            ):
                init = node["init"]
                if init is None:
                    continue
                if init.type in _FUNCTIONS:
                    self.functions[node["id"]["name"]] = init
                elif isinstance(self._literal(init), str) or (
                    init.type in ("ArrayExpression", "NewExpression")
                    and any(isinstance(self._literal(n), str) for n in Syntax.walk(init))
                ):
                    self.constants.add(node["id"]["name"])

    # -- what a handler runs ---------------------------------------------------------------------

    def _shell_kind(self, call: Node) -> str | None:
        """The child_process function a call is, by what the file bound, or None."""
        callee = call["callee"]
        if callee is None:
            return None
        if callee.type == "Identifier" and callee["name"] in self.shells:
            return str(callee["name"]) if callee["name"] in _ARGUMENT_SHELLS else "exec"
        if callee.type == "MemberExpression":
            owner, name = callee["object"], self._callee(call)
            if (
                owner is not None
                and name in _STRING_SHELLS | _ARGUMENT_SHELLS
                and (
                    (owner.type == "Identifier" and owner["name"] in self.spaces)
                    or self._requires_child_process(owner)
                )
            ):
                return name
        return None

    def _sink_args(self, call: Node) -> list[Node] | None:
        """The arguments of a call that runs a command string or code, or None for any other call."""
        args = list(call["arguments"] or [])
        name = self._callee(call)
        if call.type == "NewExpression":
            return args if name == "Function" else None
        callee = call["callee"]
        if (
            name == "eval" and callee is not None and callee.type == "Identifier"
        ) or name in _VM_RUNS:
            return args[:1]
        kind = self._shell_kind(call)
        if kind is None:
            return None
        if kind not in _ARGUMENT_SHELLS:
            return args[:1]
        if any(self._shell_option(a) for a in args):
            return args[:1]
        program = self._literal(args[0]) if args else None
        if isinstance(program, str) and program.rsplit("/", 1)[-1].lower() in _SHELL_PROGRAMS:
            return args[1:2]
        return None

    def _shell_option(self, node: Node) -> bool:
        """`{ shell: true }` (or a shell path) among a spawn's options."""
        if node.type != "ObjectExpression":
            return False
        return any(
            prop.type == "Property"
            and "shell" in self._ids(prop["key"])
            and self._literal(prop["value"]) not in (False, None, "")
            for prop in node["properties"] or []
        )

    def _tainted(self, function: Node) -> set[str]:
        """The parameters, and every name declared or assigned from one (three passes)."""
        tainted: set[str] = set()
        for param in function["params"] or []:
            tainted |= self._ids(param)
        tainted -= _IGNORED_PARAMS
        body = function["body"]
        if body is None:
            return tainted
        for _ in range(3):
            for node in Syntax.walk(body):
                if node.type == "VariableDeclarator" and self._ids(node["init"]) & tainted:
                    tainted |= self._ids(node["id"])
                elif node.type in _ASSIGNS and self._ids(node["right"]) & tainted:
                    # `x = input`, `for (const x of input)`, `for (const k in input)`
                    tainted |= self._ids(node["left"])
        return tainted

    def _run_calls(self, function: Node) -> list[Node]:
        """Every call in `function` that runs something derived from its parameters."""
        tainted = self._tainted(function)
        if not tainted or function["body"] is None:
            return []
        out = []
        for node in Syntax.walk(function["body"]):
            if node.type not in ("CallExpression", "NewExpression"):
                continue
            args = self._sink_args(node)
            if args is None and self._callee(node) in self.wrappers:
                args = list(node["arguments"] or [])
            if args and any(self._ids(a) & tainted for a in args):
                out.append(node)
        return out

    # -- the secret and the tool -----------------------------------------------------------------

    def _input_ids(self, test: Node) -> set[str]:
        """The names a test reads, leaving out those it only uses to reach the tool's name."""
        skip: set[int] = set()
        for node in Syntax.walk(test):
            prop = node["property"] if node.type == "MemberExpression" else None
            if prop is not None and prop.type == "Identifier" and prop["name"] in _TOOL_NAMES:
                skip |= {id(n) for n in Syntax.walk(node)}
        return {
            n["name"]
            for n in Syntax.walk(test)
            if n.type == "Identifier" and id(n) not in skip and n["name"]
        }

    def _gated(self, function: Node, call: Node) -> bool:
        """Whether `call` runs only behind a secret: inside an `if` (or `?:`) comparing an argument
        with a literal or a module constant -- `x.startsWith("EXEC://")`, `key === MASTER`."""
        tainted = self._tainted(function) - _TOOL_NAMES
        for node in Syntax.walk(function["body"]):
            if node.type not in ("IfStatement", "ConditionalExpression") or node["test"] is None:
                continue
            test = list(Syntax.walk(node["test"]))
            literal = any(
                (isinstance(self._literal(n), str) and len(self._literal(n)) >= 3)
                or (n.type == "Identifier" and n["name"] in self.constants)
                for n in test
            )
            compares = any(
                (n.type == "BinaryExpression" and n["operator"] in ("===", "==", "!==", "!="))
                or (n.type == "CallExpression" and self._callee(n) in _COMPARES)
                for n in test
            )
            branch = node["consequent"]
            inside = branch is not None and any(n is call for n in Syntax.walk(branch))
            if literal and compares and inside and self._input_ids(node["test"]) & tainted:
                return True
        return False

    def _handlers(self, text: str) -> list[tuple[Node, str]]:
        """(handler function, what the tool says of itself: its name and description)."""
        out: list[tuple[Node, str]] = []
        for node in Syntax.walk(self.program):
            if node.type != "CallExpression":
                continue
            args = list(node["arguments"] or [])
            functions = [a for a in args if a.type in _FUNCTIONS]
            if not functions:
                continue
            name = self._callee(node)
            if name in _REGISTER:
                said = [v for a in args if isinstance(v := self._literal(a), str)]
                said += self._descriptions(args)
                out.append((functions[-1], " ".join(said)))
            elif name == "setRequestHandler" and "CallTool" in text[args[0].start : args[0].end]:
                # The dispatcher: each tool's description is in the list handler, not here.
                out.append((functions[-1], ""))
        return out

    def _descriptions(self, args: list[Node]) -> list[str]:
        """`registerTool(name, { description, title }, fn)`."""
        out: list[str] = []
        for arg in args:
            if arg.type != "ObjectExpression":
                continue
            for prop in arg["properties"] or []:
                if prop.type == "Property" and self._ids(prop["key"]) & {"description", "title"}:
                    value = self._literal(prop["value"])
                    if isinstance(value, str):
                        out.append(value)
        return out


__all__ = ["McpJsCode"]
