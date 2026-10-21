"""Which lines of a Python file write a persistence location, read from its syntax tree.

The pattern tier sees `~/.bashrc`, `LaunchAgents`, `crontab` or a `CurrentVersion\\Run` key written out
and takes the line as a foothold planted. A path that is only named is not one: a skill that lists
the shell profiles it reads an API key from, a scanner's table of the patterns it looks for, an
incident-response script that runs `crontab -l` to save the evidence, an error that tells a person
which file to edit (review 98, DataDog real skills: es-analytics, clawhub-skill-scanner,
collecting-volatile-evidence, minimax-voice-director). The shell rule was narrowed the same way
(`e534f6c`); this is the write-context check regex cannot make across statements.

A literal that names such a location is followed to where its value goes (`py_flow.py`), and its
line is WRITTEN when the value reaches a sink. Sinks fail safe: every call is one except what only
reads or formats a path (`os.path.join`, `exists`, `read_text`, `str.format`), a message for a
person, `open` in a read mode, and a command written out whole that only lists (`crontab -l`,
`systemctl status`, `reg query`). A call outside the file that is handed the value counts as a
write, as does any process started with it. Because every such call is a sink, its RESULT does not
carry the value on (`carries`): a listing's output saved as evidence, a hash, a count are not the
location; reads, formats, the file's own functions and its field-only classes (a dataclass) do. A
literal that is itself a whole read-only command (`"crontab -l"` in a table of commands to collect)
is never written, wherever it goes.

`written_lines` returns None when the file holds more than `MAX_SEEDS` such literals: the caller
then keeps every pattern hit, as before.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from typing import ClassVar, Final

from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow

#: Text any persistence pattern of `CAP.PY.PERSIST.001` contains, case-insensitively: a superset,
#: so that a line this does not seed is a line that rule cannot match inside a literal either.
PERSIST_WORD: Final = re.compile(
    r"(?i)bashrc|bash_profile|zshrc|\.profile|crontab|/etc/cron|launch(?:agents|daemons)|systemd"
    r"|systemctl|wantedby|currentversion|sitecustomize|usercustomize|startup"
)

#: A command, folded whole, that only reads what a persistence location holds.
READ_ONLY_COMMAND: Final = re.compile(
    r"(?i)\s*(?:crontab\s+-l(?:\s+-u\s+[\w.-]+)?"
    r"|systemctl\s+(?:--user\s+)?(?:status|is-enabled|is-active|list-units|list-unit-files"
    r"|list-timers|show|cat)\b[^;&|<>`$]*"
    r"|launchctl\s+(?:list|print)\b[^;&|<>`$]*"
    r"|schtasks(?:\.exe)?\s+/query\b[^;&|<>`$]*"
    r"|reg(?:\.exe)?\s+(?:query|export)\b[^;&|<>`$]*"
    r"|(?:ls|cat|head|tail|stat|grep|test)\b[^;&|<>`$]*"
    r"|find\b(?![^;&|<>`$]*\s-(?:exec|execdir|ok|okdir|delete|fprint|fprintf|fls)\b)[^;&|<>`$]*)\s*"
)


class PythonPersistence(PythonValueFlow):
    #: Calls that only read, test or format what they are given; their result carries the value.
    READS: ClassVar[frozenset[str]] = frozenset(
        [
            "exists",
            "isfile",
            "isdir",
            "islink",
            "lexists",
            "expanduser",
            "expandvars",
            "abspath",
            "realpath",
            "normpath",
            "dirname",
            "basename",
            "split",
            "splitext",
            "join",
            "joinpath",
            "relpath",
            "getmtime",
            "getsize",
            "getctime",
            "stat",
            "lstat",
            "access",
            "listdir",
            "scandir",
            "walk",
            "glob",
            "iglob",
            "rglob",
            "iterdir",
            "read_text",
            "read_bytes",
            "is_file",
            "is_dir",
            "is_symlink",
            "resolve",
            "absolute",
            "as_posix",
            "with_suffix",
            "with_name",
            "with_stem",
            "relative_to",
            "match",
            "fnmatch",
            "Path",
            "PurePath",
            "PosixPath",
            "WindowsPath",
            "PurePosixPath",
            "PureWindowsPath",
            "str",
            "repr",
            "len",
            "sum",
            "min",
            "max",
            "abs",
            "round",
            "bool",
            "int",
            "float",
            "hash",
            "type",
            "sha1",
            "sha256",
            "sha512",
            "md5",
            "hexdigest",
            "digest",
            "format",
            "format_map",
            "sorted",
            "list",
            "tuple",
            "set",
            "frozenset",
            "dict",
            "any",
            "all",
            "enumerate",
            "zip",
            "isinstance",
            "startswith",
            "endswith",
            "strip",
            "lstrip",
            "rstrip",
            "lower",
            "upper",
            "casefold",
            "encode",
            "decode",
            "splitlines",
            "partition",
            "rpartition",
            "find",
            "rfind",
            "index",
            "count",
            "get",
            "keys",
            "values",
            "items",
            "search",
            "findall",
            "finditer",
            "fullmatch",
            "sub",
            "subn",
            "compile",
            "escape",
            "quote",
            "dumps",
            "loads",
            "getenv",
            "which",
            "home",
            "cwd",
            "read",
            "readline",
            "readlines",
            "close",
            "seek",
            "tell",
            "fileno",
        ]
    )
    #: Calls that show text to a person, or end the program with it: what they are given is advice.
    MESSAGES: ClassVar[frozenset[str]] = frozenset(
        [
            "print",
            "echo",
            "warn",
            "warning",
            "info",
            "debug",
            "error",
            "exception",
            "critical",
            "log",
            "exit",
            "secho",
            "style",
            "wrn",
            "inf",
            "dbg",
            "err",
            "fail",
            "abort",
        ]
    )
    #: Keywords that carry text for a person (`help=` of an argument, a message).
    TEXT_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        ["help", "description", "epilog", "usage", "msg", "message", "prog", "title", "doc"]
    )

    def __init__(self, tree: ast.AST) -> None:
        super().__init__(tree)
        #: The text of every seed literal of each label.
        self.texts: dict[Label, list[str]] = {}
        #: The file's classes that only hold fields (a dataclass, a NamedTuple): building one
        #: stores what it is given. A class with its own `__init__` is a call like any other.
        self.records = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and not any(
                isinstance(s, ast.FunctionDef | ast.AsyncFunctionDef)
                and s.name in ("__init__", "__new__", "__post_init__", "__set_name__")
                for s in node.body
            )
        }

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            if PERSIST_WORD.search(text):
                self.texts.setdefault(node.lineno, []).append(text)
                return node.lineno
        return None

    def carries(self, node: ast.Call) -> bool:
        """A call's result carries its arguments only when it keeps the value: a read or a format,
        the file's own function, one of its records. Any other call is a sink for what it is
        handed, so its result -- a process's output, a hash, a count -- need not carry it on."""
        name = self.name(node.func)
        return name in self.READS or name in self.functions or name in self.records

    @classmethod
    def written_lines(cls, tree: ast.AST) -> frozenset[int] | None:
        """Lines where a persistence location named by a literal is written; None when the file
        holds too many such literals to follow."""
        analysis = cls(tree)
        if not analysis.index():
            return None
        analysis.flow()
        # A literal that is itself a whole read-only command (`"crontab -l"`, `"ls /etc/cron.d/"`,
        # from a table run one by one, or saved as the header of the evidence it gave) names the
        # location only as what it lists: wherever its value goes, it plants nothing there.
        listing = {
            label
            for label, texts in analysis.texts.items()
            if all(READ_ONLY_COMMAND.fullmatch(t) for t in texts)
        }
        out: set[int] = set()
        for node in analysis.calls:
            reached = analysis._written_by(node) - listing
            if reached:
                out |= reached
                out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        return frozenset(out)

    @staticmethod
    def named_only_lines(source: str) -> frozenset[int]:
        """Lines whose every persistence word sits inside a string or a comment: the lines this
        check may speak for. A word in code itself (`from crontab import CronTab`) is not."""
        spans: dict[int, list[tuple[int, int]]] = {}
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return frozenset()
        # A string, a comment, and the literal text of an f-string (3.12 splits it into pieces).
        kinds = {tokenize.STRING, tokenize.COMMENT, getattr(tokenize, "FSTRING_MIDDLE", -1)}
        for tok in tokens:
            if tok.type not in kinds:
                continue
            (r0, c0), (r1, c1) = tok.start, tok.end
            for row in range(r0, r1 + 1):
                spans.setdefault(row, []).append(
                    (c0 if row == r0 else 0, c1 if row == r1 else 1 << 30)
                )
        out: set[int] = set()
        for row, line in enumerate(source.splitlines(), 1):
            words = list(PERSIST_WORD.finditer(line))
            if words and all(
                any(a <= w.start() and w.end() <= b for a, b in spans.get(row, ())) for w in words
            ):
                out.add(row)
        return frozenset(out)

    def _written_by(self, node: ast.Call) -> set[Label]:
        """The persistence literals this call writes, or puts into a process it starts."""
        name = self.name(node.func)
        if name in self.functions or name in self.STORES or name in self.records:
            return set()  # followed into the function; a store is a flow, not a write
        given = self.given(node, self.TEXT_KEYWORDS | {"file"})
        if self.dotted(node.func) in self.PROCESS or name in self.PROCESS:
            command = self.command(node)
            if command is not None and READ_ONLY_COMMAND.fullmatch(command):
                return set()
            return given
        if name in self.MESSAGES or (name or "").endswith(("Error", "Exception", "Warning")):
            target = next((k.value for k in node.keywords if k.arg == "file"), None)
            return self.taint(target) if target is not None else set()
        if name == "open":
            return given | self.receiver(node) if self._opens_to_write(node) else set()
        if name in self.READS:
            return set()
        return given | self.receiver(node)

    @classmethod
    def _opens_to_write(cls, node: ast.Call) -> bool:
        """`open(p, "a")`, `Path(p).open("w")`: a mode with w, a, x or +. A mode the file does not
        write out is taken as writing."""
        method = isinstance(node.func, ast.Attribute) and cls.dotted(node.func) not in (
            "io.open",
            "codecs.open",
            "os.open",
        )
        position = 0 if method else 1
        mode = node.args[position] if len(node.args) > position else None
        mode = next((k.value for k in node.keywords if k.arg == "mode"), mode)
        if mode is None:
            return False
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
            return True
        return any(flag in mode.value for flag in "wax+")


__all__ = ["PythonPersistence"]
