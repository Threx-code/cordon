"""Which runs in a Python file a decoded value cannot reach, read from its syntax tree.

`SUSPECT.DECODE_EXEC.001` and `MALWARE.INSTALL.DECODED_LAUNCH.001` pair a decode with a run near it.
In Python the AST already excuses a run whose command is written out whole (`safe_spawn_lines`).
This is the flow form, the one JavaScript gets from js_flow: the decoded value is followed
(`py_flow.py`) -- through names, containers, the file's own functions and what they return -- and a
run none of it reaches is not a run of it: a mixer decoding embedded sound effects to write them
beside the ffmpeg it runs (review 98 real skills, render-imessage-chat). Two other real skills stay
paired, rightly by this reading: a test hands the path of its decoded fixture to the function under
test, imported from another file (qwen-image-gen), and a reviewer runs `git fetch origin <sha>` with
a commit read from a decoded manifest (se-dev-plugin-review) -- a decoded git argument can run code
through an option.

Fail closed. A decoded value written to a file marks the file's path, so a later run of that path
is reached -- and so is a run naming any literal the path was built from (`open("/tmp/x", "wb")`,
then `run(["/tmp/x"])`, the same text twice). A decoded value handed to anything this does not know to only read, compare, hash,
parse as data or write -- `pickle.loads`, a ctypes copy, a call outside the file -- may run it, and
then no run in the file is excused.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow


class PythonDecodedRun(PythonValueFlow):
    #: Calls whose result is a decoded payload.
    DECODES: ClassVar[frozenset[str]] = frozenset(
        [
            "b64decode",
            "b32decode",
            "b16decode",
            "b85decode",
            "a85decode",
            "urlsafe_b64decode",
            "standard_b64decode",
            "decodebytes",
            "decodestring",
            "unhexlify",
            "a2b_base64",
            "a2b_hex",
            "a2b_qp",
            "fromhex",
            "decompress",
            "gunzip",
            "inflate",
        ]
    )
    #: `codecs.decode(x, "base64")`, `x.decode("hex")`: a decode named by its codec.
    CODECS: ClassVar[frozenset[str]] = frozenset(
        ["base64", "base_64", "hex", "zlib", "bz2", "rot13", "rot_13"]
    )
    #: Runs: what starts a process or executes code, besides `PROCESS`.
    EXECUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "exec",
            "eval",
            "compile",
            "exec_module",
            "run_path",
            "run_module",
            "import_module",
            "__import__",
            "execv",
            "execve",
            "execvp",
            "execl",
            "execlp",
            "spawnv",
            "spawnl",
            "spawnvp",
            "startfile",
        ]
    )
    #: Calls that only read, measure, compare, hash, encode or parse a value as data.
    INERT: ClassVar[frozenset[str]] = frozenset(
        [
            "len",
            "bytes",
            "bytearray",
            "str",
            "repr",
            "memoryview",
            "hex",
            "decode",
            "encode",
            "split",
            "rsplit",
            "strip",
            "lstrip",
            "rstrip",
            "startswith",
            "endswith",
            "find",
            "rfind",
            "index",
            "count",
            "replace",
            "join",
            "splitlines",
            "partition",
            "frombytes",
            "tobytes",
            "b64encode",
            "b32encode",
            "b16encode",
            "urlsafe_b64encode",
            "encodebytes",
            "hexlify",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha512",
            "md5",
            "blake2b",
            "blake2s",
            "new",
            "update",
            "digest",
            "hexdigest",
            "compare_digest",
            "isinstance",
            "print",
            "BytesIO",
            "StringIO",
            "literal_eval",
            "sorted",
            "list",
            "tuple",
            "set",
            "dict",
            "any",
            "all",
            "zip",
            "enumerate",
            "getvalue",
            "read",
            "seek",
            "read_bytes",
            "read_text",
            "exists",
            "is_file",
            "stat",
            "unlink",
        ]
    )
    #: Data parsers by module: `json.loads` turns text into values, `pickle.loads` runs code.
    PARSERS: ClassVar[frozenset[str]] = frozenset(
        [
            "json.loads",
            "json.load",
            "orjson.loads",
            "ujson.loads",
            "tomllib.loads",
            "yaml.safe_load",
        ]
    )
    #: Methods that write their argument to the file their receiver names.
    WRITES: ClassVar[frozenset[str]] = frozenset(
        ["write", "write_bytes", "write_text", "writelines"]
    )

    def __init__(self, tree: ast.AST) -> None:
        super().__init__(tree)
        self.handles: dict[str, ast.AST] = {}
        self.assigned: dict[str, list[ast.AST]] = {}
        self.written: set[str] = set()

    def seed(self, node: ast.AST) -> Label | None:
        if not isinstance(node, ast.Call):
            return None
        name = self.name(node.func)
        if name in self.DECODES:
            return node.lineno
        if name == "decode" and any(
            isinstance(a, ast.Constant) and str(a.value).lower() in self.CODECS for a in node.args
        ):
            return node.lineno
        return None

    @classmethod
    def unreached_runs(cls, source: str) -> frozenset[int]:
        """`unreached_run_lines` of a source text; empty when it does not parse."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            return frozenset()
        return cls.unreached_run_lines(tree)

    @classmethod
    def unreached_run_lines(cls, tree: ast.AST) -> frozenset[int]:
        """Lines of runs no decoded value in the file can reach; empty when one may reach any."""
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return frozenset()
        analysis._handles()
        analysis.flow()
        unreached: set[int] = set()
        reached: set[int] = set()
        for node in analysis.calls:
            if analysis._consumes(node):
                return frozenset()
            if analysis._runs(node):
                lines = range(node.lineno, (node.end_lineno or node.lineno) + 1)
                if analysis.given(node) | analysis.receiver(node) or analysis._names_written(node):
                    reached.update(lines)
                else:
                    unreached.update(lines)
        # The excuse is taken by line: a line holding a reached run keeps every hit on it, as
        # `exec(__import__("base64").b64decode(...))` holds an unreached `__import__` beside it.
        return frozenset(unreached - reached)

    def _names_written(self, node: ast.Call) -> bool:
        """Whether the run names a file a decoded value was written to, by the same literal or its
        file name (`open("x.vbs", "w")`, then `os.system("start x.vbs")`)."""
        names = self.written | {w.replace("\\", "/").rsplit("/", 1)[-1] for w in self.written}
        names = {n for n in names if len(n) > 1}
        return any(n in text for text in self._literals(node) for n in names)

    def _handles(self) -> None:
        """`f = open(path, "wb")` and `with open(path, "wb") as f`: which path each handle writes."""
        for node in ast.walk(self.tree):
            pairs: list[tuple[ast.AST, ast.AST]] = []
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                pairs.append((node.targets[0], node.value))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                pairs.append((node.optional_vars, node.context_expr))
            for target, value in pairs:
                if isinstance(target, ast.Name):
                    self.assigned.setdefault(target.id, []).append(value)
                if (
                    isinstance(target, ast.Name)
                    and isinstance(value, ast.Call)
                    and self.name(value.func) == "open"
                    and value.args
                ):
                    self.handles[target.id] = value.args[0]

    def call_flow(self, node: ast.Call) -> bool:
        """A decoded value written to a file: the file's path carries it, so running that path is
        running it."""
        if self.name(node.func) not in self.WRITES or not isinstance(node.func, ast.Attribute):
            return False
        value = self.given(node)
        if not value:
            return False
        where = node.func.value
        path: ast.AST = where
        if isinstance(where, ast.Name) and where.id in self.handles:
            path = self.handles[where.id]
        elif isinstance(where, ast.Call) and where.args:
            path = where.args[0]  # `open(p, "wb").write(x)`, `Path(p).write_bytes(x)`
        self.written |= self._literals(path)
        return self.bind(where, value) | (path is not where and self.bind(path, value))

    def _literals(self, node: ast.AST, depth: int = 0) -> set[str]:
        """The string literals an expression is built from, through what its names are assigned."""
        out: set[str] = set()
        for part in ast.walk(node):
            if (
                isinstance(part, ast.Constant)
                and isinstance(part.value, str)
                and len(part.value) > 1
            ):
                out.add(part.value)
            elif isinstance(part, ast.Name) and depth < 3:
                for value in self.assigned.get(part.id, ()):
                    out |= self._literals(value, depth + 1)
        return out

    def _runs(self, node: ast.Call) -> bool:
        name = self.name(node.func)
        return (
            self.dotted(node.func) in self.PROCESS or name in self.PROCESS or name in self.EXECUTES
        )

    def _consumes(self, node: ast.Call) -> bool:
        """Whether this call is handed a decoded value and may do with it what this does not see."""
        if not (self.given(node) or self.receiver(node)):
            return False
        name = self.name(node.func) or ""
        dotted = self.dotted(node.func) or ""
        return not (
            self._runs(node)
            or name in self.functions
            or name in self.STORES
            or name in self.WRITES
            or name in self.INERT
            or name in self.DECODES
            or name.startswith("assert")
            or dotted in self.PARSERS
            or (name == "open" and len(node.args) > 1)
            or name.endswith(("Error", "Exception", "Warning"))
        )


__all__ = ["PythonDecodedRun"]
