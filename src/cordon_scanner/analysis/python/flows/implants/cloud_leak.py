"""What the machine knows, put in a cloud store.

`blob.upload_from_string(value)` where `value` was read from the environment or from the machine
(`os.getenv`, `os.environ[...]`, the host and user names, the platform) is a collector's last step: the
bucket belongs to whoever wrote the code, and the value is what it learned about the machine. A
program that uploads files it was asked to upload, or data it made, does not start from the
environment. The environment variable that names the bucket or the project is the destination, not
the payload: it reaches `bucket(...)`, never the upload's argument.

`lines` returns the line of each upload whose payload carries such a value, in a file that imports a
cloud-storage library (`CLOUD_STORAGE_LIBRARIES`).
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.flows.http_clients import (
    CLOUD_STORAGE_LIBRARIES,
    CLOUD_UPLOAD_METHODS,
)
from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow


class CloudLeak(PythonValueFlow):
    """The uploads of machine facts in one syntax tree."""

    READS: ClassVar[frozenset[str]] = frozenset(
        {
            "os.getlogin",
            "getpass.getuser",
            "socket.gethostname",
            "socket.getfqdn",
            "platform.node",
            "platform.platform",
            "platform.system",
            "platform.uname",
            "platform.release",
            "platform.machine",
            "os.uname",
        }
    )
    #: The upload calls whose argument is the content: the methods that take a path name a file, and a
    #: path from the environment or the working directory is where the file is, not what it holds.
    PAYLOAD_POSITION: ClassVar[dict[str, int]] = {"upload_from_string": 0}
    PAYLOAD_KEYWORDS: ClassVar[frozenset[str]] = frozenset({"Body", "data", "content", "body"})

    def __init__(self, tree: ast.AST) -> None:
        super().__init__(tree)
        #: `os.environ` taken whole: handed to a call (`dict(os.environ)`), or copied or listed.
        self.whole: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for arg in node.args:
                    if (self.dotted(arg) or "") in ("os.environ", "os.environb"):
                        self.whole.add(id(arg))
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("copy", "items", "values", "keys")
                    and (self.dotted(node.func.value) or "") in ("os.environ", "os.environb")
                ):
                    self.whole.add(id(node.func.value))

    def _machine_key(self, key: ast.AST | None) -> bool:
        """Any literal key: a collector reads whatever the environment holds, and the payload position
        (below) is what keeps a setting read beside the data out."""
        return isinstance(key, ast.Constant) and isinstance(key.value, str)

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Call):
            dotted = self.dotted(node.func) or ""
            if dotted in ("os.getenv", "os.environ.get"):
                return node.lineno if node.args and self._machine_key(node.args[0]) else None
            if dotted in self.READS:
                return node.lineno
        if isinstance(node, ast.Subscript) and (self.dotted(node.value) or "") in ("os.environ", "os.environb"):
            return node.lineno if self._machine_key(node.slice) else None
        if isinstance(node, ast.Attribute) and id(node) in self.whole:
            return node.lineno
        return None

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        imported = any(
            (isinstance(n, ast.ImportFrom) and any((n.module or "") == lib or (n.module or "").startswith(lib + ".") for lib in CLOUD_STORAGE_LIBRARIES))
            or (isinstance(n, ast.Import) and any(a.name == lib or a.name.startswith(lib + ".") for a in n.names for lib in CLOUD_STORAGE_LIBRARIES))
            for n in ast.walk(tree)
        )
        if not imported:
            return []
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: set[int] = set()
        for node in analysis.calls:
            method = analysis.name(node.func) or ""
            if method not in CLOUD_UPLOAD_METHODS:
                continue
            payload: list[ast.AST] = [k.value for k in node.keywords if k.arg in cls.PAYLOAD_KEYWORDS]
            position = cls.PAYLOAD_POSITION.get(method)
            if position is not None and len(node.args) > position:
                payload.append(node.args[position])
            if any(analysis.taint(part) for part in payload):
                out.add(node.lineno)
        return sorted(out)


__all__ = ["CloudLeak"]
