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
)
from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


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
    #: Where the content of each upload is, by position; the keywords below carry it too. The methods
    #: that take a path (`upload_file`, `upload_from_filename`, `fput_object`) name a file, and a path
    #: from the environment is where the file is, not what it holds.
    PAYLOAD_POSITION: ClassVar[dict[str, int]] = {
        "upload_from_string": 0,
        "upload_blob": 0,
        "upload_data": 0,
        "upload_fileobj": 0,
        "put_blob": 1,
        "put_object": 99,  # boto3 and minio's content travels in `Body` / `data`, by keyword
    }
    PAYLOAD_KEYWORDS: ClassVar[frozenset[str]] = frozenset({"Body", "data", "content", "body"})
    #: The variables that say who and where the machine is, and which CI run it is. Any other variable
    #: is a setting (a bucket, a region, a prefix), which 15 of 16,274 benign units read and send beside
    #: their own data through `put_object` and `upload_blob`.
    MACHINE_VARIABLES: ClassVar[frozenset[str]] = frozenset(
        {"USER", "USERNAME", "LOGNAME", "HOME", "USERPROFILE", "PWD", "HOSTNAME", "COMPUTERNAME",
         "USERDOMAIN", "SHELL", "OS", "PROCESSOR_ARCHITECTURE", "LANG", "PATH", "TERM", "CI",
         "GITHUB_ACTOR", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "RUNNER_NAME", "RUNNER_OS",
         "GITLAB_USER_LOGIN", "BUILD_USER", "JENKINS_URL", "BUILD_URL"}
    )  # fmt: skip

    def __init__(self, tree: ast.AST, *, any_key: bool = False) -> None:
        super().__init__(tree)
        #: Whether any literal key of the environment is a machine fact (the payload of
        #: `upload_from_string`, where a setting is never the content), or only the machine variables.
        self.any_key = any_key
        #: `os.environ` taken whole: handed to a call (`dict(os.environ)`), or copied or listed.
        self.whole: set[int] = set()
        for node in PythonSyntax.walked_of(tree, ast.Call):
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
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return False
        return self.any_key or key.value.upper() in self.MACHINE_VARIABLES

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Call):
            dotted = self.dotted(node.func) or ""
            if dotted in ("os.getenv", "os.environ.get"):
                return node.lineno if node.args and self._machine_key(node.args[0]) else None
            if dotted in self.READS:
                return node.lineno
        if isinstance(node, ast.Subscript) and (self.dotted(node.value) or "") in (
            "os.environ",
            "os.environb",
        ):
            return node.lineno if self._machine_key(node.slice) else None
        if isinstance(node, ast.Attribute) and id(node) in self.whole:
            return node.lineno
        return None

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        if not cls._imports_a_store(tree):
            return []
        out: set[int] = set()
        for any_key in (True, False):
            analysis = cls(tree, any_key=any_key)
            if not analysis.index() or not analysis.seeds:
                continue
            analysis.flow()
            for node in analysis.calls:
                method = analysis.name(node.func) or ""
                # a setting read from the environment is content only for `upload_from_string`
                if method not in cls.PAYLOAD_POSITION or (
                    any_key and method != "upload_from_string"
                ):
                    continue
                payload: list[ast.AST] = [
                    k.value for k in node.keywords if k.arg in cls.PAYLOAD_KEYWORDS
                ]
                position = cls.PAYLOAD_POSITION[method]
                if len(node.args) > position:
                    payload.append(node.args[position])
                if any(analysis.taint(part) for part in payload):
                    out.add(node.lineno)
        return sorted(out)

    @staticmethod
    def _imports_a_store(tree: ast.AST) -> bool:
        for n in PythonSyntax.walked_of(tree, ast.Import, ast.ImportFrom):
            names = (
                [n.module or ""]
                if isinstance(n, ast.ImportFrom)
                else [a.name for a in n.names]
                if isinstance(n, ast.Import)
                else []
            )
            if any(
                m == lib or m.startswith(lib + ".")
                for m in names
                for lib in CLOUD_STORAGE_LIBRARIES
            ):
                return True
        return False


__all__ = ["CloudLeak"]
