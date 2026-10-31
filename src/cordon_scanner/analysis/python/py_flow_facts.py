"""Where a Python file sends what it reads: the flow facts of the package verdict, for Python.

The JavaScript flow facts (`JsFlow`, read by `ReachedFlows`) name each source a file reads, the sink
it reaches and the kind of destination. A setup script or a package's `__init__.py` gets the same
facts here, in the same words, so a model reads an npm package and a PyPI one alike:

- sources: `environment` (`os.environ`, `os.getenv`), `identity` (the user's or the machine's name:
  `getpass.getuser`, `socket.gethostname`, `platform.node`, `os.getlogin`, `uuid.getnode`, and the
  environment variables that hold them), `secret_file` (a credential store's path, as the
  JavaScript analysis reads one), `home_file` (`expanduser`, `Path.home`), `decoded` (base64, hex,
  zlib, marshal);
- sinks: `request` (requests, httpx, urllib, http.client), `connection` (a socket's send or connect),
  `dns` (a host lookup), `process` (subprocess, `os.system`, `os.popen`);
- destination: `drop`, `ip`, `fixed` (`JsFlow.classify`, the same lists), `unknown` when no literal
  URL or host names it.

Over-approximate like the engine it extends (`PythonValueFlow`): a value that may be carried is
carried. Facts, never findings.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow
from cordon_scanner.analysis.python.py_identity import IdentityVariables
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class PythonFlowFacts(PythonValueFlow):
    """`of(source)`: `(source, sink, destination)` for every flow in one Python file."""

    #: Labels are source kinds, so a value's label set is the set of kinds it may carry.
    KINDS: ClassVar[tuple[str, ...]] = (
        "environment",
        "identity",
        "secret_file",
        "home_file",
        "decoded",
    )
    IDENTITY_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "getpass.getuser",
            "socket.gethostname",
            "socket.getfqdn",
            "platform.node",
            "platform.uname",
            "os.getlogin",
            "os.uname",
            "uuid.getnode",
        }
    )
    HOME_CALLS: ClassVar[frozenset[str]] = frozenset(
        {"os.path.expanduser", "Path.home", "pathlib.Path.home"}
    )
    DECODE_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "base64.b64decode",
            "base64.b32decode",
            "base64.a85decode",
            "base64.urlsafe_b64decode",
            "binascii.unhexlify",
            "binascii.a2b_base64",
            "bytes.fromhex",
            "codecs.decode",
            "zlib.decompress",
            "marshal.loads",
        }
    )
    SINKS: ClassVar[dict[str, frozenset[str]]] = {
        "request": frozenset(
            {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.request",
                "httpx.get",
                "httpx.post",
                "httpx.request",
                "urllib.request.urlopen",
                "urllib.request.Request",
                "urlopen",
                "http.client.HTTPConnection",
                "http.client.HTTPSConnection",
            }
        ),
        "connection": frozenset({"send", "sendall", "sendto", "connect", "create_connection"}),
        "dns": frozenset(
            {
                "socket.gethostbyname",
                "socket.getaddrinfo",
                "dns.resolver.resolve",
                "dns.resolver.query",
            }
        ),
        "process": frozenset(
            {
                "subprocess.run",
                "subprocess.call",
                "subprocess.Popen",
                "subprocess.check_call",
                "subprocess.check_output",
                "os.system",
                "os.popen",
            }
        ),
    }

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._kind("secret_file") if JsFlow.SECRET_PATH.search(node.value) else None
        if isinstance(node, ast.Call):
            dotted = self.dotted(node.func)
            if IdentityVariables.read(node, dotted) or dotted in self.IDENTITY_CALLS:
                return self._kind("identity")
            if dotted in ("os.getenv", "os.environ.get"):
                return self._kind("environment")
            if dotted in self.HOME_CALLS:
                return self._kind("home_file")
            if dotted in self.DECODE_CALLS:
                return self._kind("decoded")
        if isinstance(node, ast.Subscript) and IdentityVariables.read(
            node, self.dotted(node.value)
        ):
            return self._kind("identity")
        if isinstance(node, ast.Attribute) and self.dotted(node) in ("os.environ", "os.environb"):
            return self._kind("environment")
        return None

    @classmethod
    def _kind(cls, name: str) -> Label:
        return cls.KINDS.index(name) + 1

    @classmethod
    def of(cls, source: str) -> set[tuple[str, str, str]]:
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return set()
        analysis = cls(tree)
        if not analysis.index():
            return set()
        try:
            analysis.flow()
        except RecursionError:
            return set()
        out: set[tuple[str, str, str]] = set()
        for node in analysis.calls:
            sink = analysis._sink(node)
            if sink is None:
                continue
            carried = analysis.given(node) | analysis.receiver(node)
            if not carried:
                continue
            destination = analysis._destination(node)
            for label in carried:
                if 1 <= label <= len(cls.KINDS):
                    out.add((cls.KINDS[label - 1], sink, destination))
        return out

    def _sink(self, node: ast.Call) -> str | None:
        dotted = self.dotted(node.func) or ""
        name = self.name(node.func) or ""
        for sink, names in self.SINKS.items():
            if dotted in names or (sink == "connection" and name in names):
                return sink
        return None

    @staticmethod
    def _destination(node: ast.Call) -> str:
        """The kind of the first literal URL or host in the call's arguments -- whole, or the start
        of one built from it (`"https://h/c?x=" + name`) -- or `unknown` if none."""
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            for part in ast.walk(arg):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    text = part.value if "://" in part.value else f"http://{part.value}"
                    host, kind = JsFlow.classify(text)
                    if host is not None and "." in host:
                        return kind
        return "unknown"


__all__ = ["PythonFlowFacts"]
