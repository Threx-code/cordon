"""A password sent to a host anyone can get for nothing: credential theft, whoever ships it.

project47 1.0 (Python 2, read through PythonTwoReader) logs into the accounts it handles and, in
`upass`, sends the `email` and `password` to `tik-tok.rf.gd`: a free-hosting subdomain dressed as
TikTok. A platform client sends a password to the platform; a password that goes to a free
subdomain, a paste site, a tunnel or an interaction service goes to whoever registered it.

`credentials sent to a free host: <sink>`: a request (an EGRESS primitive) whose destination is a
literal URL on an interaction host, or on a subdomain of a free-hosting, paste or tunnel domain
whose own name wears a login platform's brand (`PLATFORM_BRANDS`; the sets live in
`analysis/shared/destinations.py`, the one list), directly or through one binding in the
function, and whose arguments carry a password-named value (`password`, `passwd`, `pwd`, `pass`,
`senha`, `sandi`), directly or through the function's bindings.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.shared.destinations import (
    FREE_HOSTING,
    INTERACTION_HOSTS,
    PASTE_HOSTS,
    PLATFORM_BRANDS,
    TUNNEL_HOSTS,
)
from cordon_scanner.foundation.capabilities import Capability


class FreeHostCredentials(AnalyzerCore):
    """`_credentials_to_free_hosts` and what it needs."""

    HOSTS: ClassVar[frozenset[str]] = FREE_HOSTING | PASTE_HOSTS | TUNNEL_HOSTS | INTERACTION_HOSTS
    _PASSWORD: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(?:^|_)(?:pass|passwd|password|pwd|senha|sandi)(?:$|_|\d)"
    )
    _URL_HOST: ClassVar[re.Pattern[str]] = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://([^/:?#\s]+)")

    def _credentials_to_free_hosts(self, tree: ast.AST) -> None:
        scopes: list[ast.AST] = [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
            tree,
        ]
        seen: set[int] = set()
        for scope in scopes:
            bound = self._scope_values(scope)
            for call in PythonSyntax.within(scope, ast.Call):
                if id(call) in seen:
                    continue
                seen.add(id(call))
                resolved = self._resolve_callee(call)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                    continue
                parts: list[ast.AST] = [*resolved[1].args, *(k.value for k in resolved[1].keywords)]
                if self._free_host(parts, bound) and self._carries_password(parts, bound):
                    self._record(
                        Capability.EGRESS, call, f"credentials sent to a free host: {resolved[0]}"
                    )

    @staticmethod
    def _scope_values(scope: ast.AST) -> dict[str, list[ast.AST]]:
        found: dict[str, list[ast.AST]] = {}
        for node in PythonSyntax.within(scope, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, []).append(node.value)
        return found

    def _hosts(self, node: ast.AST) -> set[str]:
        return {
            m.group(1).lower()
            for c in ast.walk(node)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
            for m in [self._URL_HOST.match(c.value)]
            if m is not None
        }

    def _free_host(self, parts: list[ast.AST], bound: dict[str, list[ast.AST]]) -> bool:
        hosts: set[str] = set()
        for part in parts:
            hosts |= self._hosts(part)
            for name in (n.id for n in ast.walk(part) if isinstance(n, ast.Name)):
                for value in bound.get(name, [])[:3]:
                    hosts |= self._hosts(value)
        return any(self._collector(h) for h in hosts)

    def _collector(self, host: str) -> bool:
        """An interaction host (a password sent there has no reading but theft), or a subdomain of
        a free-hosting, paste or tunnel domain whose own name wears a login platform's brand
        (`tik-tok.rf.gd`). The service's own domain (`pastebin.com`'s login API) and a vendor's
        backend named for itself (`crucihil-server.fly.dev`) are not: 3 of 16,274 that way."""
        if any(host == k or host.endswith("." + k) for k in INTERACTION_HOSTS):
            return True
        for known in FREE_HOSTING | PASTE_HOSTS | TUNNEL_HOSTS:
            if host.endswith("." + known):
                own = host[: -len(known) - 1].replace("-", "").replace("_", "").replace(".", "")
                return any(brand in own for brand in PLATFORM_BRANDS)
        return False

    def _carries_password(self, parts: list[ast.AST], bound: dict[str, list[ast.AST]]) -> bool:
        pending = [n.id for part in parts for n in ast.walk(part) if isinstance(n, ast.Name)]
        pending += [
            c.value
            for part in parts
            for c in ast.walk(part)
            if isinstance(c, ast.Constant) and isinstance(c.value, str) and len(c.value) < 32
        ]
        seen: set[str] = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            if self._PASSWORD.search(name):
                return True
            for value in bound.get(name, [])[:3]:
                pending += [n.id for n in ast.walk(value) if isinstance(n, ast.Name)]
            if len(seen) > 64:
                break
        return False


__all__ = ["FreeHostCredentials"]
