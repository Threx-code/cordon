"""A file that computes a platform app's request signature for the platform's API.

`platform request signed: <n> signing parameters`: the file writes down at least
`MINIMUM_PARAMETERS` distinct request-signature names of a social platform's app API (headers or
query parameters: `X-Gorgon`, `X-Argus`, `X-Bogus`, `msToken` ...) as string literals, and also
names one of that platform's API hosts. A scraper reads a cookie by one of these names; the code
that signs requests needs several, and the host they are for. The tool passes as the platform's
app: it is policy (`POLICY.ABUSE_TOOLING.PLATFORM_FORGERY.001`), never malware. The names and
hosts are in `analysis/shared/platform_signing.py`.
"""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.flows.forgery.platform_signing import (
    MINIMUM_PARAMETERS,
    PlatformSigning,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class PlatformForgery(AnalyzerCore):
    """`_platform_forgery`."""

    def _platform_forgery(self, tree: ast.AST) -> None:
        signed: dict[str, ast.AST] = {}
        names_host = False
        for node in PythonSyntax.of(tree, ast.Constant):
            if not isinstance(node.value, str):
                continue
            name = PlatformSigning.parameter(node.value)
            if name is not None:
                signed.setdefault(name, node)
            elif PlatformSigning.names_platform(node.value):
                names_host = True
        if names_host and len(signed) >= MINIMUM_PARAMETERS:
            first = min(signed.values(), key=lambda n: getattr(n, "lineno", 1))
            self._record(
                Capability.EGRESS,
                first,
                f"platform request signed: {len(signed)} signing parameters",
            )
