"""A keychain item read by name and sent only to the service that issued it.

The Claude Code usage dashboards are the case (review 98, CDI): `cctop`, `overcode`,
`claude-statuskit` and `onecmd` run `security find-generic-password -s "Claude Code-credentials"
-w` to get the OAuth token the CLI stored, and send it to `api.anthropic.com` to read the
account's usage. `SUSPECT.EXFIL.CREDENTIAL_STORE.001` reads that as "a credential store is read
and the file reaches the network", which is what it is, and its remediation asks the reader to
confirm the component owns the store. A token handed back to its issuer is what a token is for.

## What this may and may not do

It answers one question about one Python file -- is every credential-store read in it one named
keychain item, and does everything the file names as a destination belong to one issuer? -- and
the only thing the answer may change is the suspect grade of the credential-store rule. The
install-time grade is never lowered: no build needs a keychain item.

Each condition fails closed. A store read that is not a literal `security find-*-password -s`
argv (a browser database, a keychain dump, the `-g` form that prints every attribute), a URL
host outside the issuer's domains, no literal destination at all, or a decode anywhere in the
file leaves the finding as it was. Stealing that same token and posting it to a webhook is the
attack this rule exists for, and it names a host the issuer does not own.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.detect.code.capability.hits import CapabilityHit
    from cordon_scanner.foundation.content import FileContent

#: Domains of one issuer. A file must name hosts from exactly one group.
ISSUERS: tuple[frozenset[str], ...] = (
    frozenset({"anthropic.com", "claude.ai", "claude.com"}),
    frozenset({"googleapis.com", "google.com"}),
    frozenset({"github.com", "githubusercontent.com"}),
)
_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})
_URL_HOST = re.compile(r"https?://([a-z0-9.-]{1,253})", re.IGNORECASE)
_LOOKUPS = frozenset({"find-generic-password", "find-internet-password"})


class KeychainOwner:
    @staticmethod
    def _named_lookups(tree: ast.AST) -> list[tuple[int, int]] | None:
        """Line spans of every `security find-*-password` argv, or None if one is not a named,
        single-item lookup. A call that takes the argv directly (`subprocess.run([...])`) spans
        from its own first line: that is where the store read is reported."""
        spans: list[tuple[int, int]] = []
        argvs: set[int] = set()
        for node in PythonSyntax.nodes(tree):
            if not isinstance(node, ast.List | ast.Tuple):
                continue
            words = [e.value for e in node.elts if isinstance(e, ast.Constant)]
            if not any(isinstance(w, str) and w in _LOOKUPS for w in words):
                continue
            flags = {w for w in words if isinstance(w, str) and w.startswith("-")}
            if "-s" not in flags or any(f.startswith("-g") for f in flags):
                return None
            argvs.add(id(node))
            spans.append((node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno))
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Call) and any(id(a) in argvs for a in node.args):
                spans.append((node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno))
        return spans

    @staticmethod
    def _issuer(tree: ast.AST) -> frozenset[str] | None:
        """The one issuer every literal URL in the file belongs to, or None."""
        found: set[frozenset[str]] = set()
        for node in PythonSyntax.nodes(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            for match in _URL_HOST.finditer(node.value):
                host = match.group(1).lower().rstrip(".")
                if host in _LOCAL:
                    continue
                group = next(
                    (g for g in ISSUERS if any(host == d or host.endswith("." + d) for d in g)),
                    None,
                )
                if group is None:
                    return None
                found.add(group)
        return next(iter(found)) if len(found) == 1 else None

    @classmethod
    def sent_to_its_issuer(cls, path: str, text: str, store_lines: set[int], decodes: bool) -> bool:
        """Whether every credential-store read on `store_lines` is a named keychain lookup and
        the file sends to no one but that item's issuer."""
        if decodes or not store_lines or not path.endswith(".py"):
            return False
        try:
            tree = PythonSyntax.shared(text)
        except (SyntaxError, ValueError, RecursionError):
            return False
        spans = cls._named_lookups(tree)
        if not spans:
            return False
        # A docstring naming the command is not a read; a line no lookup covers is another store.
        docs = {
            line
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1)
        }
        covered = all(
            line in docs or any(start <= line <= end for start, end in spans)
            for line in store_lines
        )
        return covered and cls._issuer(tree) is not None

    @classmethod
    def excuses(
        cls, content: FileContent, window: Sequence[CapabilityHit], hits: Sequence[CapabilityHit]
    ) -> bool:
        """`sent_to_its_issuer` for a credential-store composite's window: the store reads are the
        window's, and a decode anywhere in the file (`hits`) is enough to leave it as it was."""
        stores = {h.line for h in window if h.rule_id == "CAP.CREDENTIAL.STORE.001"}
        decodes = any(h.capability in (Capability.DECODE, Capability.DECOMPRESS) for h in hits)
        return cls.sent_to_its_issuer(content.path, content.text, stores, decodes)
