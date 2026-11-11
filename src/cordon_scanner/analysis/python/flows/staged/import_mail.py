"""Mail sent the moment a module is imported, from an account whose password the module carries.

Coffin2022 7.0 and Coffin-Codes-2022 7.2 (a websocket TCP tunnel, `bsb`): `tunnel_tcp.py` opens
`smtplib.SMTP_SSL(<host>, <port>)` at module level, logs in with a user and password written in the
source, and sends a fixed message to a fixed address; once a tunnel is up it mails the public port
it was given to the same address. Importing the module announces the install to the author's
mailbox, and every tunnel tells them where the user's machine can be reached.

`mail sent on import: <call>`: at module level (not under `if __name__ == "__main__"`), a
`sendmail` or `send_message` on a name the module binds to `smtplib.SMTP`/`SMTP_SSL`/`LMTP`, where
the module also calls `login` on it with literal arguments.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.foundation.capabilities import Capability


class ImportMail(AnalyzerCore):
    """`_import_mail` and what it needs."""

    CLIENTS: ClassVar[frozenset[str]] = frozenset(
        {"smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.LMTP"}
    )
    SENDS: ClassVar[frozenset[str]] = frozenset({"sendmail", "send_message"})

    def _import_mail(self, tree: ast.AST) -> None:
        body = getattr(tree, "body", [])
        clients = {
            s.targets[0].id
            for s in body
            if isinstance(s, ast.Assign)
            and len(s.targets) == 1
            and isinstance(s.targets[0], ast.Name)
            and isinstance(s.value, ast.Call)
            and (self._dotted(s.value.func) or "") in self.CLIENTS
        }
        if not clients:
            return
        calls = [
            (s.value, s.value.func)
            for s in body
            if isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Call)
            and isinstance(s.value.func, ast.Attribute)
            and isinstance(s.value.func.value, ast.Name)
            and s.value.func.value.id in clients
        ]
        logged_in = {
            func.value.id  # type: ignore[attr-defined]
            for call, func in calls
            if func.attr == "login"
            and call.args
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in call.args)
        }
        for call, func in calls:
            if func.attr in self.SENDS and func.value.id in logged_in:  # type: ignore[attr-defined]
                self._record(Capability.EGRESS, call, f"mail sent on import: smtplib.{func.attr}")
                return


__all__ = ["ImportMail"]
