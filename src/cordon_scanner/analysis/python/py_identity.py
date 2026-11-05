"""What says who or where this machine is, for the beacon flows (`PythonAnalyzer._is_recon_call`).

A call such as `socket.gethostname()`, a command whose whole output is the identity (`whoami`),
or the environment variable the shell keeps it in: `os.getenv("COMPUTERNAME")` is the same answer
as `platform.node()`, and stealers read it so (review 98: `gamepass` built its beacon from
`USERNAME` and `COMPUTERNAME`, which no call-shaped source saw).
"""

from __future__ import annotations

import ast
from typing import Final

IDENTITY_COMMANDS: Final = frozenset(
    {"whoami", "hostname", "id", "uname", "hostnamectl", "ipconfig", "ifconfig"}
)
"""Commands whose whole output is this machine's or this user's identity."""

IDENTITY_VARIABLES: Final = frozenset(
    {"USERNAME", "USER", "LOGNAME", "COMPUTERNAME", "HOSTNAME", "USERDOMAIN"}
)
"""Environment variables holding the user's or the machine's name."""


class IdentityVariables:
    @staticmethod
    def read(node: ast.AST, dotted: str | None) -> bool:
        """`os.getenv("USERNAME")`, `os.environ.get("USER")` or `os.environ["COMPUTERNAME"]`:
        a keyed read of a variable that names the user or the machine. `dotted` is the call's
        resolved callee, or the subscripted object's dotted name."""
        if isinstance(node, ast.Call) and dotted in ("os.getenv", "os.environ.get"):
            key = node.args[0] if node.args else None
        elif isinstance(node, ast.Subscript) and dotted in ("os.environ", "os.environb"):
            key = node.slice
        else:
            return False
        return (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.upper() in IDENTITY_VARIABLES
        )
