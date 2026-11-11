"""What says who or where this machine is, for the beacon flows (`PythonAnalyzer._is_recon_call`).

A call such as `socket.gethostname()`, a command whose whole output is the identity (`whoami`),
or the environment variable the shell keeps it in: `os.getenv("COMPUTERNAME")` is the same answer
as `platform.node()`, and stealers read it so (review 98: `gamepass` built its beacon from
`USERNAME` and `COMPUTERNAME`, which no call-shaped source saw).
"""

from __future__ import annotations

import ast
import re
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


IP_LOOKUP_HOSTS: Final = frozenset(
    {
        "api.ipify.org",
        "api64.ipify.org",
        "api.ip.sb",
        "ipinfo.io",
        "ifconfig.me",
        "icanhazip.com",
        "ip-api.com",
        "checkip.amazonaws.com",
        "ipecho.net",
        "ident.me",
        "wtfismyip.com",
        "api.myip.com",
        "ipapi.co",
        "geolocation-db.com",
    }
)
"""Services whose whole answer is the caller's public address."""

_URL_HOST: Final = re.compile(r"^https?://([^/:?#\s]+)", re.I)


class IpLookup:
    @staticmethod
    def names(url: str | None) -> bool:
        """The URL's host is a public-address lookup service: the reply is this machine's
        address, which is identity the same way `socket.gethostname()` is."""
        match = _URL_HOST.match(url or "")
        if match is None:
            return False
        host = match.group(1).lower()
        return any(host == known or host.endswith("." + known) for known in IP_LOOKUP_HOSTS)

    @staticmethod
    def in_command(command: str) -> bool:
        """A command line that fetches a lookup service's page: `curl -s https://ifconfig.me`."""
        return any(
            IpLookup.names(url) for url in re.findall(r"https?://[^\s\"']+", command)
        ) or any(
            re.search(r"(^|\s)" + re.escape(host) + r"(/|\s|$)", command)
            for host in IP_LOOKUP_HOSTS
        )

    @staticmethod
    def drop_destination(call: ast.Call) -> bool:
        """The request's first literal URL is a drop host (webhook, paste site, tunnel) or a bare
        address: where a collector sends, not where a client's API lives."""
        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        for argument in (*call.args, *(k.value for k in call.keywords)):
            for part in ast.walk(argument):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    text = part.value if "://" in part.value else f"http://{part.value}"
                    host, kind = JsFlow.classify(text)
                    if host is not None and "." in host:
                        return kind in ("drop", "ip")
        return False
