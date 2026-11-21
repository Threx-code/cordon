"""What the machine holds, sent to a destination the code hides (group A (a), 2026-11-10;
reviews/pypi-98/19-GROUP-A-DESIGN.md).

The analysis layer marks a send whose URL argument derives from a decode, a reversed literal or a
string built from character codes with ` dest=decoded` on its fact (`identity sent: <sink>
dest=decoded`, and the environment and secret facts the same way). A package's own service, a
vendor's telemetry, a CI notifier: each names its host, because nothing is gained by hiding it.
Hiding the host of a request that carries the machine's identity, environment or a credential is
concealment with exfiltration, and it is graded as that wherever the code runs -- on import, as a
command, or only when a function is called. That is why `MALWARE.EXFIL.HIDDEN_DESTINATION.002` is
not one of `CompositeRuleIds.ON_REQUEST_RULES`: a routine an attacker writes is not one a caller
asks for (tsshare's `_b64.b64decode(_E)` base URL, sent only from a method).
"""

from __future__ import annotations

from typing import ClassVar


class HiddenDestination:
    """The second fact a send to a hidden destination raises beside the send itself."""

    FACT: ClassVar[str] = "AST.PY.SENT_TO_HIDDEN_HOST"
    RULE: ClassVar[str] = "MALWARE.EXFIL.HIDDEN_DESTINATION.002"
    #: The send facts whose payload is something the machine holds.
    SENT: ClassVar[tuple[str, ...]] = ("identity sent", "environment sent", "secret sent")
    MARK: ClassVar[str] = "dest=decoded"

    @classmethod
    def applies(cls, detail: str) -> bool:
        """A send of identity, environment or a secret whose destination the code hides."""
        return detail.startswith(cls.SENT) and cls.MARK in detail.split()


__all__ = ["HiddenDestination"]
