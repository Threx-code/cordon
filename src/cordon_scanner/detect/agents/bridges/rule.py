"""The catalogue entry of the remote-control rule. Built with the caller's rule factory, as the protocol rules are, so this
module imports nothing of the agent detector."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Callable


class BridgeRules:
    @staticmethod
    def rules(factory: Callable[..., Any], references: tuple[str, ...]) -> dict[str, Any]:
        entry = factory(
            "SUSPECT.AGENT.REMOTE_CONTROL.001",
            "A package drives a coding agent or a terminal and listens to a remote service, and reads an agent's history",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "The code of this package starts a coding agent or a terminal, opens a client connection to a remote host "
            "that it waits on for work, and names an agent's session history. Together they let whoever runs the remote "
            "service drive the agent or the terminal on this machine and read what the agent has done, whatever the "
            "publisher intends. A remote-control product does this on purpose; a package that does it unasked is a "
            "backdoor.",
            "Read what the remote host is and who runs it. Install the package only from an author you trust, and do not "
            "run it on a machine whose agent sessions or files you would not hand to that host.",
            references,
        )
        return {entry.rule_id: entry}
