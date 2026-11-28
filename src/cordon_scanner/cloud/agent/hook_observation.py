"""What the platform learns of an agent's behaviour from the hook (BP-12-8): four fields per gated call, never what the call said.

Observed capability is counted from the hooks the device runs: which tool the agent called, the digest of what it called it on, the
decision made about it and when. Nothing else leaves the device with it: no command, argument, prompt, output, file name or path. The
records wait in the device's outbox (kind `hook-observation`) for `POST /v1/devices/observations`, like an approval request.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.cloud.runtime import Outcome

KIND = "hook-observation"


class HookObservations:
    FIELDS: ClassVar[tuple[str, ...]] = ("tool", "subject", "decision", "at")
    TOOL: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

    @classmethod
    def of(cls, hook_input: Mapping[str, Any], outcome: Outcome, clock: datetime) -> dict[str, str]:
        """The observation of one gated call: the tool's name when it is plain text, the digest of the subject it was
        decided on, the decision's id and the time."""
        tool = hook_input.get("tool_name")
        digest = outcome.resolution.artifact().digest
        return {
            "tool": tool if isinstance(tool, str) and cls.TOOL.fullmatch(tool) else "unknown",
            "subject": digest or "",
            "decision": outcome.decision.inputs_digest,
            "at": clock.isoformat(),
        }

    @classmethod
    def record(
        cls, store: LocalStore, hook_input: Mapping[str, Any], outcome: Outcome, clock: datetime
    ) -> None:
        """Queue the observation for the platform; a full outbox drops it (the store counts what it refused)."""
        body = json.dumps(
            cls.of(hook_input, outcome, clock), sort_keys=True, separators=(",", ":")
        ).encode()
        store.enqueue(KIND, body)


__all__ = ["KIND", "HookObservations"]
