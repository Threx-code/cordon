"""`agent hook`: the pre-tool hook an agent runs, asking the decision runtime.

The agent gives its `PreToolUse` input as JSON on standard input; the answer is printed in the agent's own form (`allow`, or
`deny` with the reason the agent shows its user). A call that is not one of the four gated calls is allowed without a question.
It fails closed: input that is not a JSON object is refused (exit 2, which the agent reads as a block), and a gated call on a
device with no decision runtime is denied with the way to get one, never allowed for want of an answer.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ExitCode

if TYPE_CHECKING:
    import argparse
    from typing import TextIO

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.cloud.runtime import CordonRuntime


class AgentHookCommand:
    ENVIRONMENT = "workstation"
    NO_RUNTIME = (
        "Cordon has no decision runtime on this device, so it cannot clear this call: "
        "run `cordon-scanner policy pull` to fetch the policy bundle."
    )

    @classmethod
    def run(
        cls,
        args: argparse.Namespace,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
        runtime: tuple[CordonRuntime, LocalStore] | None = None,
        clock: datetime | None = None,
    ) -> int:
        from cordon_scanner.cloud.agent.agent_hook import AgentCalls, AgentHook

        out, err = stdout or sys.stdout, stderr or sys.stderr
        try:
            hook_input: Any = json.loads((stdin or sys.stdin).read())
            if not isinstance(hook_input, dict):
                raise ValueError("the hook input is not a JSON object")
        except ValueError as problem:
            err.write(f"cordon-scanner agent hook: unreadable input, call refused ({problem})\n")
            out.write(
                json.dumps(
                    AgentHook.answer("deny", "Cordon could not read this call."), sort_keys=True
                )
                + "\n"
            )
            return 2
        if AgentCalls.of(hook_input) is None:
            answer = AgentHook.answer("allow")
        elif runtime is None:
            answer = AgentHook.answer("deny", cls.NO_RUNTIME)
        else:
            answer = AgentHook.respond(
                runtime[0],
                runtime[1],
                hook_input,
                clock or datetime.now(UTC),
                environment=cls.ENVIRONMENT,
            )
        out.write(json.dumps(answer, sort_keys=True) + "\n")
        return int(ExitCode.CLEAN)
