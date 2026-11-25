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
    from pathlib import Path
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
        store_dir: Path | None = None,
        archive: Any = None,
        cloud: Any = None,
    ) -> int:
        from cordon_scanner.cloud.agent.agent_hook import AgentCalls, AgentHook

        out, err = stdout or sys.stdout, stderr or sys.stderr
        clock = clock or datetime.now(UTC)
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
        if hook_input.get("hook_event_name") == "SessionStart":
            answer = cls._session_start(hook_input, clock, store_dir)
        elif AgentCalls.of(hook_input) is None and not cls._held_mcp_tool(hook_input, store_dir):
            answer = AgentHook.answer("allow")
        else:
            cloud = cloud or cls._cloud()
            runtime = runtime or cls._device(store_dir, clock, archive, cloud)
            if runtime is None:
                answer = AgentHook.answer("deny", cls.NO_RUNTIME)
            else:
                answer = AgentHook.respond(
                    runtime[0],
                    runtime[1],
                    hook_input,
                    clock,
                    environment=cls.ENVIRONMENT,
                    retry_online=cloud is not None,
                )
        out.write(json.dumps(answer, sort_keys=True) + "\n")
        return int(ExitCode.CLEAN)

    @staticmethod
    def _held_mcp_tool(hook_input: dict[str, Any], store_dir: Path | None) -> bool:
        """A tool call of an MCP server whose list the session start found changed: the only MCP tool call the runtime decides."""
        tool = hook_input.get("tool_name")
        if not isinstance(tool, str) or not tool.startswith("mcp__"):
            return False
        from cordon_scanner.cloud.agent.collection_status import STORE_FOLDER
        from cordon_scanner.cloud.agent.rug_pull import RugPull
        from cordon_scanner.cloud.auth import CloudAuth
        from cordon_scanner.cloud.local_store import LocalStore

        store = LocalStore(store_dir or CloudAuth.config_dir() / STORE_FOLDER)
        return RugPull.held_key(store, hook_input) is not None

    @classmethod
    def _session_start(
        cls, hook_input: dict[str, Any], clock: datetime, store_dir: Path | None
    ) -> dict[str, Any]:
        """The session start: read the approved remote servers' lists once and say which changed (the agent shows it to its user)."""
        from cordon_scanner.cloud.agent.collection_status import STORE_FOLDER
        from cordon_scanner.cloud.agent.rug_pull import RugPull
        from cordon_scanner.cloud.auth import CloudAuth
        from cordon_scanner.cloud.local_store import LocalStore

        store = LocalStore(store_dir or CloudAuth.config_dir() / STORE_FOLDER)
        found = RugPull.sweep(store, hook_input, clock)
        if not found:
            return {}
        context = RugPull.session_context(found)
        return {
            "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}
        }

    @classmethod
    def _cloud(cls) -> Any:
        """How this device asks the platform for a decision after a local denial: with the device token the MDM profile supplies,
        or not at all (a device with no token decides locally)."""
        import os

        from cordon_scanner.cloud.agent.cloud_decisions import CloudAsk

        token = os.environ.get("CORDON_DEVICE_TOKEN", "")
        return CloudAsk(token, cls.ENVIRONMENT) if token else None

    @staticmethod
    def _device(
        store_dir: Path | None, clock: datetime, archive: Any = None, cloud: Any = None
    ) -> tuple[CordonRuntime, LocalStore] | None:
        """The runtime the device store was pulled for, or None when it never was."""
        from cordon_scanner.cloud.agent.collection_status import STORE_FOLDER
        from cordon_scanner.cloud.agent.device_runtime import DeviceRuntime
        from cordon_scanner.cloud.auth import CloudAuth

        return DeviceRuntime.open(
            store_dir or CloudAuth.config_dir() / STORE_FOLDER, clock, archive, cloud
        )
