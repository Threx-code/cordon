"""The pre-tool hook of a coding agent, asking the shared decision runtime.

A coding agent calls its pre-tool hook before it installs a package, adds an MCP server, loads a skill or runs a command. `AgentCalls.of` reads which of the four a hook input is (anything else is
not gated); `AgentHook.respond` asks `CordonRuntime.run` at the point `agent_hook` with the actor `agent` and answers in the agent's own format (Claude Code's `PreToolUse` output): allow, or
deny with the reason the agent shows its user. A denied MCP add, and any call the policy sends to review, also creates an approval request in the device's outbox, and the denial names the
approver and the request's ticket. The request holds ids and codes only: no command text, no name, no argument.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, ClassVar, Final, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.cloud.runtime import CordonRuntime, Outcome

POINT: Final = "agent_hook"
ACTOR: Final = "agent"
REQUEST_KIND: Final = "approval-request"


class AgentCall(NamedTuple):
    """One gated tool call: what it is, the resolver kind that reads its reference, and the reference."""

    what: str
    resolver: str
    reference: str


class AgentCalls:
    """Which of the four gated calls a hook input is."""

    INSTALL: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:(?P<npm>(?:npm|pnpm|bun)\s+(?:install|i|add)|yarn\s+add)|(?P<pypi>pip3?\s+install|uv\s+(?:pip\s+install|add)))\s+(?P<spec>[^\s-][^\s]{0,200})"
    )
    MCP_ADD: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*claude\s+mcp\s+add\b(?P<rest>.{0,2000})$", re.S
    )
    COMMAND_LIMIT: ClassVar[int] = 4000

    @classmethod
    def of(cls, hook_input: Mapping[str, Any]) -> AgentCall | None:
        """The gated call this hook input is, or None for a tool call that is not gated."""
        tool, arguments = hook_input.get("tool_name"), hook_input.get("tool_input")
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            return None
        if tool == "Skill":
            name = arguments.get("skill") or arguments.get("name")
            return (
                AgentCall("load_skill", "skill", str(name))
                if isinstance(name, str) and name
                else None
            )
        if tool != "Bash":
            return None
        command = arguments.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        text = command[: cls.COMMAND_LIMIT]
        added = cls.MCP_ADD.match(text)
        if added:
            return AgentCall("add_mcp", "mcp_server", added.group("rest").strip())
        installed = cls.INSTALL.match(text)
        if installed:
            ecosystem = "npm" if installed.group("npm") else "pypi"
            return AgentCall("install", "package", f"{ecosystem}:{installed.group('spec')}")
        return AgentCall("run_command", "command", text)


class ApprovalRequests:
    """The approval request a denied call creates, queued for the control plane through the device's outbox."""

    @staticmethod
    def of(outcome: Outcome, call: AgentCall, clock: datetime, approver: str) -> dict[str, Any]:
        decision = outcome.decision
        ticket = (
            "AR-" + hashlib.sha256(f"{decision.inputs_digest}\0{POINT}".encode()).hexdigest()[:12]
        )
        return {
            "ticket": ticket,
            "what": call.what,
            "point": POINT,
            "actor": ACTOR,
            "state": decision.state,
            "reason_codes": list(decision.reason_codes),
            "decision": decision.inputs_digest,
            "approver": approver,
            "requested_at": clock.isoformat(),
        }

    @classmethod
    def create(
        cls, store: LocalStore, outcome: Outcome, call: AgentCall, clock: datetime, approver: str
    ) -> dict[str, Any]:
        """The request, queued once (the same decision queues the same request)."""
        request = cls.of(outcome, call, clock, approver)
        store.enqueue(
            REQUEST_KIND, json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        )
        return request


class AgentHook:
    """The answer a pre-tool hook gives its agent."""

    @staticmethod
    def _ask(
        runtime: CordonRuntime,
        call: AgentCall,
        clock: datetime,
        environment: str,
        scope_path: tuple[str, ...],
        *,
        online: bool,
    ) -> Outcome:
        return runtime.run(
            call.resolver,
            call.reference,
            POINT,
            clock,
            environment=environment,
            scope_path=scope_path,
            actor=ACTOR,
            online=online,
        )

    DENIED: ClassVar[tuple[str, ...]] = ("BLOCK", "REVIEW")

    @staticmethod
    def answer(permission: str, reason: str = "") -> dict[str, Any]:
        """Claude Code's `PreToolUse` output: `allow`, or `deny` with the reason the agent shows."""
        body: dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": permission}
        if reason:
            body["permissionDecisionReason"] = reason
        return {"hookSpecificOutput": body}

    @classmethod
    def respond(
        cls,
        runtime: CordonRuntime,
        store: LocalStore,
        hook_input: Mapping[str, Any],
        clock: datetime,
        *,
        environment: str,
        scope_path: tuple[str, ...] = (),
        approver: str = "your approver",
        retry_online: bool = False,
    ) -> dict[str, Any]:
        """The agent's answer. With `retry_online`, a denial is asked once more of the platform (the runtime's cloud source), so
        an approval given since is seen: the retry of an approved call decides ALLOW (R901)."""
        call = AgentCalls.of(hook_input)
        if call is None:
            return cls.answer("allow")
        outcome = cls._ask(runtime, call, clock, environment, scope_path, online=False)
        if outcome.decision.state in cls.DENIED and retry_online:
            outcome = cls._ask(runtime, call, clock, environment, scope_path, online=True)
        decision = outcome.decision
        if decision.state not in cls.DENIED:
            return cls.answer("allow")
        codes = ", ".join(decision.reason_codes)
        message = f"Cordon denied this {call.what.replace('_', ' ')}: {decision.explanation.summary} ({codes})."
        if call.what == "add_mcp" or decision.state == "REVIEW":
            request = ApprovalRequests.create(store, outcome, call, clock, approver)
            message += (
                f" An approval request was created for {approver}; ticket {request['ticket']}."
            )
        return cls.answer("deny", message)


__all__ = ["ACTOR", "POINT", "AgentCall", "AgentCalls", "AgentHook", "ApprovalRequests"]
