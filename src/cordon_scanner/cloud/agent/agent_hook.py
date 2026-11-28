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

from cordon_scanner.cloud.agent.hook_observation import HookObservations

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.cloud.runtime import CordonRuntime, Outcome

POINT: Final = "agent_hook"
ACTOR: Final = "agent"
REQUEST_KIND: Final = "approval-request"


class Installer(NamedTuple):
    """How a package manager's command names a package to install: the command's words up to the package (a regular
    expression), the words after them that are not the package (`skip`: `helm install RELEASE CHART`), and the form of a
    flag that carries it (`--requires=`) where the package is not a plain word."""

    command: str
    skip: int = 0
    flag: str = ""
    #: The package is written inside a quoted program (`install.packages("x")`), not as a word of its own.
    embedded: bool = False


class NotInstalled(NamedTuple):
    """An ecosystem no command of which installs a package by name, and why."""

    reason: str


class AgentCall(NamedTuple):
    """One gated tool call: what it is, the resolver kind that reads its reference, and the reference."""

    what: str
    resolver: str
    reference: str


class AgentCalls:
    """Which of the four gated calls a hook input is."""

    #: Each ecosystem's commands that install a package by name (one table: S25), or why none does. The package is the word right after the
    #: command's own words (a flag first, as in `pip install -r file`, is not a package name), or the value of the flag that carries it.
    INSTALLERS: ClassVar[dict[str, tuple[Installer, ...] | NotInstalled]] = {
        "npm": (Installer(r"(?:npm|pnpm|bun)\s+(?:install|i|add)"), Installer(r"yarn\s+add")),
        "pypi": (Installer(r"pip3?\s+install"), Installer(r"uv\s+(?:pip\s+install|add)")),
        "cargo": (Installer(r"cargo\s+(?:add|install)"),),
        "gomod": (Installer(r"go\s+(?:get|install)"),),
        "rubygems": (Installer(r"gem\s+install"), Installer(r"bundle\s+add")),
        "composer": (Installer(r"composer\s+(?:global\s+)?require"),),
        "nuget": (Installer(r"dotnet\s+add\s+(?:\S+\s+)?package"), Installer(r"nuget\s+install")),
        "pub": (Installer(r"(?:dart|flutter)\s+pub\s+add"),),
        "hex": (Installer(r"mix\s+(?:archive|escript)\.install\s+hex"),),
        "maven": (Installer(r"mvn\s+dependency:get", flag="-Dartifact"),),
        "gradle": NotInstalled(
            "Gradle has no command that adds a dependency: they are written into build.gradle or the version catalog"
        ),
        "conda": (Installer(r"(?:conda|mamba|micromamba)\s+install"),),
        "homebrew": (Installer(r"brew\s+install"),),
        "image": (Installer(r"(?:docker|podman)\s+(?:pull|run)"),),
        "helm": (
            Installer(r"helm\s+(?:pull|show\s+chart)"),
            Installer(r"helm\s+(?:install|upgrade\s+--install)", skip=1),
        ),
        "ansible": (Installer(r"ansible-galaxy\s+(?:collection\s+|role\s+)?install"),),
        "nix": (
            Installer(r"nix\s+profile\s+install"),
            Installer(r"nix-env\s+(?:-i|-iA|--install)"),
        ),
        "swift": (Installer(r"swift\s+package\s+add-dependency"),),
        "vcpkg": (Installer(r"vcpkg\s+(?:install|add\s+port)"),),
        "conan": (Installer(r"conan\s+install", flag="--requires"),),
        "cran": (Installer(r"(?:Rscript|R)\s+-e\s+['\"]install\.packages\(['\"]", embedded=True),),
        "hackage": (Installer(r"(?:cabal\s+(?:v2-)?|stack\s+)install"),),
        "julia": (Installer(r"julia\s+-e\s+['\"]using\s+Pkg;\s*Pkg\.add\(['\"]", embedded=True),),
        "opam": (Installer(r"opam\s+install"),),
        "vscode": (Installer(r"(?:code|codium|cursor|windsurf)\s+--install-extension"),),
        "cocoapods": NotInstalled(
            "CocoaPods adds a pod by editing the Podfile; `pod install` takes no package name"
        ),
        "terraform": NotInstalled(
            "Terraform has no command that adds a provider or module: they are declared in .tf files and fetched by `terraform init`"
        ),
        "actions": NotInstalled(
            "no command installs a GitHub Action: a workflow file names it and the runner fetches it"
        ),
        "bazel": NotInstalled(
            "Bazel has no command that adds a module: they are declared in MODULE.bazel (`bazel mod` only reads the graph)"
        ),
    }
    #: The compiled forms of `INSTALLERS`, in table order: (ecosystem, pattern).
    INSTALL: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = ()
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
        for ecosystem, pattern in cls.INSTALL:
            installed = pattern.match(text)
            if installed:
                return AgentCall("install", "package", f"{ecosystem}:{installed.group('spec')}")
        return AgentCall("run_command", "command", text)


class InstallPatterns:
    """`AgentCalls.INSTALLERS`, each command as a regular expression that reads the package out of it."""

    WORD: Final = r"[^\s'\"-][^\s'\"]{0,200}"

    @classmethod
    def compiled(cls) -> tuple[tuple[str, re.Pattern[str]], ...]:
        out: list[tuple[str, re.Pattern[str]]] = []
        for ecosystem, installers in AgentCalls.INSTALLERS.items():
            if isinstance(installers, NotInstalled):
                continue
            for installer in installers:
                if installer.flag:
                    tail = rf"(?:\s+-\S+)*\s+{re.escape(installer.flag)}[=\s](?P<spec>{cls.WORD})"
                elif installer.embedded:
                    tail = rf"(?P<spec>{cls.WORD})"
                else:
                    tail = rf"(?:\s+[^\s-]\S*){{{installer.skip}}}\s+(?P<spec>{cls.WORD})"
                out.append((ecosystem, re.compile(rf"^\s*{installer.command}{tail}")))
        return tuple(out)


AgentCalls.INSTALL = InstallPatterns.compiled()


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
        from cordon_scanner.cloud.agent.rug_pull import RugPull

        call = AgentCalls.of(hook_input)
        if call is None and (held := RugPull.held_key(store, hook_input)) is not None:
            call = AgentCall("use_mcp_tool", "mcp_tool", held)
        if call is None:
            return cls.answer("allow")
        outcome = cls._ask(runtime, call, clock, environment, scope_path, online=False)
        if outcome.decision.state in cls.DENIED and retry_online:
            outcome = cls._ask(runtime, call, clock, environment, scope_path, online=True)
        decision = outcome.decision
        HookObservations.record(store, hook_input, outcome, clock)
        if decision.state not in cls.DENIED:
            return cls.answer("allow")
        codes = ", ".join(decision.reason_codes)
        message = f"Cordon denied this {call.what.replace('_', ' ')}: {decision.explanation.summary} ({codes})."
        if call.what == "use_mcp_tool":
            changed = RugPull.record(store, call.reference)
            message += (
                f" Its tools changed since they were approved ({RugPull.describe(changed)})."
                if changed
                else ""
            )
        if call.what == "add_mcp" or decision.state == "REVIEW":
            request = ApprovalRequests.create(store, outcome, call, clock, approver)
            message += (
                f" An approval request was created for {approver}; ticket {request['ticket']}."
            )
        return cls.answer("deny", message)


__all__ = ["ACTOR", "POINT", "AgentCall", "AgentCalls", "AgentHook", "ApprovalRequests"]
