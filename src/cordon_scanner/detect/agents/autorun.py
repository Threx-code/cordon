"""Autorun config files: the paths whose commands an editor or agent runs without anyone typing
them, and the finding for a command that is attack-shaped.

Extracted from the agent chain detector (`chain.py`) so the rule's own handling can grow without that
file. `chain.py` keeps a one-line `_autorun` that delegates to `Autorun.autorun_findings`; the call
site and the finding are unchanged. `McpConfigs` and `RULES` are imported lazily inside the method, as
they were when one module held them and imported this one at load time.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents import agent_config
from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.agents.chain import AgentChainDetector
    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.foundation.models import Finding

AUTORUN_PATHS: Final = (
    "**/.vscode/tasks.json",
    "**/.devcontainer/devcontainer.json",
    "**/.devcontainer.json",
    "**/.devcontainer/*/devcontainer.json",
    "**/.cursor/environment.json",
)
"""Files whose commands an editor or agent runs without anyone typing them: VS Code tasks set to
run when the folder opens, dev-container lifecycle commands (`initializeCommand` on the host
itself), and the install and start steps of Cursor's background-agent environment."""

_LIFECYCLE: Final = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)


class Autorun:
    """The autorun rules and the finding for an attack-shaped autorun command. Stateless."""

    @staticmethod
    def build_rules(rule: Callable[..., Any]) -> dict[str, Any]:
        """The autorun rules, built with the caller's rule factory (agents.py passes
        AgentRules._rule after its classes exist, so this module needs no AgentRule import)."""
        return {
            "MALWARE.AGENT.AUTORUN.001": rule(
                "MALWARE.AGENT.AUTORUN.001",
                "A command an editor or agent runs on its own attacks the machine",
                Category.MALICIOUS,
                Severity.CRITICAL,
                Confidence.HIGH,
                "A command this repository configures to run without anyone typing it -- a "
                "settings helper the agent calls, a task that starts when the folder opens, a "
                "dev-container lifecycle command, an agent environment's install step -- downloads "
                "and runs code, sends credentials away, or opens a remote shell.",
                "Remove the command and treat the repository as untrusted.",
                (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.CLAUDE_CODE_SETTINGS),
            ),
            "SUSPECT.CI.DEVCONTAINER_FETCH.001": rule(
                "SUSPECT.CI.DEVCONTAINER_FETCH.001",
                "A published package's dev-container fetches and runs code when a developer opens it",
                Category.SUSPICIOUS,
                Severity.LOW,
                Confidence.HIGH,
                "A published package ships an editor task or dev-container lifecycle command that "
                "downloads and runs code when a developer opens the repository. That is off the "
                "path a consumer who installs the package ever runs, so it is a hardening concern "
                "rather than package malware -- but review it before opening in a dev container.",
                "Pin or vendor the fetched installer, and review before opening in a dev container.",
                (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
            ),
        }

    @staticmethod
    def autorun_findings(
        detector: AgentChainDetector, unit: FileUnit, ctx: ScanContext
    ) -> Iterator[Finding]:
        """Commands an editor or agent runs when the folder is opened or the environment built."""
        from cordon_scanner.detect.agents.mcp.configs import McpConfigs
        from cordon_scanner.detect.agents.rule_catalogue import RULES

        document = McpConfigs._json(unit.content)
        if not isinstance(document, dict):
            return
        text = unit.content.text
        commands: list[tuple[str, str]] = []
        for task in document.get("tasks") or ():
            if not isinstance(task, dict):
                continue
            options = task.get("runOptions")
            if isinstance(options, dict) and options.get("runOn") == "folderOpen":
                command = task.get("command")
                arguments = [str(a) for a in task.get("args") or () if isinstance(a, str)]
                if isinstance(command, str):
                    commands.append(
                        ("a task that runs when the folder opens", " ".join([command, *arguments]))
                    )
        for key in _LIFECYCLE:
            commands.extend(
                (f"the dev container's `{key}`", c)
                for c in McpConfigs._command_strings(document.get(key))
            )
        for key in ("install", "start"):
            commands.extend(
                (f"the agent environment's `{key}`", c)
                for c in McpConfigs._command_strings(document.get(key))
            )
        for terminal in document.get("terminals") or ():
            if isinstance(terminal, dict):
                commands.extend(
                    ("an agent environment terminal", c)
                    for c in McpConfigs._command_strings(terminal.get("command"))
                )
        for where, command in commands:
            verdict = agent_config.CommandClassifier.classify(command)
            if verdict is None:
                continue
            rule_id = "MALWARE.AGENT.AUTORUN.001"
            # A published package's editor/dev-container config is off the path a consumer who
            # installs the package ever runs: a fetch-run there runs for a developer who opens the
            # repository, not on an install. That is a hardening concern (recorded LOW), not package
            # malware. Secret or environment egress and reverse shells stay critical -- they attack
            # whoever opens it either way. A repo, skill or agent unit is unchanged.
            if ctx.package_distribution and verdict.kind == "fetch-exec":
                rule_id = "SUSPECT.CI.DEVCONTAINER_FETCH.001"
            yield detector._at_text(
                rule_id,
                unit,
                ctx,
                text,
                command.split(" ", 1)[0] if command not in text else command,
                message=RULES[rule_id].message + f" Here it is {where}, which {verdict.reason}.",
            )
            return
