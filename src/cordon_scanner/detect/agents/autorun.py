"""Autorun config files: the paths whose commands an editor or agent runs without anyone typing
them, and the finding for a command that is attack-shaped.

Extracted verbatim from `agents.py` (a pure refactor, no behaviour change) so the rule's own
handling can grow without that file. `agents.py` keeps a one-line `_autorun` that delegates here; the
call site and the finding are unchanged. `McpConfigs` and `RULES` are imported lazily inside the
function to avoid an import cycle (`agents` imports this module at load time).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents import agent_config

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.agents.agents import AgentChainDetector
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


def autorun_findings(
    detector: AgentChainDetector, unit: FileUnit, ctx: ScanContext
) -> Iterator[Finding]:
    """Commands an editor or agent runs when the folder is opened or the environment built."""
    from cordon_scanner.detect.agents.agents import RULES, McpConfigs

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
        if verdict is not None:
            yield detector._at_text(
                "MALWARE.AGENT.AUTORUN.001",
                unit,
                ctx,
                text,
                command.split(" ", 1)[0] if command not in text else command,
                message=RULES["MALWARE.AGENT.AUTORUN.001"].message
                + f" Here it is {where}, which {verdict.reason}.",
            )
            return
