"""Which lines of a YAML file run something (reviews/pypi-98/26).

A pattern for a destructive command matches a list item or a mapping value as a command line, which is
right for a CI step or a compose command. A YAML file that is data (a red-team tool's payload list, an
attack catalogue) names such a line as text it carries. The line is a command when a key above it runs
things (`run`, `script`, `command`, `shell`, ...), when the file's own top-level keys say it is a workflow,
a compose file, a playbook or a manifest, or when it sits under no key at all. Anything else is data."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.detect.code.capability.hits import CapabilityHit
    from cordon_scanner.foundation.content import FileContent

_KEY: Final = re.compile(r"""^[ \t]*(?:-[ \t]+)*(?P<key>[A-Za-z_][\w.-]{0,60})[ \t]*:(?:[ \t]|$)""")
_FLOW_KEY: Final = re.compile(r"""[{,][ \t]*(?P<key>[A-Za-z_][\w.-]{0,60})[ \t]*:""")


class YamlCommands:
    COMMAND_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"run", "runs", "script", "scripts", "command", "commands", "cmd", "shell", "entrypoint",
         "args", "exec", "before_script", "after_script", "install", "postinstall", "preinstall",
         "pre", "post", "execstart", "execstop", "execstartpre", "execstartpost", "runcmd",
         "bootcmd", "user_data", "userdata", "hooks", "lifecycle", "healthcheck", "init",
         "setup", "build", "test", "deploy", "start", "stop", "up", "down", "clean"}
    )  # fmt: skip
    """Keys whose value a runner executes."""
    LIVE_TOP_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"jobs", "steps", "services", "stages", "pipelines", "tasks", "hosts", "containers",
         "spec", "runcmd", "resources", "on", "before_script", "after_script", "script", "scripts",
         "pipeline", "workflows", "inputs", "runs"}
    )  # fmt: skip
    """Top-level keys of a file that is itself something a tool runs."""

    @staticmethod
    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip(" \t"))

    @staticmethod
    def runs(text: str, line: int) -> bool:
        """Whether line `line` (1-based) of a YAML file is, or could be, run as a command."""
        lines = text.splitlines()
        if not 1 <= line <= len(lines):
            return True
        for raw in lines:
            top = _KEY.match(raw) if raw and not raw[0].isspace() else None
            if top is not None and top.group("key").lower() in YamlCommands.LIVE_TOP_KEYS:
                return True
        target = lines[line - 1]
        keys: list[str] = []
        own = _KEY.match(target)
        if own is not None:
            keys.append(own.group("key").lower())
        keys.extend(m.group("key").lower() for m in _FLOW_KEY.finditer(target))
        indent = YamlCommands._indent(target)
        for at in range(line - 2, -1, -1):
            if indent == 0:
                break
            above = lines[at]
            if not above.strip() or above.lstrip().startswith("#"):
                continue
            level = YamlCommands._indent(above)
            if level < indent:
                found = _KEY.match(above)
                if found is not None:
                    keys.append(found.group("key").lower())
                indent = level
        if not keys:
            return True  # under no key at all: nothing says it is data
        return any(key in YamlCommands.COMMAND_KEYS for key in keys)

    @staticmethod
    def drop(content: FileContent, hits: list[CapabilityHit]) -> list[CapabilityHit]:
        """The destroy hits that sit in data in a YAML file, dropped; every other hit kept."""
        from cordon_scanner.foundation.capabilities import Capability

        if not any(h.capability is Capability.DESTROY for h in hits):
            return hits
        text = content.text
        return [
            h
            for h in hits
            if h.capability is not Capability.DESTROY or YamlCommands.runs(text, h.line)
        ]
