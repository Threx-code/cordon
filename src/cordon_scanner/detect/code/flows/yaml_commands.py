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

_NAME: Final = re.compile(r"[A-Za-z_][\w.-]{0,60}")
_FLOW_KEY: Final = re.compile(r"""[{,][ \t]*(?P<key>[A-Za-z_][\w.-]{0,60})[ \t]*:""")


class YamlCommands:
    COMMAND_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"run", "runs", "script", "scripts", "command", "commands", "cmd", "cmds", "entry", "steps", "post_install", "pre_install", "post-install", "pre-install", "postinstall", "shell", "entrypoint",
         "exec", "before_script", "after_script", "install", "preinstall",
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
    def key_of(line: str) -> str | None:
        """The mapping key a line opens (after any list dashes), or None. Read in code: a pattern
        for leading blanks then dashes then blanks repeats the same characters."""
        at, size = 0, len(line)
        while at < size and line[at] in " \t":
            at += 1
        while at < size and line[at] == "-" and at + 1 < size and line[at + 1] in " \t":
            at += 1
            while at < size and line[at] in " \t":
                at += 1
        name = _NAME.match(line, at)
        if name is None:
            return None
        at = name.end()
        while at < size and line[at] in " \t":
            at += 1
        if at >= size or line[at] != ":":
            return None
        if at + 1 < size and line[at + 1] not in " \t":
            return None
        return name.group(0)

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
            top = YamlCommands.key_of(raw) if raw and not raw[0].isspace() else None
            if top is not None and top.lower() in YamlCommands.LIVE_TOP_KEYS:
                return True
        target = lines[line - 1]
        keys: list[str] = []
        own = YamlCommands.key_of(target)
        if own is not None:
            keys.append(own.lower())
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
                found = YamlCommands.key_of(above)
                if found is not None:
                    keys.append(found.lower())
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
