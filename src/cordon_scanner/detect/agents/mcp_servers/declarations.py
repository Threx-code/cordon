"""MCP server declarations in every agent's configuration dialect, and what they launch."""

from __future__ import annotations

import re
import tomllib
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.detect.agents.paths import MCP_PATHS
from cordon_scanner.foundation.formats import jsonc
from cordon_scanner.foundation.formats.scanned_json import ScannedJson

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


# -- A3: MCP launch commands -----------------------------------------------------------------
_RUNNERS: Final = {
    "npx": "npm",
    "bunx": "npm",
    "pnpx": "npm",
    "uvx": "pypi",
    "pipx": "pypi",
}

_DLX_RUNNERS: Final = {
    ("pnpm", "dlx"): "npm",
    ("yarn", "dlx"): "npm",
    ("pipx", "run"): "pypi",
    ("uv", "tool"): "pypi",
}


class McpConfigs:
    """MCP server declarations in every agent's configuration dialect, and what they launch."""

    PATHS: ClassVar[tuple[str, ...]] = MCP_PATHS
    """The files an agent reads its MCP servers from (`agents.paths.MCP_PATHS`): where to look for
    the declarations `mcp_servers` reads."""

    @staticmethod
    def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
        """`@scope/pkg@1.2.3` to (`@scope/pkg`, `1.2.3`); a floating spec gets version None."""
        if ecosystem == "npm":
            head, _, version = (
                spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
            )
            name = "@" + head if spec.startswith("@") else head
            exact = re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", version)
            return name, version if exact else None
        match = re.fullmatch(r"([\w.\-]+)(?:\[[^\]]*\])?(?:==|@)(\d[\w.\-+]*)", spec)
        if match:
            return match.group(1), match.group(2)
        return re.split(r"[\[=@<>~!]", spec, maxsplit=1)[0], None

    @staticmethod
    def launched_package(command: str, args: list[str]) -> tuple[str, str, bool] | None:
        """The (ecosystem, package spec, pinned) an MCP launch command downloads, if it does."""
        runner = command.rsplit("/", 1)[-1].lower().removesuffix(".cmd").removesuffix(".exe")
        rest = list(args)
        ecosystem = _RUNNERS.get(runner)
        if ecosystem is None and rest:
            ecosystem = _DLX_RUNNERS.get((runner, rest[0].lower()))
            if ecosystem is not None:
                rest = rest[1:]
                if runner == "uv" and rest and rest[0] == "run":
                    rest = rest[1:]
        if ecosystem is None:
            return None
        package = None
        skip_next = False
        for arg in rest:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-p", "--package", "--from", "--python", "--with"):
                if arg in ("-p", "--package", "--from"):
                    skip_next = False
                    continue
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            package = arg
            break
        if not package:
            return None
        if ecosystem == "npm":
            name, _, version = (
                package[1:].partition("@") if package.startswith("@") else package.partition("@")
            )
            if package.startswith("@"):
                name = "@" + name
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", version))
        else:
            match = re.fullmatch(r"([\w.\-\[\],]+?)(?:==|@)(\d[\w.\-+]*)", package)
            pinned = match is not None
        return ecosystem, package, pinned

    @staticmethod
    def mcp_servers(path: str, text: str) -> list[tuple[str, dict[str, Any]]]:
        """Every MCP server a configuration declares, as `(name, {command, args, url, env, ...})`.

        The agents disagree on the shape. Claude, Cursor, Gemini, Cline, Kiro and Amazon Q write
        `mcpServers: {name: {command, args}}`; VS Code writes `servers`; Zed writes `context_servers`
        with the launch under `command: {path, args}`; opencode writes `mcp` with `command` as one
        list; Codex writes TOML `[mcp_servers.name]`; Continue writes YAML with `mcpServers` as a
        list. A server missed for its dialect is a server never checked.
        """
        member = path.rpartition("!")[2]
        if member.endswith(".toml"):
            try:
                document: Any = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, ValueError):
                return []
            servers: Any = document.get("mcp_servers") if isinstance(document, dict) else None
        elif member.endswith((".yaml", ".yml")) or "/.continue/mcpServers/" in f"/{member}":
            return McpConfigs._continue_servers(text)
        else:
            document = McpConfigs._json_text(text)
            if not isinstance(document, dict):
                return []
            servers = (
                document.get("mcpServers")
                or document.get("servers")
                or document.get("context_servers")
                or document.get("mcp")
            )
        if not isinstance(servers, dict):
            return []
        out: list[tuple[str, dict[str, Any]]] = []
        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            server = dict(server)
            command = server.get("command")
            if isinstance(command, dict):  # Zed: command: {path, args, env}
                server["args"] = command.get("args") or server.get("args")
                server["env"] = command.get("env") or server.get("env")
                server["command"] = command.get("path")
            elif isinstance(command, list) and command:  # opencode: command: ["npx", "-y", "pkg"]
                server["command"], server["args"] = str(command[0]), [str(a) for a in command[1:]]
            if "environment" in server and "env" not in server:
                server["env"] = server["environment"]
            out.append((str(name), server))
        return out

    @staticmethod
    def _continue_servers(text: str) -> list[tuple[str, dict[str, Any]]]:
        """Continue's `mcpServers:` list, read for the four keys that matter without a YAML library:
        each `- name:` starts a server; `args` is a flow list or the block list beneath it."""
        servers: list[dict[str, Any]] = []
        in_block = False
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.match(r"^\s*mcpServers\s*:", line):
                in_block = True
                continue
            if not in_block:
                continue
            env_start = re.match(r"^(\s*)-?\s*env\s*:\s*$", line)
            if env_start is not None and servers:
                indent = len(env_start.group(1))
                env: dict[str, str] = {}
                for following in lines[index + 1 :]:
                    pair = re.match(r"^(\s+)([A-Za-z_][\w]*)\s*:\s*(.*?)\s*$", following)
                    if pair is None or len(pair.group(1)) <= indent:
                        break
                    env[pair.group(2)] = pair.group(3).strip("'\"")
                servers[-1]["env"] = env
                continue
            match = _YAML_KEY.match(line)
            if match is None:
                continue
            key, value = match.group(1), match.group(2).strip().strip("'\"")
            if (line.lstrip().startswith("-") and key == "name") or not servers:
                servers.append({})
            current = servers[-1]
            if key == "args":
                if value.startswith("["):
                    current["args"] = [
                        a.strip().strip("'\"") for a in value.strip("[]").split(",") if a.strip()
                    ]
                else:
                    items = []
                    for following in lines[index + 1 :]:
                        item = _YAML_ITEM.match(following)
                        if item is None or _YAML_KEY.match(following):
                            break
                        items.append(item.group(1).strip("'\""))
                    current["args"] = items
            else:
                current[key] = value
        return [
            (str(s.get("name", "server")), s) for s in servers if s.get("command") or s.get("url")
        ]

    @staticmethod
    def _json_text(text: str) -> Any:
        try:
            return ScannedJson.loads(text)
        except ValueError:
            pass
        stripped = re.sub(
            r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*[\s\S]*?\*/', lambda m: m.group(1) or "", text
        )
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            return ScannedJson.loads(stripped)
        except ValueError:
            return None

    @staticmethod
    def _command_strings(value: Any) -> list[str]:
        """A command field in any of the shapes the dev-container and agent-environment schemas allow:
        a string, an argument list, or an object of named commands."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [" ".join(str(a) for a in value)] if value else []
        if isinstance(value, dict):
            return [c for v in value.values() for c in McpConfigs._command_strings(v)]
        return []

    @staticmethod
    def _hook_commands(hooks: dict[str, Any]) -> list[str]:
        commands: list[str] = []
        for entries in hooks.values():
            for entry in entries if isinstance(entries, list) else ():
                if not isinstance(entry, dict):
                    continue
                for hook in entry.get("hooks") or ():
                    if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                        commands.append(hook["command"])
                if isinstance(entry.get("command"), str):
                    commands.append(entry["command"])
        return commands

    @staticmethod
    def _json(content: FileContent) -> Any:
        # JSON with comments and trailing commas (VS Code config, dev containers): the shared helper.
        return jsonc.Jsonc.loads(content.text)


# Both are matched against every line of an MCP config an attacker may write, so neither may be
# quadratic in a line (review 98, 27-PERFORMANCE). The indentation is possessive (`\s*+`: what it gave
# back the dash cannot take and the next `\s*` would), and a value is "up to its last non-blank" rather
# than a lazy `(.*?)` re-tried against `\s*$` at every length -- the same groups, found once.
_YAML_KEY: Final = re.compile(r"^\s*+-?\s*(name|command|url|args)\s*:\s*((?:.*\S)?)\s*$")
_YAML_ITEM: Final = re.compile(r"^\s*-\s+(.*\S|[^\S\n])\s*$")
r"""One `- item` of a block list. The `[^\S\n]` branch keeps the lazy `(.+?)` form's one odd answer:
a dash followed by blanks only captures one blank."""


__all__ = ["McpConfigs"]
