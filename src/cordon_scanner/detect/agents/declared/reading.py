"""The capabilities an MCP server or a skill declares, read from its configuration and its code (BP-12-7).

Four names, the ones a policy restricts and an inventory shows: `network`, `shell`, `filesystem` and `environment`. A capability is declared
when the server's configuration says so (a remote URL, a shell as the program, an `env` block, a filesystem path or the filesystem server) or
its code uses it (an import or call of the language's own network, process, file or environment interface), and for a skill when its
`allowed-tools` list names the tool that grants it, or a script it ships uses it. The reading is of files given to it and runs nothing.

It is a declaration, not a verdict: a server that declares `shell` is one that can start a process, which a policy may allow or not. A word
in a comment counts as a use (the reading does not parse), so the answer errs toward declaring more."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, ClassVar, Final

from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs

NETWORK: Final = "network"
SHELL: Final = "shell"
FILESYSTEM: Final = "filesystem"
ENVIRONMENT: Final = "environment"


class DeclaredCapabilities:
    NAMES: ClassVar[tuple[str, ...]] = (NETWORK, SHELL, FILESYSTEM, ENVIRONMENT)
    MAX_BYTES: ClassVar[int] = 1 << 20
    MAX_FILES: ClassVar[int] = 400
    PROGRAMS: ClassVar[dict[str, frozenset[str]]] = {
        SHELL: frozenset({"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}),
    }
    FILESYSTEM_SERVERS: ClassVar[re.Pattern[str]] = re.compile(r"(?i)server-filesystem|mcp-filesystem|filesystem-mcp")
    PATH_ARGUMENT: ClassVar[re.Pattern[str]] = re.compile(r"^(?:/|~/|\.\./|[A-Za-z]:[\\/])")
    CODE: ClassVar[dict[str, dict[str, re.Pattern[str]]]] = {
        "python": {
            NETWORK: re.compile(r"\b(?:requests|httpx|aiohttp|urllib\.request|http\.client|websockets)\b|\bsocket\.(?:socket|create_connection)\b"),
            SHELL: re.compile(r"\bsubprocess\b|\bos\.(?:system|popen|exec[lv]p?e?)\b|\bpty\.spawn\b"),
            FILESYSTEM: re.compile(r"\bopen\s*\(|\bpathlib\b|\bshutil\.|\bos\.(?:listdir|remove|unlink|walk|rename|makedirs|scandir)\b"),
            ENVIRONMENT: re.compile(r"\bos\.(?:environ|getenv)\b|\bdotenv\b"),
        },
        "javascript": {
            NETWORK: re.compile(r"\bfetch\s*\(|\baxios\b|\bnode-fetch\b|\bXMLHttpRequest\b|\bWebSocket\b|\brequire\s*\(\s*['\"](?:node:)?https?['\"]|\bfrom\s+['\"](?:node:)?https?['\"]|\bnet\.(?:connect|createConnection)\b"),
            SHELL: re.compile(r"\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bexecFile\b|\bexeca\b"),
            FILESYSTEM: re.compile(r"\bfs\.\w+|\brequire\s*\(\s*['\"](?:node:)?fs(?:/promises)?['\"]|\bfrom\s+['\"](?:node:)?fs(?:/promises)?['\"]|\bDeno\.(?:readFile|writeFile|readTextFile|writeTextFile)\b"),
            ENVIRONMENT: re.compile(r"\bprocess\.env\b|\bDeno\.env\b"),
        },
    }
    SUFFIXES: ClassVar[dict[str, str]] = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "javascript",
        ".mts": "javascript",
        ".tsx": "javascript",
        ".jsx": "javascript",
    }
    #: A tool an `allowed-tools` list names, and what it grants (`mcp__...` is a remote server: network).
    TOOLS: ClassVar[dict[str, str]] = {
        "bash": SHELL,
        "shell": SHELL,
        "powershell": SHELL,
        "webfetch": NETWORK,
        "websearch": NETWORK,
        "read": FILESYSTEM,
        "write": FILESYSTEM,
        "edit": FILESYSTEM,
        "multiedit": FILESYSTEM,
        "glob": FILESYSTEM,
        "grep": FILESYSTEM,
        "notebookedit": FILESYSTEM,
    }
    TOOL_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,60}")

    @classmethod
    def of_files(cls, files: Mapping[str, str]) -> frozenset[str]:
        """The capabilities declared across the files of one server or skill (path to text): its configuration, its code, its SKILL.md."""
        found: set[str] = set()
        for path in sorted(files)[: cls.MAX_FILES]:
            text = files[path][: cls.MAX_BYTES]
            name = path.rsplit("/", 1)[-1]
            if name == "SKILL.md":
                found |= cls.of_skill(text)
            elif name.endswith(".json") or name.endswith((".toml", ".yaml", ".yml")):
                found |= cls.of_config(path, text)
            found |= cls.of_code(path, text)
        return frozenset(found)

    @classmethod
    def of_config(cls, path: str, text: str) -> frozenset[str]:
        """What the servers an MCP configuration file declares can do, by their declaration alone."""
        found: set[str] = set()
        for _name, server in McpConfigs.mcp_servers(path, text):
            found |= cls.of_server(server)
        return frozenset(found)

    @classmethod
    def of_server(cls, server: Mapping[str, Any]) -> frozenset[str]:
        found: set[str] = set()
        if any(isinstance(server.get(key), str) and server[key].strip() for key in ("url", "serverUrl", "httpUrl")):
            found.add(NETWORK)
        command = server.get("command")
        args = [a for a in server.get("args", []) if isinstance(a, str)] if isinstance(server.get("args"), list) else []
        program = command.replace("\\", "/").rsplit("/", 1)[-1].lower() if isinstance(command, str) else ""
        if program in cls.PROGRAMS[SHELL]:
            found.add(SHELL)
        env = server.get("env")
        if isinstance(env, Mapping) and env:
            found.add(ENVIRONMENT)
        words = [program, *args]
        if any(cls.FILESYSTEM_SERVERS.search(w) for w in words) or any(cls.PATH_ARGUMENT.match(a) for a in args):
            found.add(FILESYSTEM)
        return frozenset(found)

    @classmethod
    def of_code(cls, path: str, text: str) -> frozenset[str]:
        """What a source file uses: the capabilities whose interface it imports or calls. A file of another language declares none."""
        suffix = path[path.rfind(".") :].lower() if "." in path.rsplit("/", 1)[-1] else ""
        language = cls.SUFFIXES.get(suffix)
        if language is None:
            return frozenset()
        return frozenset(name for name, pattern in cls.CODE[language].items() if pattern.search(text[: cls.MAX_BYTES]))

    @classmethod
    def of_skill(cls, text: str) -> frozenset[str]:
        """What a SKILL.md grants by its `allowed-tools`: the tools named in its front matter."""
        if not text.startswith("---"):
            return frozenset()
        head = text[3 : text.find("\n---", 3)] if "\n---" in text[3:] else ""
        found: set[str] = set()
        for line in head.splitlines()[:200]:
            key, _, value = line.partition(":")
            if key.strip() not in ("allowed-tools", "allowed_tools"):
                continue
            for word in cls.TOOL_NAME.findall(value[:2000]):
                lowered = word.lower()
                if lowered.startswith("mcp__"):
                    found.add(NETWORK)
                elif lowered in cls.TOOLS:
                    found.add(cls.TOOLS[lowered])
        return frozenset(found)

    @staticmethod
    def as_json(found: frozenset[str]) -> str:
        """The declaration as an inventory writes it: the names, sorted."""
        return json.dumps(sorted(found))


__all__ = ["ENVIRONMENT", "FILESYSTEM", "NETWORK", "SHELL", "DeclaredCapabilities"]
