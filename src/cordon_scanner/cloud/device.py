"""`cordon agent`: what AI agents and MCP servers a developer's machine has configured.

Deployed by an organisation through MDM (Jamf, Intune, Kandji) and disclosed to employees. It
reads a fixed list of known configuration paths under the user's home directory -- the agent and
MCP configs of Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI and Codex, the
VS Code extension list, and the registry each package manager points at -- and nothing else. It
does not walk the disk, read source code, or read any file outside that list.

From what it reads it sends two things: an inventory (which tools, which MCP servers and how they
are launched or reached, which extensions, which registries) and the agent-chain findings on those
files. Never file contents, never a credential: inline secrets are reported by rule and location
with their value withheld, and package-manager configs contribute only the registry host.

`cordon agent inventory` prints exactly the payload `cordon agent report` would send.
"""

from __future__ import annotations

import configparser
import hmac
import json
import os
import platform
import re
import socket
import sys
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.transport import CloudTransport, Transport
from cordon_scanner.core.evidence_key import EvidenceKey
from cordon_scanner.version import __version__

SCHEMA: Final = "cordon.device-inventory/v1"
MAX_FILE_BYTES: Final = 2 << 20
MAX_EXTENSIONS: Final = 2000


@dataclass(frozen=True)
class Source:
    tool: str
    path: Path
    logical: str
    """The name the agent-chain rules match, and the only path that leaves the machine."""
    kind: str
    """`instructions`, `settings`, `mcp`, `claude-json`, `codex-toml`, `npmrc`, `pip`."""


class DeviceInventory:
    """A developer machine's agent and editor inventory, reported to the cloud."""

    @staticmethod
    def _app_support(home: Path) -> Path:
        if sys.platform == "darwin":
            return home / "Library" / "Application Support"
        if sys.platform.startswith("win"):
            return Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        return Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")

    @staticmethod
    def sources(home: Path | None = None) -> list[Source]:
        """Every path this command may read. The list is the whole of what it touches."""
        home = home or Path.home()
        support = DeviceInventory._app_support(home)
        found = [
            Source(
                "claude-code",
                home / ".claude" / "settings.json",
                "home/.claude/settings.json",
                "settings",
            ),
            Source(
                "claude-code",
                home / ".claude" / "settings.local.json",
                "home/.claude/settings.local.json",
                "settings",
            ),
            Source(
                "claude-code",
                home / ".claude" / "CLAUDE.md",
                "home/.claude/CLAUDE.md",
                "instructions",
            ),
            Source("claude-code", home / ".claude.json", "home/.claude.json", "claude-json"),
            Source(
                "claude-desktop",
                support / "Claude" / "claude_desktop_config.json",
                "home/claude_desktop_config.json",
                "mcp",
            ),
            Source("cursor", home / ".cursor" / "mcp.json", "home/.cursor/mcp.json", "mcp"),
            Source(
                "windsurf",
                home / ".codeium" / "windsurf" / "mcp_config.json",
                "home/.windsurf/mcp.json",
                "mcp",
            ),
            Source(
                "gemini-cli",
                home / ".gemini" / "settings.json",
                "home/.gemini/settings.json",
                "mcp",
            ),
            Source(
                "gemini-cli",
                home / ".gemini" / "GEMINI.md",
                "home/.gemini/GEMINI.md",
                "instructions",
            ),
            Source(
                "vscode",
                support / "Code" / "User" / "settings.json",
                "home/.vscode/settings.json",
                "settings",
            ),
            Source(
                "vscode", support / "Code" / "User" / "mcp.json", "home/.vscode/mcp.json", "mcp"
            ),
            Source(
                "codex", home / ".codex" / "config.toml", "home/.codex/config.toml", "codex-toml"
            ),
            Source("codex", home / ".codex" / "AGENTS.md", "home/.codex/AGENTS.md", "instructions"),
            Source("npm", home / ".npmrc", "home/.npmrc", "npmrc"),
            Source("pip", support / "pip" / "pip.conf", "home/pip.conf", "pip"),
            Source("pip", home / ".pip" / "pip.conf", "home/.pip/pip.conf", "pip"),
        ]
        for directory, logical in (
            (home / ".claude" / "agents", "agents"),
            (home / ".claude" / "commands", "commands"),
        ):
            if directory.is_dir():
                found += [
                    Source("claude-code", p, f"home/.claude/{logical}/{p.name}", "instructions")
                    for p in sorted(directory.glob("*.md"))[:200]
                ]
        skills = home / ".claude" / "skills"
        if skills.is_dir():
            found += [
                Source(
                    "claude-code",
                    p,
                    f"home/.claude/skills/{p.parent.name}/SKILL.md",
                    "instructions",
                )
                for p in sorted(skills.glob("*/SKILL.md"))[:200]
            ]
        return found

    @staticmethod
    def _read(path: Path) -> bytes | None:
        try:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                return None
            return path.read_bytes()
        except OSError:
            return None

    @staticmethod
    def _host(url: str) -> str:
        parsed = urllib.parse.urlsplit(url.strip())
        return f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else ""

    @staticmethod
    def _mcp_entries(tool: str, logical: str, servers: Any) -> list[dict[str, Any]]:
        from cordon_scanner.detect.agents import McpConfigs

        entries: list[dict[str, Any]] = []
        for name, server in servers.items() if isinstance(servers, dict) else ():
            if not isinstance(server, dict):
                continue
            url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
            entry: dict[str, Any] = {"tool": tool, "config": logical, "name": str(name)}
            if isinstance(url, str):
                entry.update(transport="http", endpoint=DeviceInventory._host(url))
            elif isinstance(server.get("command"), str):
                args = [
                    str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))
                ]
                launched = McpConfigs.launched_package(server["command"], args)
                entry.update(transport="stdio", command=Path(server["command"]).name)
                if launched is not None:
                    entry.update(ecosystem=launched[0], package=launched[1], pinned=launched[2])
            entries.append(entry)
        return entries

    @staticmethod
    def _registry_of(source: Source, raw: bytes) -> dict[str, Any] | None:
        """Only the registry host. Tokens in these files are never read into the payload."""
        text = raw.decode("utf-8", "replace")
        if source.kind == "npmrc":
            match = re.search(r"^\s*registry\s*=\s*(\S+)", text, re.MULTILINE)
            return {
                "manager": "npm",
                "registry": DeviceInventory._host(match.group(1))
                if match
                else "https://registry.npmjs.org",
            }
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except configparser.Error:
            return None
        index = parser.get("global", "index-url", fallback="") or parser.get(
            "install", "index-url", fallback=""
        )
        return {
            "manager": "pip",
            "registry": DeviceInventory._host(index) if index else "https://pypi.org",
        }

    @staticmethod
    def _extensions(home: Path) -> list[str]:
        directory = home / ".vscode" / "extensions"
        if not directory.is_dir():
            return []
        names = sorted(
            p.name for p in directory.iterdir() if p.is_dir() and not p.name.startswith(".")
        )
        return names[:MAX_EXTENSIONS]

    @staticmethod
    def _logical_mcp(servers: dict[str, Any]) -> bytes:
        return json.dumps({"mcpServers": servers}).encode()

    @staticmethod
    def collect(home: Path | None = None) -> dict[str, Any]:
        """The payload: device, inventory and findings. Nothing else leaves the machine."""
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.agents import AgentChainDetector
        from cordon_scanner.detect.base import FileUnit, ScanContext
        from cordon_scanner.rules.loader import RuleSet

        home = home or Path.home()
        tools: set[str] = set()
        mcp: list[dict[str, Any]] = []
        registries: list[dict[str, Any]] = []
        files: list[tuple[str, bytes]] = []
        read: list[str] = []
        for source in DeviceInventory.sources(home):
            raw = DeviceInventory._read(source.path)
            if raw is None:
                continue
            tools.add(source.tool)
            read.append(source.logical)
            if source.kind in ("npmrc", "pip"):
                registry = DeviceInventory._registry_of(source, raw)
                if registry:
                    registries.append(registry)
                continue
            if source.kind == "claude-json":
                try:
                    document = json.loads(raw)
                except ValueError:
                    continue
                servers = (
                    dict(document.get("mcpServers") or {}) if isinstance(document, dict) else {}
                )
                for project in (
                    (document.get("projects") or {}).values() if isinstance(document, dict) else ()
                ):
                    if isinstance(project, dict):
                        servers.update(project.get("mcpServers") or {})
                mcp += DeviceInventory._mcp_entries(source.tool, source.logical, servers)
                files.append(("home/.claude/.mcp.json", DeviceInventory._logical_mcp(servers)))
                continue
            if source.kind == "codex-toml":
                try:
                    servers = tomllib.loads(raw.decode("utf-8", "replace")).get("mcp_servers") or {}
                except tomllib.TOMLDecodeError:
                    continue
                mcp += DeviceInventory._mcp_entries(source.tool, source.logical, servers)
                files.append(("home/.codex/.mcp.json", DeviceInventory._logical_mcp(servers)))
                continue
            if source.kind == "mcp":
                try:
                    document = json.loads(raw)
                    servers = (
                        (document.get("mcpServers") or document.get("servers") or {})
                        if isinstance(document, dict)
                        else {}
                    )
                except ValueError:
                    servers = {}
                mcp += DeviceInventory._mcp_entries(source.tool, source.logical, servers)
            files.append((source.logical, raw))
        extensions = DeviceInventory._extensions(home)
        if extensions:
            tools.add("vscode")

        config = Config.default()
        context = ScanContext(config=config, rules=RuleSet(()), offline=True)
        detector = AgentChainDetector()
        findings: list[dict[str, Any]] = []
        for logical, raw in files:
            unit = FileUnit(content=FileContent(path=logical, raw=raw, size=len(raw)))
            for finding in detector.inspect(unit, context):
                findings.append(
                    {
                        "rule_id": finding.rule_id,
                        "severity": str(finding.severity),
                        "category": str(finding.category),
                        "path": finding.location.path,
                        "line": finding.location.line,
                        "message": finding.message,
                        "fingerprint": finding.fingerprint,
                    }
                )
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
        return {
            "schema": SCHEMA,
            "agent_version": __version__,
            "device": {
                "hostname": socket.gethostname(),
                "os": f"{platform.system()} {platform.release()}",
                # Keyed with this install's secret: an unkeyed hash of a known hostname and a
                # short user name is the user name, to anyone who tries the likely ones.
                "user": hmac.new(
                    EvidenceKey.key(), b"device-user\0" + user.encode(), "sha256"
                ).hexdigest()[:16],
                # Stable for this install and unforgeable without its key; what the cloud binds the
                # device record to, so one laptop's token cannot overwrite another laptop's report.
                "install_id": hmac.new(
                    EvidenceKey.key(), b"device-install-id", "sha256"
                ).hexdigest()[:32],
            },
            "read": sorted(read),
            "inventory": {
                "tools": sorted(tools),
                "mcp_servers": mcp,
                "extensions": extensions,
                "registries": registries,
            },
            "findings": findings,
        }

    @staticmethod
    def report(
        payload: dict[str, Any],
        *,
        url: str | None = None,
        token: str | None = None,
        transport: Transport | None = None,
    ) -> str:
        """Send the payload with the organisation's device token. Returns the cloud's receipt id."""
        device_token = token or os.environ.get("CORDON_DEVICE_TOKEN", "")
        if not device_token:
            raise CloudError("CORDON_DEVICE_TOKEN is not set; the MDM profile supplies it")
        response = CloudTransport.request(
            "POST",
            f"{CloudEndpoint.base_url(url)}/v1/devices/inventory",
            json_body=payload,
            token=device_token,
            transport=transport,
        )
        if response.status not in (200, 201, 202):
            raise CloudError(f"the inventory was refused ({CloudTransport.error_text(response)})")
        return str(response.body.get("receipt", ""))


__all__ = ["SCHEMA", "DeviceInventory", "Source"]
