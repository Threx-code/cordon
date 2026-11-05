"""The agent tools: content an agent is about to use -- a file's text, agent instruction files,
skills, MCP servers and the tools they serve, and editor extensions."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from cordon_scanner.mcp.extensions import ExtensionError, ExtensionFetcher
from cordon_scanner.mcp.packages import (
    InstallCommand,
    PackageError,
)
from cordon_scanner.mcp.results import Results, ScanSummary
from cordon_scanner.mcp.runner import CancelToken
from cordon_scanner.mcp.tools.base import (
    MAX_CONTENT,
    MAX_FILES,
    Args,
    Outcome,
    Scans,
    Settings,
    ToolError,
)
from cordon_scanner.mcp.tools.machine import MachineTools
from cordon_scanner.mcp.tools.packages import PackageTools
from cordon_scanner.mcp.untrusted import Untrusted


class AgentTools:
    CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "command",
            "args",
            "env",
            "url",
            "type",
            "headers",
            "cwd",
            "transport",
            "serverUrl",
            "httpUrl",
            "disabled",
            "timeout",
        }
    )

    @staticmethod
    def scan_file_content(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = str(Args.relative(Args.text(args, "filename", required=True, limit=255) or ""))
        content = Args.content(args)
        hidden = Untrusted.hidden_count(content)
        summary = Scans.files(
            settings,
            {name: content},
            token,
            args,
            {"filename": name, "bytes": len(content.encode())},
        )
        if hidden:
            summary.notes.append(
                f"the content holds {hidden} invisible or direction-changing character(s)"
            )
        return Scans.outcome(summary)

    @staticmethod
    def check_agent_file(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = str(Args.relative(Args.text(args, "path", required=True, limit=255) or ""))
        return Scans.outcome(
            Scans.files(settings, {name: Args.content(args)}, token, args, {"agent_file": name})
        )

    @staticmethod
    def check_skill(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = Args.text(args, "name", required=True, limit=100) or ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
            raise ToolError("name must be a skill directory name: letters, digits, '.', '_' or '-'")
        files = args.get("files")
        if not isinstance(files, dict) or not files:
            raise ToolError("files must map each file's path inside the skill to its content")
        if len(files) > MAX_FILES:
            raise ToolError(f"at most {MAX_FILES} files per skill")
        total = 0
        tree: dict[str, str] = {}
        for relative, content in files.items():
            if not isinstance(content, str):
                raise ToolError(f"{relative}: content must be a string")
            total += len(content)
            if total > 8 * MAX_CONTENT:
                raise ToolError("the skill's files are larger than 16 MB together")
            tree[f".claude/skills/{name}/{Args.relative(str(relative))}"] = content
        if not any(PurePosixPath(k).name == "SKILL.md" for k in tree):
            raise ToolError("a skill needs its SKILL.md among the files")
        return Scans.outcome(
            Scans.files(settings, tree, token, args, {"skill": name, "files": sorted(files)})
        )

    @staticmethod
    def check_mcp_server(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        name = Args.text(args, "name", required=True, limit=100) or ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@/-]{0,99}", name):
            raise ToolError(
                "name must be the server's key: letters, digits, '.', '_', '@', '/' or '-'"
            )
        config = args.get("config")
        remote = isinstance(config, dict) and any(
            config.get(k) for k in ("url", "serverUrl", "httpUrl")
        )
        if not isinstance(config, dict) or not (config.get("command") or remote):
            raise ToolError("config is the server's entry: a command (with args) or a url")
        unknown = set(config) - AgentTools.CONFIG_KEYS
        if unknown:
            raise ToolError(f"unrecognised config keys: {', '.join(sorted(unknown))}")
        body = json.dumps({"mcpServers": {name: config}}, indent=2)
        if len(body) > MAX_CONTENT:
            raise ToolError("config is larger than 2 MB")
        parts = [
            Scans.files(
                settings, {".mcp.json": body}, token, args, {"mcp_server": name}, online=online
            )
        ]
        words = [str(config.get("command") or "")]
        words += [str(a) for a in config.get("args") or [] if isinstance(a, str | int | float)]
        launch = " ".join(words).strip()
        notes: list[str] = []
        if launch and config.get("command"):
            try:
                parsed = InstallCommand.parse(launch)
            except PackageError:
                parsed = None
            if parsed and parsed.packages:
                parts.append(
                    PackageTools.check(
                        settings,
                        parsed.packages,
                        token,
                        online=online,
                        max_findings=Args.max_findings(settings, args),
                        subject={"launches": [s.label for s in parsed.packages]},
                    )
                )
                notes.append("launches " + ", ".join(s.label for s in parsed.packages))
                if any(not s.version for s in parsed.packages):
                    notes.append(
                        "the launched package is not pinned to a version: every start can run a different release"
                    )
        image = AgentTools.container_image(config)
        if image is not None:
            notes.append(f"launches the container image {image}")
            if not re.search(r"@sha256:[0-9a-f]{64}$", image) and not re.search(
                r":(?!latest$)[^/:@]+$", image
            ):
                notes.append(
                    "the image is not pinned to a tag or digest: every start can run a different image"
                )
            if online:
                try:
                    parts.append(
                        Scans.scan(
                            settings,
                            MachineTools.image_purl(image),
                            token,
                            online=True,
                            severity=Args.severity(args),
                            max_findings=Args.max_findings(settings, args),
                            subject={"image": image},
                            cache=False,
                        )
                    )
                except ToolError as exc:
                    notes.append(f"the image was not scanned: {exc}")
                    parts.append(ScanSummary("incomplete", "image not scanned", {}, [], 0, False))
            else:
                notes.append(
                    "the image itself is only pulled and scanned online (--allow-online and online)"
                )
        if remote and not online:
            notes.append(
                "a remote server: what it serves now is only read online (--allow-online and online)"
            )
        merged = Results.merge(
            parts,
            max_findings=Args.max_findings(settings, args),
            subject={"mcp_server": name, "launch": launch[:300]},
        )
        merged.notes = list(dict.fromkeys(notes + merged.notes))
        return Scans.outcome(merged)

    #: `docker`/`podman`/`nerdctl` options that take a value, so the value is not the image.
    CONTAINER_VALUED: ClassVar[frozenset[str]] = frozenset(
        {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "--name",
         "--network", "--net", "-u", "--user", "-w", "--workdir", "--entrypoint", "--platform",
         "-l", "--label", "--pull", "--add-host", "--cap-add", "--cap-drop", "--memory", "-m",
         "--cpus", "--restart", "--hostname", "-h", "--device", "--security-opt", "--tmpfs"}
    )  # fmt: skip

    @staticmethod
    def container_image(config: dict[str, Any]) -> str | None:
        """The image a `docker run` (or podman, nerdctl) launch starts, or None."""
        command = PurePosixPath(str(config.get("command") or "")).name.removesuffix(".exe")
        if command not in {"docker", "podman", "nerdctl"}:
            return None
        words = [str(a) for a in config.get("args") or [] if isinstance(a, str | int | float)]
        if "run" not in words:
            return None
        rest = words[words.index("run") + 1 :]
        skip = False
        for word in rest:
            if skip:
                skip = False
                continue
            if word.startswith("-"):
                skip = word in AgentTools.CONTAINER_VALUED and "=" not in word
                continue
            return word if MachineTools.IMAGE.match(word) else None
        return None

    @staticmethod
    def check_mcp_tools(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        from cordon_scanner.detect.agents.mcp_servers.source import McpServerSource

        tools = args.get("tools")
        if not isinstance(tools, list) or not tools or len(tools) > 1000:
            raise ToolError(
                "tools must be a list of 1 to 1000 tool definitions, as tools/list returns them"
            )
        findings: list[dict[str, Any]] = []
        for entry in tools:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ToolError("each tool needs at least a name")
            texts: list[tuple[str, str]] = [("description", str(entry.get("description") or ""))]
            schema = entry.get("inputSchema")
            if isinstance(schema, dict):
                texts += AgentTools.schema_descriptions(schema, "inputSchema")
            for where, text in texts:
                if not text:
                    continue
                if len(text) > MAX_CONTENT:
                    raise ToolError(f"{entry['name']}: a description is longer than 2 MB")
                reason = McpServerSource._poisoned_description(text)
                if reason:
                    tool = Untrusted.text(entry["name"], 100)
                    findings.append(
                        {
                            "rule_id": "SUSPECT.AGENT.MCP_TOOL_POISONING.001",
                            "severity": "high",
                            "confidence": "high",
                            "category": "suspicious",
                            "path": Untrusted.text(f"{entry['name']}:{where}", 300),
                            "message": f"Tool {tool!r} {reason} in its {where}: a description that steers "
                            "the agent rather than describing the tool (tool poisoning).",
                            "remediation": "Do not add this server, or remove the tool, until its description is fixed.",
                        }
                    )
        counts = {"critical": 0, "high": len(findings), "medium": 0, "low": 0, "info": 0}
        summary = ScanSummary(
            "block" if findings else "pass",
            f"{len(findings)} poisoned description(s) in {len(tools)} tool(s)"
            if findings
            else f"{len(tools)} tool description(s), none steering the agent",
            counts,
            findings[: Args.max_findings(settings, args)],
            len(findings),
            True,
            ["checked with the test the scanner applies to every MCP server it reads"],
            {"server": Untrusted.text(args.get("server") or "", 200)},
        )
        return Scans.outcome(summary)

    @staticmethod
    def schema_descriptions(
        schema: dict[str, Any], where: str, depth: int = 0
    ) -> list[tuple[str, str]]:
        """Every description inside a tool's input schema: parameter descriptions steer agents too."""
        if depth > 8:
            return []
        out: list[tuple[str, str]] = []
        if isinstance(schema.get("description"), str) and depth:
            out.append((where, schema["description"]))
        for key in ("properties", "$defs", "definitions"):
            children = schema.get(key)
            if isinstance(children, dict):
                for child, sub in list(children.items())[:500]:
                    if isinstance(sub, dict):
                        out += AgentTools.schema_descriptions(sub, f"{where}.{child}", depth + 1)
        items = schema.get("items")
        if isinstance(items, dict):
            out += AgentTools.schema_descriptions(items, f"{where}[]", depth + 1)
        return out

    @staticmethod
    def check_ide_extension(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        path_arg = Args.text(args, "path")
        identifier = Args.text(args, "id", limit=260)
        if bool(path_arg) == bool(identifier):
            raise ToolError(
                "give either path (a .vsix in the workspace) or id (publisher.name), not both"
            )
        if path_arg:
            target = Args.path(settings, args)
            if not target.is_file():
                raise ToolError("path must be a .vsix file")
            return Scans.outcome(
                Scans.scan(
                    settings,
                    str(target),
                    token,
                    online=False,
                    severity=Args.severity(args),
                    max_findings=Args.max_findings(settings, args),
                    subject={"extension": target.name},
                )
            )
        if not settings.allow_online:
            raise ToolError(
                "fetching an extension by id needs the server started with --allow-online; or give the path to a .vsix"
            )
        registry = args.get("registry", "open-vsx")
        if registry not in ("open-vsx", "vscode-marketplace"):
            raise ToolError("registry must be open-vsx or vscode-marketplace")
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-ext-") as work:
            try:
                fetch = (
                    ExtensionFetcher.open_vsx
                    if registry == "open-vsx"
                    else ExtensionFetcher.marketplace
                )
                fetched = fetch(identifier or "", Args.text(args, "version", limit=64), Path(work))
            except ExtensionError as exc:
                raise ToolError(str(exc)) from exc
            summary = Scans.scan(
                settings,
                str(fetched.path),
                token,
                online=True,
                severity=Args.severity(args),
                max_findings=Args.max_findings(settings, args),
                subject={
                    "extension": fetched.identifier,
                    "version": fetched.version,
                    "registry": fetched.registry,
                },
                cache=False,
                notes=[f"integrity: {fetched.integrity}"],
            )
        return Scans.outcome(summary)
