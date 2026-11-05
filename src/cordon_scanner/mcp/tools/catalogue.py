"""The tools Cordon's MCP server offers, and what each one runs.

Every tool reads. None installs, executes what it reads, writes into a workspace root or changes any
configuration; all of them are annotated read-only and non-destructive. Tools that reach a registry
or a remote server are annotated open-world and need the server started with `--allow-online`;
tools that read beyond the workspace (the machine's own agents, the host's packages) need
`--allow-machine`. Each tool runs the scanner's own code -- most by running the scanner in a child
process (`runner`), a few by calling the same function the scanner calls -- so an agent gets the
verdict the CLI, CI and the editor would give.

    base.py       Tool, Settings, Outcome; Args (argument checking) and Scans (running the scanner
                  and shaping what it returns), shared by every tool
    packages.py   PackageTools: packages, lists of packages, install commands, advisories
    workspace.py  WorkspaceTools: paths in the workspace: scans, secrets, graphs, bills of
                  materials, reviews
    agents.py     AgentTools: content an agent is about to use: files, skills, MCP servers,
                  extensions
    machine.py    MachineTools: container images and this machine
    knowledge.py  KnowledgeTools: rules and intel
    catalogue.py  Catalogue: the tool definitions, in a fixed order; ServerStatus, which lists them
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

from cordon_scanner.mcp.packages import (
    ECOSYSTEMS,
)
from cordon_scanner.mcp.results import SCAN_OUTPUT
from cordon_scanner.mcp.runner import CancelToken, TimedOut
from cordon_scanner.mcp.tools.agents import AgentTools
from cordon_scanner.mcp.tools.base import (
    MAX_PACKAGES,
    SEVERITY_ENUM,
    Outcome,
    Scans,
    Settings,
    Tool,
)
from cordon_scanner.mcp.tools.knowledge import KnowledgeTools
from cordon_scanner.mcp.tools.machine import MachineTools
from cordon_scanner.mcp.tools.packages import PackageTools
from cordon_scanner.mcp.tools.workspace import WorkspaceTools


class Catalogue:
    """The tool definitions, in a fixed order (the specification asks for a deterministic list)."""

    ONLINE: ClassVar[dict[str, Any]] = {
        "type": "boolean",
        "default": False,
        "description": "Also ask the public registries (fetch and scan the published code, newest "
        "intel). Needs the server started with --allow-online.",
    }
    SEVERITY: ClassVar[dict[str, Any]] = {
        "enum": SEVERITY_ENUM,
        "default": "low",
        "description": "Report findings at or above this severity.",
    }
    PATH: ClassVar[dict[str, Any]] = {
        "type": "string",
        "description": "A path inside the workspace (relative paths are taken from the first root).",
    }
    MAX: ClassVar[dict[str, Any]] = {
        "type": "integer",
        "minimum": 1,
        "maximum": 500,
        "description": "Most findings to return (default 50).",
    }
    PACKAGE: ClassVar[dict[str, Any]] = {
        "ecosystem": {
            "enum": list(ECOSYSTEMS),
            "description": "The registry: npm, pypi, cargo, gomod, maven (group:artifact), nuget, composer, "
            "rubygems, pub, hex, cran, swift.",
        },
        "name": {
            "type": "string",
            "description": "The package name exactly as published (Maven: group:artifact; Go: module path).",
        },
        "version": {
            "type": "string",
            "description": "The exact version. Without it only the name is checked (typosquat, hallucinated "
            "name, malware-only name).",
        },
    }
    DATA: ClassVar[dict[str, Any]] = {"type": "object"}

    @staticmethod
    def schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        }

    @classmethod
    def build(cls) -> list[Tool]:
        return [
            *cls._package_tools(),
            *cls._code_tools(),
            *cls._agent_content_tools(),
            *cls._agent_server_tools(),
            *cls._image_and_change_tools(),
            *cls._repository_tools(),
            *cls._machine_and_knowledge_tools(),
        ]

    @classmethod
    def _package_tools(cls) -> list[Tool]:
        """Packages, lists of packages, install commands and advisories."""
        s, on, mx, pkg, data = cls.schema, cls.ONLINE, cls.MAX, cls.PACKAGE, cls.DATA
        return [
            Tool(
                "check_package",
                "Check a package before installing it",
                "Before installing or recommending a package, ask whether it is safe: known malicious releases, "
                "known vulnerabilities (with the version that fixes them), typosquats of popular packages and "
                "names AI assistants are documented to invent. With online, also fetch the published release, "
                "verify it against the registry's digest and scan its code (install scripts, obfuscation, "
                "credential theft, what changed since the previous release). Verdict block means do not install.",
                s({**pkg, "online": on, "max_findings": mx}, ["ecosystem", "name"]),
                PackageTools.check_package,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_packages",
                "Check many packages at once",
                "check_package for up to 200 packages in one call, across ecosystems: for a dependency list, a "
                "plan of what to add, or everything a generated project would install.",
                s(
                    {
                        "packages": {
                            "type": "array",
                            "maxItems": MAX_PACKAGES,
                            "items": s(pkg, ["ecosystem", "name"]),
                        },
                        "online": on,
                        "max_findings": mx,
                    },
                    ["packages"],
                ),
                PackageTools.check_packages,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_install_command",
                "Check a shell install command before running it",
                "Before running a command that installs software -- npm/yarn/pnpm/bun install or add, npx, "
                "pip/uv/poetry/pipx/uvx, cargo, gem/bundle, go get/install, dotnet add package, composer require "
                "-- pass the command. Every package it names is checked as check_package does; a custom registry "
                "or index, a URL, git or local source, and fetch-and-run shapes such as curl | sh are reported. "
                "Verdict block means do not run it.",
                s(
                    {
                        "command": {
                            "type": "string",
                            "description": "The command exactly as it would be run.",
                        },
                        "online": on,
                        "max_findings": mx,
                    },
                    ["command"],
                ),
                PackageTools.check_install_command,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "get_package_advisories",
                "List a package's advisories",
                "Every advisory Cordon holds for a package -- malicious-release records and vulnerabilities, "
                "with affected and fixed versions -- and, given a version, which affect it and the versions that "
                "fix them. For choosing a safe version to upgrade to.",
                s(pkg, ["ecosystem", "name"]),
                PackageTools.get_package_advisories,
                data,
            ),
        ]

    @classmethod
    def _code_tools(cls) -> list[Tool]:
        """Scans of a path in the workspace, and its secrets."""
        s, on, sev, path, mx = cls.schema, cls.ONLINE, cls.SEVERITY, cls.PATH, cls.MAX
        strings = {"type": "array", "items": {"type": "string"}}
        return [
            Tool(
                "scan_path",
                "Scan a directory, file or archive",
                "Scan part of the workspace with every Cordon detector: malicious and vulnerable dependencies, "
                "install-time behaviour, obfuscated or credential-stealing code, secrets, CI/CD pipelines, "
                "Dockerfiles and infrastructure code, AI agent instruction files, skills, hooks and MCP "
                "configuration, and editor files that run when a folder opens. Archives (.tgz, .whl, .zip, "
                ".vsix, .jar) are opened, never extracted to disk or run.",
                s(
                    {
                        "path": path,
                        "severity": sev,
                        "include": {**strings, "description": "Only paths matching these globs."},
                        "exclude": {**strings, "description": "Skip paths matching these globs."},
                        "changed_since": {
                            "type": "string",
                            "description": "Only files that differ from this git revision (e.g. origin/main).",
                        },
                        "staged": {
                            "type": "boolean",
                            "description": "Scan what is staged in git, not the working tree.",
                        },
                        "tracked_only": {
                            "type": "boolean",
                            "description": "Only files git tracks.",
                        },
                        "history": {
                            "type": "boolean",
                            "description": "Also read git history for secrets removed from the tree.",
                        },
                        "reachability": {
                            "type": "boolean",
                            "description": "Mark vulnerabilities in dependencies no first-party code imports.",
                        },
                        "fail_on": {
                            "enum": SEVERITY_ENUM,
                            "description": "Block at or above this severity instead of the configured policy.",
                        },
                        "online": on,
                        "max_findings": mx,
                    }
                ),
                WorkspaceTools.scan_path,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "find_secrets",
                "Find committed secrets",
                "Find credentials in the workspace -- API keys, tokens, private keys, connection strings -- and, "
                "with history, in git history the tree no longer shows. Values are never returned. With verify "
                "(online), each credential's own issuer is asked whether it still works.",
                s(
                    {
                        "path": path,
                        "history": {"type": "boolean"},
                        "verify": {"type": "boolean"},
                        "max_findings": mx,
                    }
                ),
                WorkspaceTools.find_secrets,
                SCAN_OUTPUT,
                open_world=True,
            ),
        ]

    @classmethod
    def _agent_content_tools(cls) -> list[Tool]:
        """A file's text, agent instruction files and skills."""
        s, sev, mx = cls.schema, cls.SEVERITY, cls.MAX
        return [
            Tool(
                "scan_file_content",
                "Check a file's content before writing or using it",
                "Scan content that is not on disk yet -- a generated Dockerfile, CI workflow, package.json, "
                "requirements file, shell script or config -- as if it were at filename in a repository. Nothing "
                "is written into the workspace.",
                s(
                    {
                        "filename": {
                            "type": "string",
                            "description": "Relative path the content would have, e.g. .github/workflows/ci.yml.",
                        },
                        "content": {"type": "string"},
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["filename", "content"],
                ),
                AgentTools.scan_file_content,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_agent_file",
                "Check an AI agent instruction file",
                "Before following or saving an agent instruction file -- CLAUDE.md, AGENTS.md, GEMINI.md, "
                ".cursorrules, .cursor/rules/*, .github/copilot-instructions.md, .windsurfrules, .clinerules, a "
                "slash command, an agent definition, hooks or settings -- check it for prompt injection, hidden "
                "characters, instructions to fetch and run code, credential access, concealment from the user and "
                "approval being switched off.",
                s(
                    {
                        "path": {
                            "type": "string",
                            "description": "Where the file lives in a repository, e.g. AGENTS.md or .claude/settings.json.",
                        },
                        "content": {"type": "string"},
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["path", "content"],
                ),
                AgentTools.check_agent_file,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_skill",
                "Check an agent skill before loading it",
                "Before installing or loading an agent skill, pass its files (SKILL.md and any scripts or "
                "references). Checked for malicious instructions, droppers, fake prerequisites, credential theft, "
                "remote instructions and scripts that fetch and run code.",
                s(
                    {
                        "name": {"type": "string", "description": "The skill's directory name."},
                        "files": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Path inside the skill -> content. Must include SKILL.md.",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["name", "files"],
                ),
                AgentTools.check_skill,
                SCAN_OUTPUT,
            ),
        ]

    @classmethod
    def _agent_server_tools(cls) -> list[Tool]:
        """MCP servers, the tools they serve, and editor extensions."""
        s, on, sev, path, mx = cls.schema, cls.ONLINE, cls.SEVERITY, cls.PATH, cls.MAX
        return [
            Tool(
                "check_mcp_server",
                "Check an MCP server before adding it",
                "Before adding an MCP server to an agent's configuration, pass its entry (command and args, or "
                "url). Checked for dangerous launch commands, unpinned or malicious packages it launches (npx, "
                "uvx, pipx, bunx...), secrets in its environment, plain-HTTP or tunnelled endpoints and approval "
                "bypasses. With online, the launched package's published code is scanned and a remote server's "
                "live tool descriptions are read.",
                s(
                    {
                        "name": {
                            "type": "string",
                            "description": "The server's key in the configuration.",
                        },
                        "config": {
                            "type": "object",
                            "description": "The server's entry: command, args, env, or url, type, headers.",
                        },
                        "online": on,
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["name", "config"],
                ),
                AgentTools.check_mcp_server,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_mcp_tools",
                "Check MCP tool descriptions for poisoning",
                "Pass the tools an MCP server lists (name, description, inputSchema). Each description and "
                "parameter description is checked for tool poisoning: steering the agent's use of other tools, "
                "asking it to hide things from the user, pointing it at credential files, tags addressed to the "
                "model and invisible characters.",
                s(
                    {
                        "server": {"type": "string"},
                        "tools": {"type": "array", "items": {"type": "object"}},
                        "max_findings": mx,
                    },
                    ["tools"],
                ),
                AgentTools.check_mcp_tools,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_ide_extension",
                "Check an editor extension before installing it",
                "Check a VS Code-compatible extension: a .vsix in the workspace (path), or by id (publisher.name) "
                "fetched from Open VSX -- verified against its published SHA-256 -- or the VS Code Marketplace. "
                "Checked for malicious code, obfuscation, credential theft, activation on every start and "
                "known-malicious or impersonating extensions.",
                s(
                    {
                        "path": path,
                        "id": {"type": "string", "description": "publisher.name"},
                        "version": {"type": "string"},
                        "registry": {
                            "enum": ["open-vsx", "vscode-marketplace"],
                            "default": "open-vsx",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    }
                ),
                AgentTools.check_ide_extension,
                SCAN_OUTPUT,
                open_world=True,
            ),
        ]

    @classmethod
    def _image_and_change_tools(cls) -> list[Tool]:
        """Container images, dependency changes and release comparisons."""
        s, on, sev, path, mx, data = (
            cls.schema,
            cls.ONLINE,
            cls.SEVERITY,
            cls.PATH,
            cls.MAX,
            cls.DATA,
        )
        return [
            Tool(
                "scan_container_image",
                "Scan a container image",
                "Pull an image from its registry (never run it) and scan its OS and language packages for known "
                "vulnerabilities and malicious releases, and its files for secrets and malware. Needs --allow-online.",
                s(
                    {
                        "image": {
                            "type": "string",
                            "description": "e.g. nginx:1.27, ghcr.io/org/app:2, name@sha256:<digest>",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["image"],
                ),
                MachineTools.scan_container_image,
                SCAN_OUTPUT,
                open_world=True,
                needs=("online",),
            ),
            Tool(
                "review_dependency_changes",
                "Review what a dependency update adds",
                "What a branch changes in its dependencies since a git revision: packages added, removed and "
                "upgraded, and for each upgrade, with online, what the new release adds over the old (install "
                "hooks, network or execution, obfuscation, binaries, a new publisher).",
                s(
                    {
                        "path": path,
                        "base": {"type": "string", "description": "e.g. origin/main"},
                        "online": on,
                    },
                    ["base"],
                ),
                WorkspaceTools.review_dependency_changes,
                data,
                open_world=True,
            ),
            Tool(
                "compare_releases",
                "Compare two releases of a package",
                "What one release of a package adds over an earlier one, both on disk: a new install hook, new "
                "network or execution capability, new obfuscation or binaries.",
                s(
                    {"path": path, "previous_path": path, "max_findings": mx},
                    ["path", "previous_path"],
                ),
                WorkspaceTools.compare_releases,
                SCAN_OUTPUT,
            ),
        ]

    @classmethod
    def _repository_tools(cls) -> list[Tool]:
        """The repository's dependencies, description, bill of materials, baseline
        and suppressions."""
        s, on, sev, path, mx, data = (
            cls.schema,
            cls.ONLINE,
            cls.SEVERITY,
            cls.PATH,
            cls.MAX,
            cls.DATA,
        )
        return [
            Tool(
                "list_dependencies",
                "List the dependency graph",
                "Every dependency the workspace resolves, direct and transitive, with versions, where each is "
                "declared and its advisory, malware, integrity and licence status.",
                s({"path": path, "direct_only": {"type": "boolean"}, "online": on}),
                WorkspaceTools.list_dependencies,
                data,
                open_world=True,
            ),
            Tool(
                "describe_repository",
                "Describe what the repository is",
                "The ecosystems, projects, manifests and lockfiles, languages, CI systems, containers, "
                "infrastructure code and hooks Cordon finds, with the evidence for each.",
                s({"path": path}),
                WorkspaceTools.describe_repository,
                data,
            ),
            Tool(
                "generate_sbom",
                "Generate a software or AI bill of materials",
                "A CycloneDX or SPDX bill of materials from the resolved dependency graph; with ai, the AI bill "
                "of materials (agent instruction files, skills, MCP servers, models and AI SDKs); with "
                "vulnerabilities, the advisory matches embedded, exploited ones marked.",
                s(
                    {
                        "path": path,
                        "format": {"enum": ["cyclonedx", "spdx"], "default": "cyclonedx"},
                        "ai": {"type": "boolean"},
                        "vulnerabilities": {"type": "boolean"},
                    }
                ),
                WorkspaceTools.generate_sbom,
                data,
            ),
            Tool(
                "compare_with_baseline",
                "Show only new findings",
                "Scan and leave out every finding recorded in a baseline file: what a change introduced.",
                s(
                    {"path": path, "baseline": path, "severity": sev, "max_findings": mx},
                    ["baseline"],
                ),
                WorkspaceTools.compare_with_baseline,
                SCAN_OUTPUT,
            ),
            Tool(
                "list_suppressions",
                "List suppressions",
                "Every suppression in the repository's configuration, who approved it, when it expires and "
                "whether it is in force.",
                s({"path": path}),
                WorkspaceTools.list_suppressions,
                data,
            ),
        ]

    @classmethod
    def _machine_and_knowledge_tools(cls) -> list[Tool]:
        """This machine's agents and packages, the rules, the intel and this
        server."""
        s, on, sev, mx, data = cls.schema, cls.ONLINE, cls.SEVERITY, cls.MAX, cls.DATA
        return [
            Tool(
                "list_local_agents",
                "List this machine's AI agents and MCP servers",
                "The AI agents, MCP servers and editor extensions configured on this computer, with what Cordon "
                "finds about each. Nothing is sent anywhere. Needs the server started with --allow-machine.",
                s({}),
                MachineTools.list_local_agents,
                data,
                needs=("machine",),
            ),
            Tool(
                "scan_machine",
                "Scan this machine's installed packages",
                "The operating system's packages and the language packages installed outside any project, "
                "matched for known vulnerabilities and malicious releases. Needs --allow-machine.",
                s(
                    {
                        "include_home": {
                            "type": "boolean",
                            "description": "Also read this user's own installs (pipx, ~/.local, cargo install).",
                        },
                        "online": on,
                        "severity": sev,
                        "max_findings": mx,
                    }
                ),
                MachineTools.scan_machine,
                SCAN_OUTPUT,
                open_world=True,
                needs=("machine",),
            ),
            Tool(
                "explain_rule",
                "Explain a finding's rule",
                "What a rule detects, why it matters, how to fix what it reports and who documents the threat, "
                "for a rule_id from any finding.",
                s({"rule_id": {"type": "string"}}, ["rule_id"]),
                KnowledgeTools.explain_rule,
                data,
            ),
            Tool(
                "search_rules",
                "Search Cordon's rules",
                "Find rules by words in their id or title, category and minimum severity.",
                s(
                    {
                        "query": {"type": "string"},
                        "category": {"type": "string"},
                        "min_severity": {"enum": SEVERITY_ENUM},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    }
                ),
                KnowledgeTools.search_rules,
                data,
            ),
            Tool(
                "intel_status",
                "Threat-intel freshness",
                "Where Cordon's threat intelligence comes from, its serial and its age, without fetching anything.",
                s({}),
                KnowledgeTools.intel_status,
                data,
            ),
            Tool(
                "server_status",
                "This server's settings",
                "The directories this server may read, whether online checks and machine-wide reads are allowed, "
                "the scan deadline, the Cordon Cloud sign-in and the tools available.",
                s({}),
                ServerStatus.report,
                data,
            ),
        ]

    @staticmethod
    def available(settings: Settings) -> list[Tool]:
        """The tools this server offers: one whose server flag is off is not listed at all."""
        enabled = {"online": settings.allow_online, "machine": settings.allow_machine}
        return [t for t in TOOLS if all(enabled[n] for n in t.needs)]


class ServerStatus:
    """The `server_status` tool: this server's settings and the tools it offers. Beside the
    catalogue, which it lists, so the tools need not import the module that lists them."""

    @staticmethod
    def report(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        try:
            run = settings.runner.run(["whoami"], timeout=30, token=token)
            # Signed in or not, never who: the identity would go to the model and its provider.
            cloud = "signed in" if run.exit_code == 0 else "not signed in"
        except TimedOut:
            cloud = "unknown (timed out)"
        structured = {
            "server": "cordon-scanner",
            "version": settings.version,
            "workspace_roots": settings.workspace.describe(),
            "online_allowed": settings.allow_online,
            "machine_reads_allowed": settings.allow_machine,
            "private_network_allowed": settings.allow_private_network,
            "scan_timeout_seconds": settings.timeout,
            "cordon_cloud": cloud,
            "ecosystems": list(ECOSYSTEMS),
            "tools": [t.name for t in Catalogue.available(settings)],
        }
        return Scans.data(structured, "Cordon MCP server status")


TOOLS: Final[list[Tool]] = Catalogue.build()


@dataclass(slots=True)
class Registry:
    settings: Settings
    tools: dict[str, Tool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.tools = {t.name: t for t in Catalogue.available(self.settings)}
