"""K8: the AI bill of materials. What in a repository steers, extends or runs an AI system.

A CycloneDX 1.6 document listing, for one repository:

* agent instruction, skill, command and prompt files -- `data` components, hashed, because
  their text is what an agent acts on;
* agent settings (hooks, permissions) -- `data` components with what they grant as properties;
* MCP servers -- a local server is an `application` component with the package it launches; a
  remote one is a `service` with its endpoint, which crosses the trust boundary;
* models -- `machine-learning-model` components: weight files in the tree (hashed when small
  enough to hash in seconds), Hugging Face models the code loads, and hosted models it names;
* AI SDKs from the dependency graph, and AI agents run in CI workflows.

Every entry carries `cordon:ai:kind`, so a consumer can filter without knowing the layout. Nothing
is executed, loaded or fetched to build it.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.core.walker import PathGlob, Walker
from cordon_scanner.detect.agents import (
    AGENT_ACTIONS,
    AGENT_SETTINGS_PATHS,
    INSTRUCTION_PATHS,
    MCP_PATHS,
    WORKFLOW_PATHS,
    McpConfigs,
)
from cordon_scanner.report.sbom import TOOL_NAME, _identity, _timestamp

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Dependency

SPEC_VERSION: Final = "1.6"
MAX_READ: Final = 1 << 20
MAX_HASH_BYTES: Final = 512 << 20
"""Weight files larger than this are listed without a hash: hashing tens of gigabytes would turn
an inventory into a wait."""

PROMPT_PATHS: Final = (
    "**/*.prompt",
    "**/*.prompt.md",
    "**/*.prompty",
    "**/prompts/**/*.md",
    "**/prompts/**/*.txt",
)
MODEL_SUFFIXES: Final = {
    ".safetensors": "safetensors",
    ".gguf": "gguf",
    ".ggml": "ggml",
    ".onnx": "onnx",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".ckpt": "checkpoint",
    ".h5": "keras",
    ".keras": "keras",
    ".tflite": "tflite",
    ".mlmodel": "coreml",
    ".pb": "tensorflow",
    ".joblib": "joblib",
    ".pkl": "pickle",
}
AI_SDKS: Final = frozenset(
    {
        "openai", "anthropic", "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk", "claude-agent-sdk",
        "google-generativeai", "google-genai", "@google/genai", "@google/generative-ai", "vertexai",
        "mistralai", "@mistralai/mistralai", "cohere", "cohere-ai", "groq", "groq-sdk", "ollama",
        "langchain", "langchain-core", "langchain-openai", "langchain-anthropic", "@langchain/core",
        "langgraph", "@langchain/langgraph", "llama-index", "llama-index-core", "llamaindex",
        "transformers", "sentence-transformers", "huggingface-hub", "@huggingface/inference",
        "vllm", "litellm", "dspy", "dspy-ai", "crewai", "autogen", "pyautogen", "ag2",
        "semantic-kernel", "haystack-ai", "ai", "@ai-sdk/openai", "@ai-sdk/anthropic",
        "mcp", "@modelcontextprotocol/sdk", "fastmcp", "openai-agents", "@openai/agents",
    }
)  # fmt: skip
_HF_LOAD: Final = re.compile(
    r"""(?:from_pretrained|hf_hub_download|snapshot_download|pipeline)\s*\([^)]{0,200}?["']([A-Za-z0-9][\w.-]{0,95}/[\w.-]{1,95})["']"""
)
_HOSTED: Final = re.compile(
    r"""["'](claude-(?:opus|sonnet|haiku|fable|3|instant)[\w.-]{0,40}|gpt-[0-9][\w.-]{0,30}|o[134](?:-mini|-pro)?(?:-\d{4}-\d{2}-\d{2})?|gemini-[0-9][\w.-]{0,40}|mistral-(?:large|medium|small)[\w.-]{0,30}|command-r[\w.-]{0,20})["']"""
)
_SUPPLIER: Final = (("claude-", "Anthropic"), ("gpt-", "OpenAI"), ("o1", "OpenAI"), ("o3", "OpenAI"), ("o4", "OpenAI"), ("gemini-", "Google"), ("mistral-", "Mistral AI"), ("command-", "Cohere"))  # fmt: skip
_CODE_SUFFIXES: Final = (
    ".py",
    ".ts",
    ".js",
    ".mjs",
    ".cjs",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".kt",
    ".rb",
    ".cs",
    ".ipynb",
)
_AGENT_OF: Final = (
    ("CLAUDE", "claude-code"), (".claude/", "claude-code"), ("AGENTS.md", "agents-md"), ("AGENT.md", "agents-md"),
    ("GEMINI.md", "gemini-cli"), (".gemini/", "gemini-cli"), (".cursor", "cursor"), (".windsurf", "windsurf"),
    (".clinerules", "cline"), ("copilot-instructions", "github-copilot"), (".github/instructions", "github-copilot"),
    (".github/prompts", "github-copilot"), (".roo/", "roo-code"), (".vscode/", "vscode"), ("SKILL.md", "agent-skills"),
)  # fmt: skip


@dataclass
class AiInventory:
    components: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    refs: set[str] = field(default_factory=set)

    def add(self, entry: dict[str, Any], *, service: bool = False) -> None:
        if entry["bom-ref"] in self.refs:
            return
        self.refs.add(entry["bom-ref"])
        (self.services if service else self.components).append(entry)


def _props(**values: object) -> list[dict[str, str]]:
    return [
        {"name": f"cordon:{key.replace('_', ':', 1).replace('_', '-')}", "value": str(value)}
        for key, value in values.items()
        if value not in (None, "")
    ]


def _matches(path: str, patterns: Sequence[str]) -> bool:
    return any(PathGlob.matches(path, pattern) for pattern in patterns)


def _agent_of(path: str) -> str:
    return next((agent for marker, agent in _AGENT_OF if marker in path), "")


def _kind_of_instruction(path: str) -> str:
    if "/skills/" in path or path.endswith("SKILL.md"):
        return "skill"
    if "/commands/" in path:
        return "command"
    if "/agents/" in path:
        return "subagent"
    if "/prompts/" in path:
        return "prompt"
    return "agent-instructions"


def _sha256(path: Path, size: int) -> list[dict[str, str]]:
    if size > MAX_HASH_BYTES:
        return []
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return [{"alg": "SHA-256", "content": digest.hexdigest()}]


def _endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}{parsed.path}"


def _mcp(inventory: AiInventory, rel: str, raw: bytes) -> None:
    try:
        config = json.loads(raw)
    except ValueError:
        return
    servers = (
        (config.get("mcpServers") or config.get("servers") or {})
        if isinstance(config, dict)
        else {}
    )
    for name, server in servers.items() if isinstance(servers, dict) else ():
        if not isinstance(server, dict):
            continue
        url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
        if isinstance(url, str):
            inventory.add(
                {
                    "bom-ref": f"mcp-service:{rel}#{name}",
                    "name": str(name),
                    "endpoints": [_endpoint(url)],
                    "authenticated": bool(server.get("headers")),
                    "x-trust-boundary": True,
                    "properties": _props(
                        ai_kind="mcp-server",
                        mcp_transport=server.get("type") or "http",
                        mcp_config=rel,
                    ),
                },
                service=True,
            )
            continue
        command = server.get("command")
        if not isinstance(command, str):
            continue
        args = [str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))]
        launched = McpConfigs.launched_package(command, args)
        entry: dict[str, Any] = {
            "type": "application",
            "bom-ref": f"mcp-server:{rel}#{name}",
            "name": str(name),
            "properties": _props(
                ai_kind="mcp-server", mcp_transport="stdio", mcp_config=rel, mcp_command=command
            ),
        }
        if launched is not None:
            ecosystem, spec, pinned = launched
            if ecosystem in ("npm", "pypi"):
                package, version = McpConfigs.split_spec(ecosystem, spec)
                quoted = urllib.parse.quote(package, safe="/")
                entry["purl"] = f"pkg:{ecosystem}/{quoted}" + (f"@{version}" if version else "")
                if version:
                    entry["version"] = version
            entry["properties"] += _props(mcp_package=spec, mcp_pinned=str(pinned).lower())
        inventory.add(entry)


def _settings(inventory: AiInventory, rel: str, raw: bytes, hashes: list[dict[str, str]]) -> None:
    try:
        settings = json.loads(raw)
    except ValueError:
        settings = {}
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    permissions = settings.get("permissions") if isinstance(settings, dict) else None
    allow = permissions.get("allow") if isinstance(permissions, dict) else None
    hook_count = (
        sum(len(v) for v in hooks.values() if isinstance(v, list)) if isinstance(hooks, dict) else 0
    )
    inventory.add(
        {
            "type": "data",
            "bom-ref": f"file:{rel}",
            "name": rel,
            "hashes": hashes,
            "data": [{"type": "configuration", "name": rel}],
            "properties": _props(
                ai_kind="agent-settings",
                ai_agent=_agent_of(rel),
                ai_hooks=hook_count or None,
                ai_permissions_allow=len(allow) if isinstance(allow, list) else None,
            ),
        }
    )


def _workflow(inventory: AiInventory, rel: str, text: str) -> None:
    for match in re.finditer(r"uses:\s*['\"]?([\w.-]+/[\w./-]+)@([\w.-]+)", text):
        action, ref = match.group(1), match.group(2)
        base = "/".join(action.split("/")[:2])
        if base not in AGENT_ACTIONS:
            continue
        inventory.add(
            {
                "type": "application",
                "bom-ref": f"ci-agent:{rel}#{base}@{ref}",
                "name": base,
                "version": ref,
                "purl": f"pkg:github/{base}@{ref}",
                "properties": _props(ai_kind="ci-agent", ci_workflow=rel),
            }
        )


def _code(inventory: AiInventory, rel: str, text: str) -> None:
    for match in _HF_LOAD.finditer(text):
        repo = match.group(1)
        inventory.add(
            {
                "type": "machine-learning-model",
                "bom-ref": f"model:huggingface/{repo}",
                "name": repo,
                "purl": f"pkg:huggingface/{repo}",
                "properties": _props(
                    ai_kind="model", ai_source="huggingface", ai_referenced_in=rel
                ),
            }
        )
    for match in _HOSTED.finditer(text):
        model = match.group(1)
        supplier = next((name for prefix, name in _SUPPLIER if model.startswith(prefix)), "")
        inventory.add(
            {
                "type": "machine-learning-model",
                "bom-ref": f"model:hosted/{model}",
                "name": model,
                "supplier": {"name": supplier} if supplier else None,
                "properties": _props(ai_kind="model", ai_source="hosted-api", ai_referenced_in=rel),
            }
        )


def inventory(root: Path, dependencies: Sequence[Dependency] = ()) -> AiInventory:
    found = AiInventory()
    walker = Walker()
    for entry in walker.walk(root):
        rel = entry.rel_path
        suffix = Path(rel).suffix.lower()
        if suffix in MODEL_SUFFIXES and (
            suffix not in (".pkl", ".pb", ".pt", ".joblib")
            or "model" in rel.lower()
            or entry.size > (1 << 20)
        ):
            found.add(
                {
                    "type": "machine-learning-model",
                    "bom-ref": f"file:{rel}",
                    "name": rel,
                    "hashes": _sha256(entry.real_path, entry.size),
                    "properties": _props(
                        ai_kind="model",
                        ai_source="file",
                        ai_format=MODEL_SUFFIXES[suffix],
                        ai_size=entry.size,
                    ),
                }
            )
            continue
        relevant = (
            _matches(rel, INSTRUCTION_PATHS)
            or _matches(rel, PROMPT_PATHS)
            or _matches(rel, AGENT_SETTINGS_PATHS)
            or _matches(rel, MCP_PATHS)
            or _matches(rel, WORKFLOW_PATHS)
            or suffix in _CODE_SUFFIXES
        )
        if not relevant or entry.size > MAX_READ:
            continue
        try:
            raw = entry.real_path.read_bytes()
        except OSError:
            continue
        text = raw.decode("utf-8", "replace")
        if _matches(rel, MCP_PATHS):
            _mcp(found, rel, raw)
        elif _matches(rel, AGENT_SETTINGS_PATHS):
            _settings(
                found, rel, raw, [{"alg": "SHA-256", "content": hashlib.sha256(raw).hexdigest()}]
            )
        elif _matches(rel, INSTRUCTION_PATHS) or _matches(rel, PROMPT_PATHS):
            found.add(
                {
                    "type": "data",
                    "bom-ref": f"file:{rel}",
                    "name": rel,
                    "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(raw).hexdigest()}],
                    "data": [
                        {
                            "type": "other",
                            "name": rel,
                            "description": "Text an AI agent reads and acts on",
                        }
                    ],
                    "properties": _props(
                        ai_kind=_kind_of_instruction(rel), ai_agent=_agent_of(rel)
                    ),
                }
            )
        elif _matches(rel, WORKFLOW_PATHS):
            _workflow(found, rel, text)
        if suffix in _CODE_SUFFIXES:
            _code(found, rel, text)
    for dependency in dependencies:
        if dependency.name.lower() in AI_SDKS:
            found.add(
                {
                    "type": "library",
                    "bom-ref": dependency.purl,
                    "name": dependency.name,
                    "version": dependency.version or "",
                    "purl": dependency.purl,
                    "properties": _props(ai_kind="ai-sdk"),
                }
            )
    for entry_list in (found.components, found.services):
        for item in entry_list:
            if item.get("supplier") is None:
                item.pop("supplier", None)
            if not item.get("hashes"):
                item.pop("hashes", None)
    return found


def cyclonedx_document(
    root: Path,
    dependencies: Sequence[Dependency],
    *,
    root_name: str,
    root_version: str,
    tool_version: str,
    moment: str | None = None,
) -> dict[str, Any]:
    found = inventory(root, dependencies)
    root_purl = f"pkg:generic/{root_name}@{root_version}"
    kinds: dict[str, int] = {}
    for item in [*found.components, *found.services]:
        kind = next(
            (p["value"] for p in item.get("properties", ()) if p["name"] == "cordon:ai:kind"),
            "other",
        )
        kinds[kind] = kinds.get(kind, 0) + 1
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_identity(root_purl + '#ai', dependencies)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(moment),
            "tools": {
                "components": [{"type": "application", "name": TOOL_NAME, "version": tool_version}]
            },
            "component": {
                "type": "application",
                "bom-ref": root_purl,
                "name": root_name,
                "version": root_version,
            },
            "properties": [
                {"name": f"cordon:ai:count:{k}", "value": str(v)} for k, v in sorted(kinds.items())
            ],
        },
        "components": sorted(found.components, key=lambda c: c["bom-ref"]),
    }
    if found.services:
        document["services"] = sorted(found.services, key=lambda s: s["bom-ref"])
    document["dependencies"] = [{"ref": root_purl, "dependsOn": sorted(found.refs)}]
    return document


__all__ = ["AI_SDKS", "AiInventory", "cyclonedx_document", "inventory"]
