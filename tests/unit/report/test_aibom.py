"""K8: the AI bill of materials, built from a repository with one of everything it inventories."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.cli.main import CommandLine

SHA = "f0c8eb29f2b8a5e3c1d4b6a7e8f90123456789ab"

FILES: dict[str, str | bytes] = {
    "CLAUDE.md": "# Project\nRun `make test` before committing.\n",
    ".claude/skills/release/SKILL.md": "---\nname: release\n---\nCut a release.\n",
    ".claude/commands/review.md": "Review the diff.\n",
    ".claude/settings.json": json.dumps(
        {
            "permissions": {"allow": ["Bash(make test)", "Read"]},
            "hooks": {
                "PostToolUse": [
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "make fmt"}]}
                ]
            },
        }
    ),
    ".mcp.json": json.dumps(
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "."],
                },
                "git": {"command": "uvx", "args": ["mcp-server-git==0.6.2"]},
                "docs": {
                    "type": "http",
                    "url": "https://user:pw@mcp.example.com/v1?key=secret",
                    "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"},
                },
            }
        }
    ),
    ".github/prompts/summarise.prompt.md": "Summarise the change.\n",
    ".github/workflows/assistant.yml": (
        "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: anthropics/claude-code-action@{SHA}\n"
    ),
    "models/classifier.safetensors": b"\x08\x00\x00\x00\x00\x00\x00\x00{}      ",
    "app.py": (
        "from transformers import AutoModel\n"
        'model = AutoModel.from_pretrained("google-bert/bert-base-uncased")\n'
        'client.messages.create(model="claude-sonnet-4-5", max_tokens=10)\n'
    ),
    "package.json": json.dumps(
        {"name": "app", "version": "1.2.0", "dependencies": {"@anthropic-ai/sdk": "0.40.0"}}
    ),
    "package-lock.json": json.dumps(
        {
            "name": "app",
            "version": "1.2.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.2.0"},
                "node_modules/@anthropic-ai/sdk": {
                    "version": "0.40.0",
                    "integrity": "sha512-x",
                    "resolved": "https://registry.npmjs.org/@anthropic-ai/sdk/-/sdk-0.40.0.tgz",
                },
            },
        }
    ),
}


class AibomFixtures:
    """Fixtures for the tests in test_aibom.py; every test class here inherits them."""

    @pytest.fixture
    def document(self, tmp_path: Path) -> dict:
        for name, data in FILES.items():
            path = tmp_path / "repo" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes) else data.encode())
        out = tmp_path / "ai.cdx.json"
        assert (
            CommandLine.main(
                ["sbom", "generate", str(tmp_path / "repo"), "--ai", "--output", str(out)]
            )
            == 0
        )
        return json.loads(out.read_text(encoding="utf-8"))


class AibomHelpers:
    """Helpers for test_aibom.py."""

    @staticmethod
    def _kind(entry: dict) -> str:
        return next(p["value"] for p in entry["properties"] if p["name"] == "cordon:ai:kind")

    @staticmethod
    def _prop(entry: dict, name: str) -> str | None:
        return next((p["value"] for p in entry.get("properties", ()) if p["name"] == name), None)


class TestTheAiBom(AibomFixtures):
    def test_it_is_cyclonedx_1_6(self, document) -> None:
        assert (document["bomFormat"], document["specVersion"]) == ("CycloneDX", "1.6")
        assert document["metadata"]["component"]["name"] == "app"

    def test_every_kind_is_inventoried(self, document) -> None:
        kinds = sorted(
            AibomHelpers._kind(c) for c in [*document["components"], *document["services"]]
        )
        assert kinds == sorted(
            [
                "agent-instructions",  # CLAUDE.md
                "skill",
                "command",
                "agent-settings",
                "mcp-server",  # fs
                "mcp-server",  # git
                "mcp-server",  # docs (service)
                "prompt",
                "ci-agent",
                "model",  # safetensors
                "model",  # huggingface
                "model",  # hosted
                "ai-sdk",
            ]
        )

    def test_mcp_servers_name_their_packages_and_endpoints(self, document) -> None:
        by_name = {c["name"]: c for c in document["components"]}
        assert (
            by_name["fs"]["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem@2025.8.21"
        )
        assert by_name["git"]["purl"] == "pkg:pypi/mcp-server-git@0.6.2"
        assert AibomHelpers._prop(by_name["git"], "cordon:mcp:pinned") == "true"
        [service] = document["services"]
        assert service["endpoints"] == ["https://mcp.example.com/v1"], (
            "credentials and query are not copied"
        )
        assert service["authenticated"] is True and service["x-trust-boundary"] is True

    def test_settings_record_what_they_grant(self, document) -> None:
        [settings] = [
            c for c in document["components"] if AibomHelpers._kind(c) == "agent-settings"
        ]
        assert AibomHelpers._prop(settings, "cordon:ai:hooks") == "1"
        assert AibomHelpers._prop(settings, "cordon:ai:permissions-allow") == "2"
        assert settings["hashes"][0]["alg"] == "SHA-256"

    def test_models(self, document) -> None:
        models = {
            c["name"]: c for c in document["components"] if c["type"] == "machine-learning-model"
        }
        assert (
            models["google-bert/bert-base-uncased"]["purl"]
            == "pkg:huggingface/google-bert/bert-base-uncased"
        )
        assert models["claude-sonnet-4-5"]["supplier"] == {"name": "Anthropic"}
        assert (
            AibomHelpers._prop(models["models/classifier.safetensors"], "cordon:ai:format")
            == "safetensors"
        )
        assert "hashes" in models["models/classifier.safetensors"]

    def test_the_ci_agent_and_the_sdk(self, document) -> None:
        names = {c["name"]: c for c in document["components"]}
        assert names["anthropics/claude-code-action"]["version"] == SHA
        assert names["@anthropic-ai/sdk"]["purl"].startswith("pkg:npm/")

    def test_every_dependency_ref_exists(self, document) -> None:
        refs = {c["bom-ref"] for c in [*document["components"], *document["services"]]}
        [edges] = document["dependencies"]
        assert set(edges["dependsOn"]) == refs

    def test_an_archive_is_refused(self, tmp_path) -> None:
        target = tmp_path / "x.tar"
        target.write_bytes(b"")
        assert CommandLine.main(["sbom", "generate", str(target), "--ai"]) == 3
