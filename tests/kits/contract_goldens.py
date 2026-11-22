"""Builds `tests/unit/contracts/golden_ids.json`: 2,000 benign subject inputs and the canonical id of each.

Inputs are public names only: the popularity lists shipped in `intel/data/*.txt` for packages (every
n-th name, with the spellings a tool might use: upper case, scoped, with underscores), and a fixed list of
well-known actions, images, extensions, skills, MCP servers, models, agents, repositories and artifacts.
Nothing is drawn from a corpus. Run it after a change to a canonical form, and review the diff:

    python tests/kits/contract_goldens.py ids src > tests/unit/contracts/golden_ids.json

and writes the JSON data files and the manifest that go with the schemas (`contracts/data/`,
`contracts/manifest.json`), after a change to a reason code, a subject kind or a schema:

    python tests/kits/contract_goldens.py data src/cordon_scanner/contracts
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar

from cordon_scanner.contracts.manifest import ContractData
from cordon_scanner.contracts.subjects import CanonicalIds, SubjectKind

DATA = (
    Path(sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "ids" else "src")
    / "cordon_scanner"
    / "intel"
    / "data"
)
LISTS = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "composer": "composer",
    "cran": "cran",
    "nuget": "nuget",
    "rubygems": "gem",
}
PER_LIST = 280


class ContractGoldens:
    """The golden inputs, built deterministically."""

    FIXED: ClassVar[list[tuple[SubjectKind, dict[str, str]]]] = [
        *(
            (SubjectKind.CONTAINER_IMAGE, {"name": name})
            for name in (
                "nginx",
                "nginx:1.27",
                "ubuntu:24.04",
                "redis@sha256:" + "0" * 64,
                "library/postgres:16",
                "ghcr.io/actions/runner:latest",
                "quay.io/prometheus/prometheus",
                "mcr.microsoft.com/dotnet/aspnet:8.0",
                "registry.k8s.io/pause:3.9",
                "GCR.io/Distroless/Static",
            )
        ),
        *(
            (SubjectKind.CI_ACTION, {"host": "github", "owner": owner, "repo": repo})
            for owner, repo in (
                ("actions", "checkout"),
                ("Actions", "Setup-Node"),
                ("docker", "build-push-action"),
                ("github", "codeql-action"),
                ("hashicorp", "setup-terraform"),
                ("aws-actions", "configure-aws-credentials"),
            )
        ),
        (
            SubjectKind.CI_ACTION,
            {"host": "github", "owner": "github", "repo": "codeql-action", "path": "analyze"},
        ),
        (
            SubjectKind.CI_ACTION,
            {"host": "gitlab", "project": "components/Sast", "component": "sast"},
        ),
        *(
            (SubjectKind.IDE_EXTENSION, {"marketplace": market, "publisher": pub, "name": name})
            for market, pub, name in (
                ("vscode", "ms-python", "python"),
                ("vscode", "esbenp", "prettier-vscode"),
                ("openvsx", "redhat", "java"),
                ("jetbrains", "JetBrains", "Kotlin"),
            )
        ),
        *(
            (SubjectKind.AGENT_SKILL, {"source": "gh", "locator": loc})
            for loc in ("anthropics/skills/pdf", "Anthropics/Skills/docx", "openai/skills")
        ),
        (SubjectKind.AGENT_SKILL, {"source": "registry", "locator": "Deploy-Helper"}),
        (SubjectKind.AGENT_SKILL, {"source": "local", "locator": ".claude/skills/review"}),
        (SubjectKind.AGENT_SKILL, {"source": "archive", "locator": "sha256:" + "ab" * 32}),
        *(
            (SubjectKind.MCP_SERVER, {"transport": t, "locator": loc})
            for t, loc in (
                ("npm", "@modelcontextprotocol/server-filesystem"),
                ("npm", "@Modelcontextprotocol/Server-Memory"),
                ("pypi", "mcp-server-git"),
                ("oci", "ghcr.io/example/mcp:1"),
                ("remote", "https://mcp.example.com/sse"),
                ("remote", "https://MCP.Example.com:8443/v1/"),
                ("local", "/usr/local/bin/NPX -y @example/server"),
            )
        ),
        *(
            (SubjectKind.AI_MODEL, {"provider": p, "name": n})
            for p, n in (
                ("openai", "gpt-example"),
                ("Anthropic", "claude-example"),
                ("huggingface", "bert-base-uncased"),
                ("huggingface", "meta-llama/Llama-3-8B"),
            )
        ),
        *(
            (SubjectKind.AGENT, {"product": p})
            for p in ("claude-code", "Cursor", "Codex CLI", "windsurf")
        ),
        *(
            (SubjectKind.SOURCE_REPOSITORY, {"scm": s, "owner": o, "name": n})
            for s, o, n in (
                ("github", "torvalds", "linux"),
                ("GitHub", "Kubernetes", "kubernetes.git"),
                ("gitlab", "gitlab-org", "gitlab"),
                ("bitbucket", "atlassian", "stash"),
                ("git", "Example", "Repo.git"),
            )
        ),
        *(
            (SubjectKind.BUILD_ARTIFACT, {"scope": s, "name": n})
            for s, n in (
                ("acme-prod", "app/image"),
                ("Acme-Prod", "web"),
                ("team-a", "lib/core/v2"),
            )
        ),
    ]

    @classmethod
    def inputs(cls) -> list[tuple[SubjectKind, dict[str, str]]]:
        found = list(cls.FIXED)
        for filename, ecosystem in LISTS.items():
            names = [
                line.strip()
                for line in (DATA / f"{filename}.txt").read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
            step = max(1, len(names) // PER_LIST)
            for index, name in enumerate(names[::step][:PER_LIST]):
                found.append(
                    (
                        SubjectKind.PACKAGE,
                        {"ecosystem": ecosystem, "name": cls._spelling(name, index)},
                    )
                )
        return found[:2000]

    @staticmethod
    def _spelling(name: str, index: int) -> str:
        """The way a tool might write the name: as listed, in upper case, or with its separators swapped."""
        variant = index % 4
        if variant == 1:
            return name.upper()
        if variant == 2:
            return name.replace("-", "_")
        return name

    @classmethod
    def build(cls) -> list[dict[str, object]]:
        return [
            {"kind": kind.value, "parts": parts, "id": CanonicalIds.canonical_id(kind, parts)}
            for kind, parts in cls.inputs()
        ]


if __name__ == "__main__":
    if sys.argv[1:2] == ["data"]:
        for written in ContractData.write(Path(sys.argv[2])):
            sys.stdout.write(f"wrote {written}\n")
    else:
        sys.stdout.write(
            json.dumps(ContractGoldens.build(), indent=0, sort_keys=True, ensure_ascii=False) + "\n"
        )
