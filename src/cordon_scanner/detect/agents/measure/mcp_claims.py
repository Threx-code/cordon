"""What an MCP server's tool descriptions claim, beside what its code can reach: the same two readings a skill's front matter gets, for a measurement run.

A tool's description is what the agent's user approves; the server's code is what runs. For each of four kinds of reach (the network, credentials, a process, files) `mcp_claims_<kind>` is 1 when
some tool description mentions it, and `mcp_unclaimed_<kind>` is 1 when the code reaches it and no description does. The words are the ones the skill reading uses, so a skill and a server are read
alike. Facts for the model's measure, never findings, and nothing in a scan or in `FeatureSchema` reads them: a recorder merges `record(...)` into its row beside its other fields.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from typing import ClassVar

from cordon_scanner.detect.agents.mcp_servers.source import McpServerSource


class McpClaims:
    CLAIM: ClassVar[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in {
            "network": r"\b(?:api|http|web|url|download|upload|fetch|online|search|browse|"
            r"webhook|slack|github|notion|google|cloud|server|service|remote|sync)\b",
            "credentials": r"\b(?:token|key|secret|credential|password|auth|oauth|login|"
            r"wallet|keychain|ssh|vault)\b",
            "shell": r"\b(?:shell|terminal|command|install|deploy|docker|kubectl|git|run|"
            r"execute|script|process|system|automation)\b",
            "files": r"\b(?:file|folder|directory|document|pdf|csv|excel|image|disk|backup)\b",
        }.items()
    }
    """The claim words of a skill's description (`VerdictFeatures.SKILL_CLAIM`), held equal by a test."""
    REACH: ClassVar[dict[str, frozenset[str]]] = {
        "network": frozenset({"egress", "network"}),
        "credentials": frozenset({"credential"}),
        "shell": frozenset({"spawn", "execute", "runs_download"}),
        "files": frozenset({"read_file", "write_file"}),
    }

    @classmethod
    def descriptions(cls, sources: Iterable[tuple[str, str]]) -> list[str]:
        """Every tool description the server sources `(path, text)` declare."""
        return [d for path, text in sources for d in McpServerSource._tool_descriptions(text, path)]

    @staticmethod
    def reaches(package: Mapping[str, float]) -> set[str]:
        """What the code can reach, from the scan's package facts (`agent_can_*`)."""
        return {
            name[len("agent_can_") :]
            for name, value in package.items()
            if name.startswith("agent_can_") and value
        }

    @classmethod
    def of(cls, descriptions: Iterable[str], reaches: Collection[str]) -> dict[str, float]:
        text = " ".join(descriptions)
        out: dict[str, float] = {}
        for kind, pattern in cls.CLAIM.items():
            claimed = bool(pattern.search(text))
            out[f"mcp_claims_{kind}"] = float(claimed)
            out[f"mcp_unclaimed_{kind}"] = float(
                bool(cls.REACH[kind] & set(reaches)) and not claimed
            )
        return out

    @classmethod
    def record(
        cls, sources: Iterable[tuple[str, str]], package: Mapping[str, float]
    ) -> dict[str, dict[str, dict[str, float]]]:
        """What a recorder adds to a row: `{"measure": {"mcp_claims": {...}}}`, empty for a package with no tool description."""
        found = cls.descriptions(sources)
        return {"measure": {"mcp_claims": cls.of(found, cls.reaches(package))}} if found else {}


__all__ = ["McpClaims"]
