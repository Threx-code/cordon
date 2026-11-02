"""The package verdict in a repository scan (`Verdict._lowers`, `repository`): a MALICIOUS finding is
never lowered there. The model was fitted on packages; a repository that also holds an MCP server's
manifest is scored in area `mcp`, a liftable area, and on 28 October 2026 a 40-file repository's
MALICIOUS code findings were held at medium because its score (0.124) was under that line (0.7296).

    scan of no package format ──► Ceilings.verdict(repository=True) ──► Verdict.decide
        └─► _lowers: MALICIOUS in a repository ──► kept ──► PolicyGate fails the scan
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.decide.verdict import Verdict, VerdictModel
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)


class RepositoryKit:
    """The 28 October shape: an MCP server's manifest beside a MALICIOUS code finding, and a model
    that scores the whole under area `mcp`'s line."""

    RULE = "MALWARE.EXFIL.BEACON.001"
    LINE = 0.7296

    @staticmethod
    def finding() -> Finding:
        return Finding(
            rule_id=RepositoryKit.RULE,
            category=Category.MALICIOUS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            message="m.",
            location=Location(path="setup.py"),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
            ),
            remediation="",
            explanation=Explanation(summary="", matched_rule=RepositoryKit.RULE),
            risk=RiskScore(value=90, base=90, confidence_multiplier=1.0),
            detector="t",
        )

    @staticmethod
    def model() -> dict[str, object]:
        # No trees: every package scores the baseline, about 0.007, far under the line.
        return {
            "format": VerdictModel.FORMAT,
            "features": [],
            "baseline": -5.0,
            "trees": [],
            "areas": {"mcp": RepositoryKit.LINE, Verdict.FALLBACK: 0.95},
            "lift_areas": ["mcp"],
            "floor": [],
            "keep": [],
        }

    @staticmethod
    def decide(*, repository: bool) -> tuple[list[Finding], dict[str, Any]]:
        manifest = json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}).encode()
        with mock.patch.object(VerdictModel, "load", return_value=RepositoryKit.model()):
            return Verdict.decide(
                [RepositoryKit.finding()],
                [(".mcp.json", 40), ("package.json", len(manifest)), ("setup.py", 200)],
                {"package.json": manifest},
                repository=repository,
            )


class TestTheTwentyEighthOfOctober:
    def test_a_repository_s_malicious_finding_beside_an_mcp_manifest_blocks(self) -> None:
        graded, summary = RepositoryKit.decide(repository=True)
        assert summary["area"] == "mcp"
        assert summary["score"] < summary["block"] == RepositoryKit.LINE
        (finding,) = graded
        assert (finding.category, finding.severity) == (Category.MALICIOUS, Severity.CRITICAL)
        assert PolicyGate._fails(finding, Policy())

    def test_the_same_package_is_still_graded_by_the_verdict(self) -> None:
        # The control: in a package the trained lowering is unchanged (measured on package rows,
        # 2026-10-31: keeping MALICIOUS there cost ~800 benign blocks per 102.5k units).
        (finding,), _ = RepositoryKit.decide(repository=False)
        assert (finding.category, finding.severity) == (Category.SUSPICIOUS, Severity.MEDIUM)
        assert not PolicyGate._fails(finding, Policy())

    def test_lowers_keeps_malicious_only_in_a_repository(self) -> None:
        def lowers(category: Category, repository: bool) -> bool:
            return Verdict._lowers(
                RepositoryKit.RULE, Severity.HIGH, Confidence.HIGH, category, score=0.1,
                block=0.9, liftable=True, floor=frozenset(), keep=frozenset(),
                repository=repository,
            )  # fmt: skip

        assert not lowers(Category.MALICIOUS, True)
        assert lowers(Category.MALICIOUS, False)
        assert lowers(Category.SUSPICIOUS, True)  # repository grading is option A's, not this


class TestWhichScansAreRepositories:
    """The scanner passes `repository` from the scan's own context: True for a directory or an
    archive of no package format, False for a recognised package."""

    @staticmethod
    def seen(target: Path) -> list[bool]:
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        seen: list[bool] = []
        decide = Verdict.decide

        def recording(*args: Any, repository: bool = False, **kwargs: Any) -> Any:
            seen.append(repository)
            return decide(*args, repository=repository, **kwargs)

        with mock.patch.object(Verdict, "decide", staticmethod(recording)):
            Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return seen

    def test_a_directory_is_a_repository(self, tmp_path: Path) -> None:
        (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
        (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        assert self.seen(tmp_path) == [True]

    @pytest.mark.parametrize(
        ("members", "repository"),
        [
            # npm's own layout: a published package
            ({"package/package.json": b'{"name": "x", "version": "1.0.0"}'}, False),
            # a repository snapshot: no packaging tool's metadata at its first level
            ({"repo-main/.mcp.json": b'{"mcpServers": {}}', "repo-main/README.md": b"x\n"}, True),
        ],
    )
    def test_an_archive_is_one_unless_its_format_is_known(
        self, tmp_path: Path, members: dict[str, bytes], repository: bool
    ) -> None:
        target = tmp_path / "x.tgz"
        root = next(iter(members)).split("/")[0]
        with tarfile.open(target, "w:gz") as tar:
            for name, data in {**members, f"{root}/index.js": b"exports.a = 1;\n"}.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        assert self.seen(target) == [repository]
