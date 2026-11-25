"""A decompression bomb and a parser-crash fixture end as an incomplete scan the decision names R204: never a crash, never a pass.

An artifact that attacks the scanner is read under budgets. When a budget stops the read, or a parser cannot take the content to its end, the scan says part of the content was not examined and the
decision for it is a block with the reason `R204`. Each fixture below is scanned for real and judged by the decision function through the same bridge the gate is compared with.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context
from cordon_scanner.decide.decision.legacy import LegacyBridge
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.limits import DEFAULT_LIMITS


class Hostile:
    BOMB_LIMITS = DEFAULT_LIMITS.merged(
        max_archive_ratio=10,
        max_member_bytes=1024 * 1024,
        max_elided_member_bytes=0,
        max_elided_bytes=0,
    )

    @staticmethod
    def tarball(root: Path, files: dict[str, bytes], name: str = "p-1.0.0.tgz") -> Path:
        target = root / name
        with tarfile.open(target, "w:gz") as archive:
            for path, data in files.items():
                info = tarfile.TarInfo(f"package/{path}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return target

    @staticmethod
    def scan(target: Path, limits: Any = DEFAULT_LIMITS) -> Any:
        config = Config.default().with_overrides(use_cache=False, offline=True, limits=limits)
        return Scanner(config).scan(target)

    @staticmethod
    def decision(result: Any) -> Any:
        policy = Policy()
        evidence = LegacyBridge.evidence(result, policy, date.today())
        artifact, context = ArtifactRef("package", "pkg:npm/hostile"), Context("cli", "dev")
        return Decider.decide(
            artifact, context, LegacyBridge.compiled(policy), evidence, datetime.now(UTC)
        )


class TestADecompressionBomb:
    def test_the_scan_is_incomplete_and_names_what_was_not_read(self, tmp_path: Path) -> None:
        bomb = Hostile.tarball(
            tmp_path,
            {
                "package.json": b'{"name": "p", "version": "1.0.0"}',
                "bomb.txt": b"\x00" * (8 * 1024 * 1024),
            },
        )
        result = Hostile.scan(bomb, Hostile.BOMB_LIMITS)
        assert not result.content_complete
        assert any(rule.startswith("OPERATIONAL.") for rule, _path in result.content_gaps)

    def test_the_decision_is_a_block_with_the_incomplete_reason(self, tmp_path: Path) -> None:
        bomb = Hostile.tarball(
            tmp_path,
            {
                "package.json": b'{"name": "p", "version": "1.0.0"}',
                "bomb.txt": b"\x00" * (8 * 1024 * 1024),
            },
        )
        decision = Hostile.decision(Hostile.scan(bomb, Hostile.BOMB_LIMITS))
        assert decision.state == "BLOCK" and "R204" in decision.reason_codes

    def test_a_clean_package_beside_it_is_not_blocked_for_that_reason(self, tmp_path: Path) -> None:
        clean = Hostile.tarball(
            tmp_path,
            {
                "package.json": b'{"name": "p", "version": "1.0.0"}',
                "index.js": b"module.exports = 1;\n",
            },
        )
        decision = Hostile.decision(Hostile.scan(clean, Hostile.BOMB_LIMITS))
        assert "R204" not in decision.reason_codes


class TestAParserCrashFixture:
    FIXTURES: ClassVar[dict[str, dict[str, bytes]]] = {
        "a manifest nested past any parser's depth": {
            "package.json": b"[" * 200_000 + b"]" * 200_000
        },
        "a manifest cut in the middle of a string": {
            "package.json": b'{"name": "p", "version": "1.0.0", "scripts": {"postinstall": "node x'
        },
        "a manifest that is not text": {"package.json": bytes(range(256)) * 40},
    }

    @pytest.mark.parametrize("name", list(FIXTURES))
    def test_the_scan_ends_with_a_result_and_never_a_pass(self, tmp_path: Path, name: str) -> None:
        archive = Hostile.tarball(
            tmp_path, {**self.FIXTURES[name], "index.js": b"module.exports = 1;\n"}
        )
        result = Hostile.scan(archive)
        assert not result.content_complete, name
        assert Hostile.decision(result).state == "BLOCK"

    @pytest.mark.parametrize("name", list(FIXTURES))
    def test_the_decision_names_the_incomplete_scan(self, tmp_path: Path, name: str) -> None:
        archive = Hostile.tarball(
            tmp_path, {**self.FIXTURES[name], "index.js": b"module.exports = 1;\n"}
        )
        assert "R204" in Hostile.decision(Hostile.scan(archive)).reason_codes, name

    def test_a_truncated_compressed_archive_is_incomplete_too(self, tmp_path: Path) -> None:
        whole = Hostile.tarball(
            tmp_path,
            {
                "package.json": json.dumps({"name": "p", "version": "1.0.0"}).encode(),
                "index.js": b"x" * 5000,
            },
        ).read_bytes()
        cut = tmp_path / "cut-1.0.0.tgz"
        cut.write_bytes(gzip.compress(gzip.decompress(whole))[: len(whole) // 2])
        result = Hostile.scan(cut)
        assert not result.content_complete
        assert "R204" in Hostile.decision(result).reason_codes
