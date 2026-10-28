"""Recipes are matched by the SHA-256 of their exact bytes, never by name: one edit is another recipe."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.recipe_digests import (
    KNOWN_RULE,
    PROVISIONAL_RULE,
    RecipeDigestDetector,
    RecipeDigests,
)
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.advisories import shipped
from cordon_scanner.intel.malware.feed import FeedRoles
from kits.feedkit import FeedKit, SignedFeed

FORMULA = b'class Evil < Formula\n  url "https://example.invalid/evil-1.0.tar.gz"\nend\n'


class RecipeKit:
    @staticmethod
    def record(digest: str, **extra) -> dict:
        return {
            "id": "CORDON-HOMEBREW-0123456789ABCDEF0123",
            "ecosystem": "homebrew",
            "name": "evil",
            "versions": ["0278853cf62d"],
            "malicious": True,
            "digests": [digest],
            "summary": "a formula that runs a payload",
            **extra,
        }

    @staticmethod
    def delta(serial: int, **sections) -> bytes:
        return gzip.compress(
            FeedRoles.canonical({"serial": serial, "advisories": {}, **sections}), mtime=0
        )

    @staticmethod
    def tap(root: Path, body: bytes = FORMULA) -> Path:
        (root / "Formula").mkdir(parents=True, exist_ok=True)
        (root / "Formula" / "evil.rb").write_bytes(body)
        return root

    @staticmethod
    def rules(root: Path) -> set[str]:
        config = Config.default().with_overrides(use_cache=False)
        return {
            f.rule_id
            for f in Scanner(config, detectors=(RecipeDigestDetector(),)).scan(root).findings
        }


class RecipeFixtures:
    @pytest.fixture(autouse=True)
    def isolated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.delenv("CORDON_OFFLINE", raising=False)
        shipped.ShippedAdvisories.reset_caches()
        yield
        shipped.ShippedAdvisories.reset_caches()

    @staticmethod
    def feed(**sections) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, FeedKit.full_bundle({"npm": []})))
        test_feed.client().update()
        test_feed.publish(2, deltas={2: RecipeKit.delta(2, **sections)})
        test_feed.client().update()


class TestRecipeDigests(RecipeFixtures):
    def test_the_condemned_recipe_bytes_block(self, tmp_path) -> None:
        digest = hashlib.sha256(FORMULA).hexdigest()
        self.feed(advisories={"homebrew": {"upsert": [RecipeKit.record(digest)], "withdraw": []}})
        assert KNOWN_RULE in RecipeKit.rules(RecipeKit.tap(tmp_path / "tap"))

    def test_one_edit_is_another_recipe(self, tmp_path) -> None:
        digest = hashlib.sha256(FORMULA).hexdigest()
        self.feed(advisories={"homebrew": {"upsert": [RecipeKit.record(digest)], "withdraw": []}})
        edited = FORMULA.replace(b"1.0", b"1.1")
        assert RecipeKit.rules(RecipeKit.tap(tmp_path / "tap", edited)) == set()

    def test_a_held_recipe_is_paused(self, tmp_path) -> None:
        digest = hashlib.sha256(FORMULA).hexdigest()
        held = RecipeKit.record(digest, provisional=True)
        self.feed(provisional={"homebrew": {"upsert": [held], "withdraw": []}})
        assert RecipeKit.rules(RecipeKit.tap(tmp_path / "tap")) == {PROVISIONAL_RULE}

    def test_a_withdrawn_verdict_matches_nothing(self, tmp_path) -> None:
        digest = hashlib.sha256(FORMULA).hexdigest()
        record = RecipeKit.record(digest)
        self.feed(advisories={"homebrew": {"upsert": [record], "withdraw": [record["id"]]}})
        assert RecipeKit.rules(RecipeKit.tap(tmp_path / "tap")) == set()

    @pytest.mark.parametrize(
        "path, ecosystem",
        [
            ("Formula/wget.rb", "homebrew"),
            ("Casks/app.rb", "homebrew"),
            ("recipes/zlib/all/conanfile.py", "conan"),
            ("ports/zlib/portfile.cmake", "vcpkg"),
            ("pkgs/tools/x/package.nix", "nix"),
            ("lib/helper.rb", None),
            ("README.md", None),
        ],
    )
    def test_which_files_are_recipes(self, path, ecosystem) -> None:
        assert RecipeDigests.ecosystem_of(path) == ecosystem


class TestMcpBundles(RecipeFixtures):
    """An MCP bundle (`.mcpb`, a zip of a server's code) is matched by its exact bytes, as the
    backend analysed it from the MCP registry."""

    @staticmethod
    def bundle(root: Path) -> bytes:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("manifest.json", '{"name": "server", "version": "1.2.0"}')
            archive.writestr("server/index.js", "module.exports = {};\n")
        root.mkdir(parents=True, exist_ok=True)
        (root / "server.mcpb").write_bytes(buffer.getvalue())
        return buffer.getvalue()

    def test_the_condemned_bundle_bytes_block(self, tmp_path) -> None:
        data = self.bundle(tmp_path / "p")
        record = RecipeKit.record(
            hashlib.sha256(data).hexdigest(), ecosystem="mcp", id="CORDON-MCP-0123456789ABCDEF0123"
        )
        self.feed(advisories={"mcp": {"upsert": [record], "withdraw": []}})
        assert KNOWN_RULE in RecipeKit.rules(tmp_path / "p")

    def test_any_other_bundle_does_not(self, tmp_path) -> None:
        self.bundle(tmp_path / "p")
        record = RecipeKit.record("0" * 64, ecosystem="mcp", id="CORDON-MCP-0123456789ABCDEF0123")
        self.feed(advisories={"mcp": {"upsert": [record], "withdraw": []}})
        assert KNOWN_RULE not in RecipeKit.rules(tmp_path / "p")
