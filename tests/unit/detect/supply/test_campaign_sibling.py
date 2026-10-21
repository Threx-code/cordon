"""SUSPECT.CAMPAIGN.SIBLING.001: a published npm package that is one campaign with a condemned release
(review 98 C3). Inert fixtures: manifests and file names only."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.intel.malware.campaign import CampaignFingerprint, CampaignIndex

RULE = "SUSPECT.CAMPAIGN.SIBLING.001"

CONDEMNED = {
    "name": "ledger-utils-41",
    "version": "1.0.3",
    "scripts": {"preinstall": "node setup-41.js"},
    "dependencies": {"axios": "^1"},
}
FILES = ("setup-41.js", "lib/index.js")


class SiblingHelpers:
    @staticmethod
    def tarball(tmp_path: Path, manifest: dict[str, object], files: tuple[str, ...]) -> Path:
        members = {"package/package.json": json.dumps(manifest).encode()}
        members |= {f"package/{name}": b"module.exports = {};\n" for name in files}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / f"{manifest['name']}-{manifest['version']}.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def rules(target: Path) -> set[str]:
        scanner = Scanner(Config.default().with_overrides(use_cache=False))
        return {f.rule_id for f in scanner.scan(target).findings}


tarball, rules = SiblingHelpers.tarball, SiblingHelpers.rules


class TestCampaignSibling:
    @pytest.fixture(autouse=True)
    def condemned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The shipped index replaced by one holding the condemned release above."""
        tree = ["package/package.json", *(f"package/{f}" for f in FILES)]
        record = {
            "name": "ledger-utils-41",
            "version": "1.0.3",
            "id": "MAL-2026-1",
            "published": "2026-10-01",
        }
        facets = CampaignFingerprint.of(CONDEMNED, tree)
        index = CampaignIndex.of_document(CampaignIndex.build([(facets, record)], [], "2026-10-21"))
        monkeypatch.setattr(CampaignIndex, "shipped", staticmethod(lambda: index))

    def test_a_renamed_renumbered_variant_is_held(self, tmp_path: Path) -> None:
        variant = {**CONDEMNED, "name": "ledger-tools-97", "version": "2.0.0"}
        variant["scripts"] = {"preinstall": "node setup-97.js"}
        assert RULE in rules(tarball(tmp_path, variant, ("setup-97.js", "lib/index.js")))

    def test_the_condemned_release_is_not_its_own_sibling(self, tmp_path: Path) -> None:
        assert RULE not in rules(tarball(tmp_path, CONDEMNED, FILES))

    def test_one_shared_facet_is_not_a_campaign(self, tmp_path: Path) -> None:
        # Same dependencies, a different manifest and tree.
        other = {"name": "dashboard", "version": "1.0.0", "dependencies": {"axios": "^1"}}
        other["scripts"] = {"build": "tsc", "test": "jest"}
        assert RULE not in rules(tarball(tmp_path, other, ("src/a.js", "src/b.js")))

    def test_only_a_published_npm_package_is_read(self, tmp_path: Path) -> None:
        # The same files checked out as a project, not a published tarball: not this check's.
        root = tmp_path / "repo"
        (root / "lib").mkdir(parents=True)
        variant = {**CONDEMNED, "name": "ledger-tools-97"}
        (root / "package.json").write_text(json.dumps(variant), encoding="utf-8")
        for name in FILES:
            (root / name).write_text("module.exports = {};\n", encoding="utf-8")
        assert RULE not in rules(root)


class TestIntelNotContent:
    def test_the_verdict_never_reads_a_campaign_match_as_code(self) -> None:
        # A match against what the feed condemned is not a reading of this package's code: the
        # content verdict neither takes it as evidence nor lifts it.
        from cordon_scanner.decide.verdict import VerdictFeatures

        assert VerdictFeatures.is_intel(RULE)
        assert not VerdictFeatures.is_code(RULE)
