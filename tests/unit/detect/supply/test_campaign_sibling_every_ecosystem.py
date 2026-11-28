"""A renamed copy of a condemned release is found as its sibling in every ecosystem whose published package has a manifest
the fingerprint reads, through one code path keyed by the adapter (`CampaignFingerprint.root_manifest`, `of_manifest`).

The manifests are the real ones of `own_name_captures` (see its CAPTURES.md). The condemned release is the capture itself, put in a
real `CampaignIndex`; the variant is the same file with the name cut by a letter, as a campaign republishes under another name.
An ecosystem whose published package carries no manifest the fingerprint reads is a strict expected failure naming why: the
shipped index holds condemned releases of the ecosystems the dataset has confirmed (a data matter), but the code path has to
read the package before any of them can match."""

from __future__ import annotations

import pytest
from test_own_name_every_ecosystem import CASES, Real

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.campaign_sibling import CampaignSiblingDetector
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.intel.malware.campaign import CampaignFingerprint, CampaignIndex
from cordon_scanner.rules.loader import RuleSet


class Package:
    @staticmethod
    def archive_of(case: Real) -> str:
        """The archive a package of the ecosystem is published as, as far as the fingerprint tells them apart."""
        return "pkg.vsix!" if case.ecosystem == "vscode" else "pkg.tgz!"

    @staticmethod
    def member(case: Real) -> str:
        """Where the manifest sits in a published archive: npm packs under `package/`."""
        if case.ecosystem == "npm":
            return f"package/{case.path}"
        return case.root or case.path

    @staticmethod
    def renamed(raw: bytes, cut: str) -> bytes:
        """The manifest republished under another name: the declaration of the name (its first quoted spelling, else its
        first spelling) loses a letter; nothing else changes, as a campaign renames only the package."""
        quoted = f'"{cut}"'.encode()
        if quoted in raw:
            return raw.replace(quoted, f'"{cut[:-1]}"'.encode(), 1)
        return raw.replace(cut.encode(), cut[:-1].encode(), 1)

    @classmethod
    def reads(cls, case: Real) -> bool:
        return (
            CampaignFingerprint.root_manifest(f"{Package.archive_of(case)}{cls.member(case)}")
            == case.ecosystem
        )

    @classmethod
    def unit(cls, case: Real, raw: bytes) -> tuple[FileUnit, ScanContext]:
        path = f"{Package.archive_of(case)}{cls.member(case)}"
        unit = FileUnit(content=FileContent.from_bytes(path, raw))
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(()),
            tree_paths=frozenset(
                {
                    path,
                    f"{Package.archive_of(case)}lib/a.txt",
                    f"{Package.archive_of(case)}lib/b.txt",
                }
            ),
        )
        return unit, ctx


#: Real files too bare to fingerprint: google/uuid's go.mod requires nothing, and a Terraform provider's release is one binary
#: named for it, so each has one informative facet (its layout) and no campaign can be two facets of it.
UNINFORMATIVE = {"gomod", "terraform"}
READ = [c for c in CASES if c.ecosystem not in UNINFORMATIVE]


class TestAVariantIsFoundInEveryEcosystemWhoseManifestIsRead:
    @pytest.mark.parametrize("case", READ, ids=[c.ecosystem for c in READ])
    def test_a_renamed_copy_is_the_condemned_releases_sibling(
        self, case: Real, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        condemned, ctx = Package.unit(case, case.raw())
        facets = CampaignFingerprint.of_manifest(
            case.ecosystem,
            condemned.content,
            ["lib/a.txt", "lib/b.txt", Package.member(case)],
        )
        record = {
            "name": "condemned-name",
            "version": "9.9.9",
            "id": "MAL-2026-1",
            "published": "2026-10-01",
        }
        index = CampaignIndex.of_document(CampaignIndex.build([(facets, record)], [], "2026-10-21"))
        monkeypatch.setattr(CampaignIndex, "shipped", staticmethod(lambda: index))
        variant, _ = Package.unit(case, Package.renamed(case.raw(), case.cut))
        found = CampaignSiblingDetector.siblings_of(variant, ctx)
        assert found is not None and [r["id"] for r in found[1]] == ["MAL-2026-1"], case.ecosystem


class TestEveryPublishedIdentityFileIsRead:
    @pytest.mark.parametrize("case", CASES, ids=[c.ecosystem for c in CASES])
    def test_the_file_that_names_a_published_package_is_a_manifest_the_fingerprint_reads(
        self, case: Real
    ) -> None:
        assert Package.reads(case), case.ecosystem
