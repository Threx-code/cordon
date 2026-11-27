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

ARCHIVE = "pkg.tgz!"


class Package:
    @staticmethod
    def member(case: Real) -> str:
        """Where the manifest sits in a published archive: npm packs under `package/`."""
        return f"package/{case.path}" if case.ecosystem == "npm" else case.path

    @classmethod
    def reads(cls, case: Real) -> bool:
        return CampaignFingerprint.root_manifest(f"{ARCHIVE}{cls.member(case)}") == case.ecosystem

    @classmethod
    def unit(cls, case: Real, raw: bytes) -> tuple[FileUnit, ScanContext]:
        path = f"{ARCHIVE}{cls.member(case)}"
        unit = FileUnit(content=FileContent.from_bytes(path, raw))
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(()),
            tree_paths=frozenset({path, f"{ARCHIVE}lib/a.txt", f"{ARCHIVE}lib/b.txt"}),
        )
        return unit, ctx


#: Real manifests too bare to fingerprint: google/uuid's go.mod requires nothing, so it has one informative facet (its layout)
#: and no campaign can be two facets of it.
UNINFORMATIVE = {"gomod"}
READ = [c for c in CASES if Package.reads(c) and c.ecosystem not in UNINFORMATIVE]
NOT_READ = [c for c in CASES if not Package.reads(c) and c.ecosystem not in UNINFORMATIVE]


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
        slip = case.cut[:-1]
        variant, _ = Package.unit(case, case.raw().replace(case.cut.encode(), slip.encode(), 1))
        found = CampaignSiblingDetector.siblings_of(variant, ctx)
        assert found is not None and [r["id"] for r in found[1]] == ["MAL-2026-1"], case.ecosystem


class TestWhatTheFingerprintDoesNotYetRead:
    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(
                c,
                marks=pytest.mark.xfail(
                    strict=True,
                    reason=(
                        f"{c.ecosystem}: the file that names a published package is not a manifest the "
                        "fingerprint reads at the package's root"
                    ),
                ),
            )
            for c in NOT_READ
        ],
        ids=[c.ecosystem for c in NOT_READ],
    )
    def test_the_published_manifest_is_read(self, case: Real) -> None:
        assert Package.reads(case)
