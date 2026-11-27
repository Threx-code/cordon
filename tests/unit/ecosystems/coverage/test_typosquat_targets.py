"""The names a look-alike is measured against, for every ecosystem (the guard row "typosquat (look-alike names)").

A target is a name the registry's users know well: the hand-kept popular set (`PackageIntel.POPULAR_PACKAGES`), each name of which is
established by the ranked list the refresh ships for its registry or, for an ecosystem the registry does not rank, by the curated
set in `real.py`. A `<ecosystem>.index.txt` is a strided sample of a whole index: a name in it is any name, so it is neither a target
nor an allowlist (a squat inside an index is not made safe by being listed there)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.ecosystems.contract import CONTRACTS
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.registries import real
from cordon_scanner.intel.registries.names import PopularPackageNames
from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import DATA_DIR, RealPackages


class TestEveryEcosystemHasTargets:
    @pytest.mark.parametrize("ecosystem", sorted(EcosystemRegistry.BY_ID))
    def test_a_popular_set_or_a_contract_reason(self, ecosystem: str) -> None:
        contract = next(c for c in CONTRACTS if c.id == ecosystem)
        if "UNI-13" in contract.not_applicable:
            assert PopularPackageNames.popular(ecosystem) == frozenset()
            assert len(contract.not_applicable["UNI-13"].split()) >= 8
        else:
            assert len(PopularPackageNames.popular(ecosystem)) >= 5, ecosystem

    @pytest.mark.parametrize("ecosystem", sorted(EcosystemRegistry.BY_ID))
    def test_an_established_set_exists_for_the_ecosystem(self, ecosystem: str) -> None:
        shipped, curated = RealPackages.parts(ecosystem)
        shared = RealPackages.real_packages("maven" if ecosystem == "gradle" else ecosystem)
        assert shipped or curated or shared, ecosystem


class TestAnIndexIsNeverATarget:
    def test_an_index_file_is_not_read_as_an_allowlist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "zzz.index.txt").write_text("# sample\nsquatted-name\n", encoding="utf-8")
        monkeypatch.setattr(real, "DATA_DIR", tmp_path)
        assert RealPackages._shipped("zzz") == frozenset()

    def test_an_ecosystem_with_only_an_index_has_hand_kept_targets_not_the_sample(self) -> None:
        for index in DATA_DIR.glob("*.index.txt"):
            ecosystem = index.name.removesuffix(".index.txt")
            shipped, _ = RealPackages.parts(ecosystem)
            assert not shipped, f"{ecosystem}: a ranked list and an index both ship"
            assert PopularPackageNames.popular(ecosystem), ecosystem


class TestEditorExtensionTargets:
    def test_each_is_established_by_the_ranked_list_it_is_measured_with(self) -> None:
        ranked = {
            line.strip()
            for line in (DATA_DIR / "vscode.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        assert PopularPackageNames.popular("vscode") <= ranked

    def test_a_slip_of_an_extension_is_a_target_miss_not_a_known_name(self) -> None:
        assert not PackageIntel.is_known_package("vscode", "ms-pyhton.python")
        assert PackageIntel.is_known_package("vscode", "ms-python.python")
