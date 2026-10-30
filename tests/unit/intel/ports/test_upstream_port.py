"""`UpstreamAdvisories.for_graph`, the upstream port (`intel.base.UpstreamLookup`), answers exactly what
the advisory detector computes today from `check` and `_with_nvd`, offline and online."""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.detect.base import GraphUnit
from cordon_scanner.detect.supply.advisories.detector import UPSTREAM_ECOSYSTEMS, AdvisoryDetector
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel import registry
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from cordon_scanner.intel.advisories.upstream_advisories import UpstreamAdvisories, UpstreamResult


class UpstreamKit:
    GRAPH: ClassVar[tuple[Dependency, ...]] = tuple(
        Dependency(ecosystem=eco, name=name, version=version, purl=f"pkg:{eco}/{name}@{version}")
        for eco, name, version in (
            ("conan", "zlib", "1.2.11"),
            ("conan", "openssl", "1.1.1k"),
            ("vcpkg", "curl", "7.79.0"),
            ("homebrew", "jq", "1.6"),
            ("conda", "numpy", "1.21.0"),
            ("cocoapods", "AFNetworking", "4.0.1"),
            ("npm", "left-pad", "1.0.0"),
        )
    )

    @staticmethod
    def answer(candidates: list[Dependency]) -> UpstreamResult:
        """A fixed online answer: the first candidate checked with one advisory, the next not."""
        first, *rest = candidates
        return UpstreamResult(
            advisories={
                first.purl: (
                    Advisory(
                        ecosystem=first.ecosystem,
                        name=first.name,
                        versions=(first.version or "",),
                        summary="s",
                        identifier="OSV-1",
                    ),
                )
            },
            checked={first.purl},
            unchecked={d.purl: "no upstream named" for d in rest},
            homes={d.purl: ("https://example.org/home",) for d in rest},
        )

    @staticmethod
    def detector_today(database: AdvisoryDatabase, *, offline: bool) -> UpstreamResult | None:
        """The detector's own lines: upstream for what it serves when online, then `_with_nvd`."""
        unit = GraphUnit(dependencies=UpstreamKit.GRAPH)
        upstream = None
        if not offline:
            candidates = [
                d
                for d in unit.dependencies
                if not d.local
                and not d.bundled
                and d.ecosystem in UPSTREAM_ECOSYSTEMS
                and not database.covers(d.ecosystem)
            ]
            if candidates:
                upstream = UpstreamAdvisories.check(candidates)
        return AdvisoryDetector(database)._with_nvd(unit, upstream)


class TestThePort:
    @pytest.mark.parametrize("offline", [True, False])
    def test_for_graph_is_the_detectors_answer(
        self, monkeypatch: pytest.MonkeyPatch, offline: bool
    ) -> None:
        monkeypatch.setattr(UpstreamAdvisories, "check", staticmethod(UpstreamKit.answer))
        database = AdvisoryDatabase(
            (Advisory(ecosystem="npm", name="left-pad", versions=("1.0.0",), summary="s"),)
        )
        want = UpstreamKit.detector_today(database, offline=offline)
        got = registry.UpstreamAdvisories.for_graph(
            UpstreamKit.GRAPH, database.covers, offline=offline
        )
        assert got == want
        assert want is not None and (offline or want.checked)

    def test_the_roles_are_the_classes(self) -> None:
        from cordon_scanner.intel.advisories import osv_import, upstream_advisories

        assert registry.UpstreamAdvisories is upstream_advisories.UpstreamAdvisories
        assert registry.OsvImport is osv_import.OsvImport
        assert registry.UPSTREAM_ECOSYSTEMS == upstream_advisories.SUPPORTED
        for url in ("https://github.com/Owner/Repo.git", "git@github.com:owner/repo", "not a url"):
            assert registry.OsvImport.repository_key(url) == osv_import.OsvImport.repository_key(
                url
            )
