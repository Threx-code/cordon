"""`PackageIntel.is_known_package` as a set lookup: the same answer as normalising every candidate on
every call, for every ecosystem, every listed name as written and as normalised, and names that are
near misses of them; and the kept set rebuilt when a list it was made from is replaced."""

from __future__ import annotations

import random

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import REAL_PACKAGES


class Reference:
    """The lookup as it was: membership, then every candidate normalised and compared."""

    @staticmethod
    def is_known(ecosystem: str, name: str) -> bool:
        candidates = (
            PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
            | REAL_PACKAGES.get(ecosystem, frozenset())
            | PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())
        )
        if name in candidates:
            return True
        implementation = EcosystemRegistry.get(ecosystem)
        if implementation is None:
            return False
        return any(implementation.normalize_name(c) == name for c in candidates)

    @staticmethod
    def answers(ecosystem: str, names: set[str]) -> dict[str, bool]:
        """`is_known` for each of `names`, the same comparison with each candidate normalised once
        here, never by the code under test: asked name by name, every candidate was normalised for
        every name, and the test took 460 s of the suite's 5,422 (5 Nov)."""
        candidates = (
            PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
            | REAL_PACKAGES.get(ecosystem, frozenset())
            | PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())
        )
        implementation = EcosystemRegistry.get(ecosystem)
        normalised = (
            {implementation.normalize_name(c) for c in candidates} if implementation else set()
        )
        return {n: n in candidates or n in normalised for n in names}

    @staticmethod
    def ecosystems() -> list[str]:
        return sorted(
            {*PackageIntel.POPULAR_PACKAGES, *REAL_PACKAGES, *PackageIntel._KNOWN_NEIGHBOURS}
            | {"no-such-ecosystem"}
        )

    @staticmethod
    def near(name: str, rng: random.Random) -> str:
        """A one-edit near miss: a character dropped, doubled, or swapped for `_`, `-`, `.`."""
        if not name:
            return "x"
        i = rng.randrange(len(name))
        edit = rng.choice(("drop", "double", "sep", "case"))
        if edit == "drop":
            return name[:i] + name[i + 1 :]
        if edit == "double":
            return name[:i] + name[i] + name[i:]
        if edit == "sep":
            return name[:i] + rng.choice("_-.") + name[i + 1 :]
        return name[:i] + name[i].swapcase() + name[i + 1 :]


class TestTheLookup:
    @pytest.mark.parametrize("ecosystem", Reference.ecosystems())
    def test_every_listed_name_and_its_near_misses(self, ecosystem: str) -> None:
        rng = random.Random(f"known|{ecosystem}")  # noqa: S311 -- a fixture, not key material
        implementation = EcosystemRegistry.get(ecosystem)
        names = sorted(
            PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
            | REAL_PACKAGES.get(ecosystem, frozenset())
            | PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())
        )
        asked = set(names)
        if implementation is not None:
            asked |= {implementation.normalize_name(n) for n in names}
        asked |= {Reference.near(n, rng) for n in names for _ in range(2)}
        asked |= {"", "zz-not-a-package-zz", "a"}
        known = sum(PackageIntel.is_known_package(ecosystem, n) for n in asked)
        expected = Reference.answers(ecosystem, asked)
        for name in sorted(asked):
            assert PackageIntel.is_known_package(ecosystem, name) == expected[name], (
                ecosystem,
                name,
            )
        # The batch answer is the per-name one: checked on a sample, where each costs a full pass.
        for name in sorted(asked)[:: max(1, len(asked) // 40)]:
            assert Reference.is_known(ecosystem, name) == expected[name], (ecosystem, name)
        assert ecosystem == "no-such-ecosystem" or known >= len(names)  # not vacuous

    def test_a_replaced_list_is_read_again(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert not PackageIntel.is_known_package("npm", "zz-added-for-this-test")
        replaced = {**PackageIntel.POPULAR_PACKAGES}
        replaced["npm"] = replaced.get("npm", frozenset()) | {"zz-added-for-this-test"}
        monkeypatch.setattr(PackageIntel, "POPULAR_PACKAGES", replaced)
        assert PackageIntel.is_known_package("npm", "zz-added-for-this-test")


class TestTheLookupCost:
    """A lookup is a set membership: the known names are normalised once per set of lists, not on
    every call. Before, each call normalised every candidate -- 17.7 million normalisations for the
    1,020 names of one package-lock, 34 of a 35 s scan."""

    def test_a_thousand_lookups_normalise_each_name_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        implementation = EcosystemRegistry.get("npm")
        assert implementation is not None
        calls = [0]
        normalize = type(implementation).normalize_name

        def counted(self, name: str) -> str:
            calls[0] += 1
            return normalize(self, name)

        monkeypatch.setattr(type(implementation), "normalize_name", counted)
        getattr(PackageIntel, "_KNOWN", {}).pop("npm", None)  # (no such store before the fix)
        candidates = len(
            PackageIntel.POPULAR_PACKAGES.get("npm", frozenset())
            | REAL_PACKAGES.get("npm", frozenset())
            | PackageIntel._KNOWN_NEIGHBOURS.get("npm", frozenset())
        )
        for n in range(1000):
            PackageIntel.is_known_package("npm", f"zz-not-a-package-{n}")
        assert calls[0] <= candidates, (calls[0], candidates)
