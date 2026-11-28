"""A name that resembles a more popular one reaches the allowlist only when a reviewer kept it or the
registry says it is years old: inflated downloads buy a ratio, never an age."""

from __future__ import annotations

import datetime as dt

import pytest
from refresh_script import RefreshScript

TODAY = dt.date(2026, 11, 28)
OLD = "2019-03-01T00:00:00+00:00"
YOUNG = "2026-10-01T00:00:00+00:00"


class ContestedHelpers:
    """Helpers for test_contested_names.py."""

    @staticmethod
    def run(ranked, ages: dict[str, str] | None, ecosystem: str = "npm"):
        refresh = RefreshScript.module().PackageIntelRefresh
        asked: list[str] = []

        def first_published(name: str) -> str:
            asked.append(name)
            if ages is None:
                raise OSError("registry down")
            return ages.get(name, "")

        kept, refused = refresh.refuse_self_allowlisting(
            ranked, ecosystem=ecosystem, first_published=first_published, today=TODAY
        )
        return kept, refused, asked


class TestAnInflatedSquatIsNotAllowlisted:
    @pytest.mark.parametrize(
        "squat",
        [
            "lodesh",  # a letter changed
            "lodashs",  # a letter added
            "lodsh",  # a letter dropped
            "lo-dash",  # a separator added
        ],
    )
    def test_a_young_look_alike_is_refused_whatever_its_downloads(self, squat: str) -> None:
        # 1/10 of the target's downloads: far past the ratio a squat used to need.
        kept, refused, _ = ContestedHelpers.run(
            [("lodash", 10_000_000), (squat, 1_000_000)], {squat: YOUNG}
        )
        assert kept == ["lodash"]
        assert refused == [f"{squat} ~ lodash (contested; not 2 years old)"]

    def test_a_look_alike_whose_age_cannot_be_read_is_refused(self) -> None:
        kept, refused, _ = ContestedHelpers.run([("lodash", 10_000_000), ("lodesh", 900)], None)
        assert kept == ["lodash"] and len(refused) == 1

    def test_a_look_alike_the_registry_gives_no_date_for_is_refused(self) -> None:
        kept, _, _ = ContestedHelpers.run([("lodash", 10_000_000), ("lodesh", 900)], {})
        assert kept == ["lodash"]

    def test_with_no_way_to_ask_the_age_a_look_alike_is_refused(self) -> None:
        refresh = RefreshScript.module().PackageIntelRefresh
        kept, _ = refresh.refuse_self_allowlisting(
            [("lodash", 10_000_000), ("lodesh", 900)], ecosystem="npm", today=TODAY
        )
        assert kept == ["lodash"]


class TestRealNeighboursStay:
    def test_an_old_look_alike_is_kept(self) -> None:
        kept, refused, _ = ContestedHelpers.run(
            [("chardet", 50_000_000), ("cchardet", 2_000_000)], {"cchardet": OLD}, "pypi"
        )
        assert kept == ["cchardet", "chardet"] and refused == []

    def test_a_reviewed_name_is_kept_without_asking(self) -> None:
        kept, _, asked = ContestedHelpers.run(
            [("rustls", 50_000_000), ("rustis", 10_000)], {}, "cargo"
        )
        assert "rustis" in kept and asked == []

    def test_a_name_like_no_other_costs_no_request(self) -> None:
        kept, refused, asked = ContestedHelpers.run(
            [("express", 9_000_000), ("pandas", 8_000_000)], {}
        )
        assert kept == ["express", "pandas"] and refused == [] and asked == []

    def test_a_strong_slip_past_the_ratio_is_refused_before_any_age(self) -> None:
        _, refused, asked = ContestedHelpers.run(
            [("tqdm", 100_000_000), ("tdqm", 10)], {"tdqm": OLD}, "pypi"
        )
        assert refused == ["tdqm ~ tqdm"] and asked == []


class TestTheRegistryIsAskedInItsOwnSpelling:
    def test_a_lowered_name_is_asked_about_as_the_registry_spells_it(self, monkeypatch) -> None:
        """Hackage's `HTTP` is listed as `http`; asking Hackage about `http` asks about nothing, and the name
        would be refused as of unknown age."""
        refresh = RefreshScript.module().PackageIntelRefresh
        monkeypatch.setattr(refresh, "SPELLINGS", {})
        assert refresh.spelt("HTTP") == "http"
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        asked: list[tuple[str, str]] = []
        monkeypatch.setattr(
            ReleaseHistory,
            "first_published",
            classmethod(lambda cls, ecosystem, name: asked.append((ecosystem, name)) or OLD),
        )
        assert refresh.first_published_of("hackage")("http") == OLD
        assert asked == [("hackage", "HTTP")]
