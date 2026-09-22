"""Converting an OSV bulk-export record into `Advisory`, offline.

The network-touching half (`_download`, `sync_ecosystem`, `sync_all` against
the real OSV host) is exercised by `TestSyncAgainstOsv` below, marked
`network` and deselected by default -- the same convention
`test_review_advisories.py::TestAgainstOsv` already uses. Everything else here
runs against synthetic OSV-shaped JSON, because the conversion logic is what
this project controls and what a regression here would actually be in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.intel import osv_import
from cordon_scanner.intel.advisories import (
    DIGESTS_NAME,
    Advisory,
    DatabaseMeta,
    digest_of,
    verify_data_dir,
)


def npm_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "A worked example vulnerability.",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad", "purl": "pkg:npm/left-pad"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.3.0"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}
        ],
        "database_specific": {"severity": "HIGH"},
    }
    record.update(overrides)
    return record


class TestRangeRecords:
    def test_a_range_record_produces_a_range_advisory(self) -> None:
        results = osv_import.advisories_from_osv_record("npm", npm_record())
        assert len(results) == 1
        advisory = results[0]
        assert advisory.name == "left-pad"
        assert advisory.is_range
        assert advisory.introduced == "0"
        assert advisory.fixed == "1.3.0"
        assert not advisory.malicious
        assert advisory.severity == "high"
        assert advisory.identifier == "GHSA-aaaa-bbbb-cccc"
        assert advisory.reference.startswith("https://")

    def test_it_matches_a_version_inside_the_range(self) -> None:
        (advisory,) = osv_import.advisories_from_osv_record("npm", npm_record())
        assert advisory.affects("1.2.0")
        assert not advisory.affects("1.3.0")
        assert not advisory.affects("2.0.0")

    def test_a_second_range_is_not_dropped(self) -> None:
        """Real shape, not invented: PYSEC-2011-28 affects Django on
        `[0, 1.1.3)` *and*, separately, `[1.2, 1.2.4)` -- two entries in one
        `affected[].ranges` array, one fix branch per major line. An earlier
        version of this parser took only the first `ECOSYSTEM` range per
        `affected` entry, so `django==1.2.1` -- inside the second, dropped
        range -- matched nothing at all. Found by re-fetching this exact
        record from the live OSV export and comparing it against what the
        parser produced.
        """
        record = {
            "id": "PYSEC-2011-28",
            "summary": "Django directory traversal.",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "django"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.1.3"}],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.2"}, {"fixed": "1.2.4"}],
                        },
                    ],
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/x"}],
        }
        results = osv_import.advisories_from_osv_record("pypi", record)
        assert len(results) == 2
        assert any(a.affects("1.1.0") for a in results), "the first range was lost"
        assert any(a.affects("1.2.1") for a in results), "the second range was lost"
        assert not any(a.affects("1.1.3") for a in results)  # fixed, first branch
        assert not any(a.affects("1.2.4") for a in results)  # fixed, second branch
        assert all(a.identifier == "PYSEC-2011-28" for a in results)


class TestExactVersionRecords:
    def test_an_explicit_version_list_is_preferred_over_the_range(self) -> None:
        record = npm_record()
        record["affected"][0]["versions"] = ["1.0.0", "1.1.0"]  # type: ignore[index]
        (advisory,) = osv_import.advisories_from_osv_record("npm", record)
        assert not advisory.is_range
        assert advisory.versions == ("1.0.0", "1.1.0")
        assert advisory.affects("1.0.0")
        assert not advisory.affects("1.2.0")


class TestMaliciousIdentifiers:
    def test_a_mal_prefixed_id_is_reported_as_malicious(self) -> None:
        record = npm_record(id="MAL-2024-1234")
        record["affected"][0]["versions"] = ["6.6.6"]  # type: ignore[index]
        (advisory,) = osv_import.advisories_from_osv_record("npm", record)
        assert advisory.malicious

    def test_a_ghsa_id_is_not_malicious(self) -> None:
        (advisory,) = osv_import.advisories_from_osv_record("npm", npm_record())
        assert not advisory.malicious


class TestMultiPackageRecords:
    def test_one_record_naming_two_packages_yields_two_advisories(self) -> None:
        record = npm_record()
        record["affected"].append(  # type: ignore[attr-defined]
            {
                "package": {"ecosystem": "npm", "name": "right-pad"},
                "versions": ["2.0.0"],
            }
        )
        results = osv_import.advisories_from_osv_record("npm", record)
        assert {a.name for a in results} == {"left-pad", "right-pad"}


class TestEcosystemFiltering:
    def test_an_entry_for_a_different_ecosystem_is_skipped(self) -> None:
        record = npm_record()
        results = osv_import.advisories_from_osv_record("pypi", record)
        assert results == ()

    def test_gradle_has_no_direct_osv_mapping(self) -> None:
        assert "gradle" not in osv_import.ECOSYSTEM_OSV_NAMES

    def test_a_non_default_registry_suffix_still_matches(self) -> None:
        """Real shape: 574 of 13,443 Packagist-shaped OSV entries (4.3%) use
        `"Packagist:https://packages.drupal.org/8"`, not bare `"Packagist"`,
        for packages published through Drupal's contrib-module registry.
        Found by scanning a live OSV export for ecosystem strings a plain
        equality check would silently reject."""
        record = {
            "id": "DRUPAL-CONTRIB-2019-019",
            "summary": "Drupal module vulnerability.",
            "affected": [
                {
                    "package": {
                        "name": "drupal/jsonapi",
                        "ecosystem": "Packagist:https://packages.drupal.org/8",
                    },
                    "versions": ["1.24.0"],
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/x"}],
        }
        results = osv_import.advisories_from_osv_record("composer", record)
        assert len(results) == 1
        assert results[0].name == "drupal/jsonapi"

    def test_a_suffix_without_the_colon_separator_does_not_falsely_match(self) -> None:
        """`_same_osv_ecosystem` requires the `:` -- "PackagistFoo" is a
        different, unrelated ecosystem string, not a suffixed variant."""
        record = {
            "id": "X-1",
            "affected": [
                {"package": {"name": "p", "ecosystem": "PackagistFoo"}, "versions": ["1.0.0"]}
            ],
        }
        results = osv_import.advisories_from_osv_record("composer", record)
        assert results == ()

    def test_every_cordon_advisory_ecosystem_but_cocoapods_has_a_mapping(self) -> None:
        expected = {
            "npm",
            "pypi",
            "cargo",
            "gomod",
            "maven",
            "nuget",
            "composer",
            "rubygems",
            "pub",
        }
        assert set(osv_import.ECOSYSTEM_OSV_NAMES) == expected


class TestMalformedRecords:
    """Records arrive from a bulk export this project does not control."""

    @pytest.mark.parametrize(
        "record",
        [
            {},
            {"id": ""},
            {"id": "GHSA-x"},
            {"id": "GHSA-x", "affected": "not-a-list"},
            {"id": "GHSA-x", "affected": [{"package": "not-a-dict"}]},
            {"id": "GHSA-x", "affected": [{"package": {"ecosystem": "npm"}}]},
            {"id": "GHSA-x", "affected": [{"package": {"ecosystem": "npm", "name": ""}}]},
            {
                "id": "GHSA-x",
                "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "ranges": "bad"}],
            },
        ],
    )
    def test_never_raises_and_degrades_to_no_advisory(self, record: dict[str, object]) -> None:
        results = osv_import.advisories_from_osv_record("npm", record)
        assert results == ()


class TestTheDataIsTamperEvident:
    """`MALWARE.DEPENDENCY.KNOWN.001` is the only rule allowed to report
    CONFIRMED confidence, and these files are all that back it. The rule pack
    has a count floor against truncation; the data had nothing at all.

    The attack this closes is not deletion of the database -- that is loud --
    but the quiet removal of a single entry: delist the one npm package being
    shipped that week, leave the other twenty-three thousand in place, and the
    record count still reads healthy while the scan reports clean.
    """

    @staticmethod
    def _written(tmp_path: Path, name: str = "left-pad") -> Path:
        advisory = Advisory(
            ecosystem="npm",
            name=name,
            versions=("1.0.0",),
            malicious=True,
            summary="s",
            reference="https://example.invalid",
            identifier="GHSA-x",
            severity="critical",
        )
        result = osv_import.SyncResult(per_ecosystem={"npm": (advisory,)}, meta=_meta())
        osv_import.write_output(result, tmp_path)
        return tmp_path / "advisories-npm.json"

    def test_a_manifest_is_written_beside_the_data(self, tmp_path: Path) -> None:
        self._written(tmp_path)
        manifest = json.loads((tmp_path / DIGESTS_NAME).read_text(encoding="utf-8"))
        assert "advisories-npm.json" in manifest
        assert "advisories-meta.json" in manifest
        assert DIGESTS_NAME not in manifest

    def test_untouched_data_verifies(self, tmp_path: Path) -> None:
        self._written(tmp_path)
        assert verify_data_dir(tmp_path) == ()

    def test_delisting_one_entry_is_caught(self, tmp_path: Path) -> None:
        path = self._written(tmp_path)
        records = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps([r for r in records if r["name"] != "left-pad"]), "utf-8")
        assert verify_data_dir(tmp_path) == ("advisories-npm.json",)

    def test_deleting_a_file_is_caught_too(self, tmp_path: Path) -> None:
        """The cheapest way to water the database down, and the one a scheme
        that hashed only the files still present would miss entirely."""
        path = self._written(tmp_path)
        path.unlink()
        assert verify_data_dir(tmp_path) == ("advisories-npm.json",)

    def test_no_manifest_means_nothing_to_check(self, tmp_path: Path) -> None:
        """A checkout that never ran the build script has neither, and that is
        normal rather than a failure."""
        (tmp_path / "advisories-npm.json").write_text("[]", encoding="utf-8")
        assert verify_data_dir(tmp_path) == ()

    def test_a_refused_file_is_not_loaded_and_is_recorded(self, tmp_path: Path) -> None:
        """Half-trusted advisory data is worse than none: the count still looks
        healthy, so the absence reads as an absence of findings."""
        path = self._written(tmp_path, name="evil-pkg")
        path.write_text(json.dumps([]), encoding="utf-8")

        recorded = json.loads((tmp_path / DIGESTS_NAME).read_text(encoding="utf-8"))
        assert digest_of(path) != recorded["advisories-npm.json"]
        assert verify_data_dir(tmp_path) == ("advisories-npm.json",)


class TestWriteOutput:
    def test_it_writes_one_file_per_ecosystem_plus_meta(self, tmp_path: Path) -> None:
        advisory = Advisory(
            ecosystem="npm",
            name="left-pad",
            versions=("1.0.0",),
            malicious=False,
            summary="s",
            reference="https://example.invalid",
            identifier="GHSA-x",
            severity="high",
        )
        result = osv_import.SyncResult(per_ecosystem={"npm": (advisory,)}, meta=_meta())
        osv_import.write_output(result, tmp_path)

        npm_file = tmp_path / "advisories-npm.json"
        meta_file = tmp_path / "advisories-meta.json"
        assert npm_file.exists()
        assert meta_file.exists()

        loaded = json.loads(npm_file.read_text(encoding="utf-8"))
        assert loaded == [
            {
                "ecosystem": "npm",
                "name": "left-pad",
                "malicious": False,
                "summary": "s",
                "reference": "https://example.invalid",
                "id": "GHSA-x",
                "versions": ["1.0.0"],
                "severity": "high",
            }
        ]

        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert meta["record_count"] == 1
        assert meta["sources"]

    def test_written_files_are_not_group_or_world_writable(self, tmp_path: Path) -> None:
        """Not a secrecy requirement -- this is public OSV data -- but a
        different local user on a shared machine must not be able to plant
        or tamper with a file this project later reads back and trusts. Same
        reasoning `ScanCache`'s own key file uses, applied here."""
        import stat

        advisory = Advisory(
            ecosystem="npm",
            name="left-pad",
            versions=("1.0.0",),
            identifier="GHSA-x",
            reference="https://example.invalid",
        )
        result = osv_import.SyncResult(per_ecosystem={"npm": (advisory,)}, meta=_meta())
        osv_import.write_output(result, tmp_path)

        for path in (tmp_path / "advisories-npm.json", tmp_path / "advisories-meta.json"):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert not (mode & stat.S_IWGRP), f"{path} is group-writable: {oct(mode)}"
            assert not (mode & stat.S_IWOTH), f"{path} is world-writable: {oct(mode)}"

    def test_a_resync_overwrites_rather_than_failing_on_an_existing_file(
        self, tmp_path: Path
    ) -> None:
        """Not `O_EXCL`: unlike the cache's MAC key, this file is meant to be
        rewritten on every sync, not created once and kept forever."""
        advisory = Advisory(
            ecosystem="npm", name="left-pad", versions=("1.0.0",), reference="https://x.invalid"
        )
        result = osv_import.SyncResult(per_ecosystem={"npm": (advisory,)}, meta=_meta())
        osv_import.write_output(result, tmp_path)
        osv_import.write_output(result, tmp_path)  # must not raise
        assert (tmp_path / "advisories-npm.json").exists()

    def test_the_filtered_flag_round_trips(self, tmp_path: Path) -> None:
        from cordon_scanner.intel.advisories import DatabaseMeta

        advisory = Advisory(
            ecosystem="npm",
            name="left-pad",
            versions=("1.0.0",),
            identifier="GHSA-x",
            reference="https://example.invalid",
        )
        meta = DatabaseMeta(
            built_at="2026-01-01T00:00:00Z", sources=("osv:npm",), record_count=1, filtered=True
        )
        result = osv_import.SyncResult(per_ecosystem={"npm": (advisory,)}, meta=meta)
        osv_import.write_output(result, tmp_path)

        raw = json.loads((tmp_path / "advisories-meta.json").read_text(encoding="utf-8"))
        assert raw["filtered"] is True

        from cordon_scanner.intel.advisories import _read_meta

        assert _read_meta(tmp_path).filtered is True

    def test_the_written_file_round_trips_through_from_file(self, tmp_path: Path) -> None:
        from cordon_scanner.intel.advisories import AdvisoryDatabase

        advisory = Advisory(
            ecosystem="pypi",
            name="example",
            introduced="1.0.0",
            fixed="2.0.0",
            severity="moderate",
            identifier="GHSA-y",
            reference="https://example.invalid",
        )
        result = osv_import.SyncResult(per_ecosystem={"pypi": (advisory,)}, meta=_meta())
        osv_import.write_output(result, tmp_path)

        database = AdvisoryDatabase.from_file(tmp_path / "advisories-pypi.json")
        assert database.matching("pypi", "example", "1.5.0")
        assert not database.matching("pypi", "example", "2.0.0")


def _meta() -> DatabaseMeta:
    return DatabaseMeta(built_at="2026-01-01T00:00:00Z", sources=("osv:npm",), record_count=1)


@pytest.mark.network
class TestSyncAgainstOsv:
    """The check the offline tests cannot make: does the real export still
    have this shape. Deselected by default; run with `pytest -m network`."""

    def test_a_small_ecosystem_downloads_and_parses(self, tmp_path: Path) -> None:
        records = osv_import.sync_ecosystem("pub", tmp_dir=tmp_path)
        assert isinstance(records, tuple)
        # Pub is one of OSV's smaller exports but is not empty.
        assert len(records) > 0
        assert all(a.ecosystem == "pub" for a in records)
