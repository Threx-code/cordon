"""The registry's record of a release, read as of its own publish time (review 98, second review P)."""

from __future__ import annotations

from cordon_scanner.intel.registries.registry_record import RegistryRecord


class Docs:
    @staticmethod
    def packument(**versions: dict) -> dict:
        """An npm packument: `versions` maps a version to (published, metadata)."""
        return {
            "name": "demo",
            "time": {
                "created": min(v["at"] for v in versions.values()),
                **{k[1:].replace("_", "."): v["at"] for k, v in versions.items()},
            },
            "versions": {k[1:].replace("_", "."): v["meta"] for k, v in versions.items()},
        }

    @staticmethod
    def meta(user: str = "alice", **extra: object) -> dict:
        return {"_npmUser": {"name": user}, "maintainers": [{"name": user}], **extra}


class TestAsOfTheRelease:
    def test_a_later_release_does_not_change_what_an_earlier_one_was(self):
        document = Docs.packument(
            v1_0_0={"at": "2026-01-01T00:00:00Z", "meta": Docs.meta()},
            v1_0_1={"at": "2026-01-02T00:00:00Z", "meta": Docs.meta()},
            v2_0_0={"at": "2026-06-01T00:00:00Z", "meta": Docs.meta()},
        )
        record = RegistryRecord.from_npm(document, "1.0.1")
        assert record is not None
        assert record.prior_versions == 1
        assert record.previous_version == "1.0.0"
        assert record.prior_24h == 1

    def test_a_first_release_on_a_new_name(self):
        document = Docs.packument(v99_0_0={"at": "2026-03-03T10:00:00Z", "meta": Docs.meta()})
        facts = RegistryRecord.from_npm(document, "99.0.0").facts()
        assert facts["reg_first_release"] == 1.0
        assert facts["reg_confusion_version"] == 1.0
        assert facts["reg_name_age_days"] == 0.0

    def test_a_version_the_registry_has_no_time_for_is_not_read(self):
        assert (
            RegistryRecord.from_npm(
                Docs.packument(v1_0_0={"at": "2026-01-01T00:00:00Z", "meta": Docs.meta()}), "9.9.9"
            )
            is None
        )


class TestWhatTheReleaseChanged:
    def test_a_hook_and_a_dependency_added_by_an_account_new_to_the_package(self):
        document = Docs.packument(
            v1_0_0={
                "at": "2025-01-01T00:00:00Z",
                "meta": Docs.meta("alice", dependencies={"a": "1"}),
            },
            v1_1_0={
                "at": "2025-06-01T00:00:00Z",
                "meta": Docs.meta("alice", dependencies={"a": "1"}),
            },
            v1_1_1={
                "at": "2026-01-01T00:00:00Z",
                "meta": Docs.meta(
                    "mallory",
                    dependencies={"a": "1", "fresh-helper": "1"},
                    scripts={"postinstall": "node setup.js", "test": "jest"},
                ),
            },
        )
        record = RegistryRecord.from_npm(document, "1.1.1")
        assert record.hooks_added == ("postinstall",)
        assert record.dependencies_added == ("fresh-helper",)
        facts = record.facts()
        assert facts["reg_new_publisher"] == 1.0
        assert facts["reg_name_age_days"] > 360

    def test_the_same_publisher_and_hooks_as_before_add_nothing(self):
        same = Docs.meta("alice", scripts={"install": "node-gyp rebuild"})
        document = Docs.packument(
            v1_0_0={"at": "2025-01-01T00:00:00Z", "meta": same},
            v1_0_1={"at": "2025-02-01T00:00:00Z", "meta": same},
        )
        facts = RegistryRecord.from_npm(document, "1.0.1").facts()
        assert facts["reg_hooks_added"] == 0.0
        assert facts["reg_new_publisher"] == 0.0


class TestPyPI:
    def test_manifest_facts_are_unknown_for_a_release_that_is_not_the_newest(self):
        document = {
            "info": {"name": "demo", "version": "2.0", "author": "a", "home_page": "https://x"},
            "releases": {
                "1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
                "2.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
            },
        }
        old = RegistryRecord.from_pypi(document, "1.0").facts()
        new = RegistryRecord.from_pypi(document, "2.0").facts()
        assert old["reg_manifest_known"] == 0.0 and new["reg_manifest_known"] == 1.0
        assert new["reg_manifest_repository"] == 1.0 and new["reg_prior_versions"] == 1.0


class TestTheStore:
    def test_a_record_round_trips(self, tmp_path):
        record = RegistryRecord.from_npm(
            Docs.packument(
                v1_0_0={
                    "at": "2026-01-01T00:00:00Z",
                    "meta": Docs.meta(scripts={"preinstall": "x"}),
                }
            ),
            "1.0.0",
        )
        record.save(tmp_path)
        assert RegistryRecord.load("npm", "demo", "1.0.0", tmp_path) == record
        assert RegistryRecord.load("npm", "demo", "2.0.0", tmp_path) is None
