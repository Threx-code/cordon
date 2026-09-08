"""M-06: the advisory layer, which did not exist.

`Category.VULNERABLE` was defined, documented ("A known weakness in something
depended upon. CVE, GHSA, OSV"), threaded through severity floors, policy,
filtering and every reporter -- and emitted by nothing. `Confidence.CONFIRMED`
was documented as reserved for "an exact package-and-version match against the
threat-intelligence database", and no such database existed, so the highest
confidence the model defines was unreachable.
"""

from __future__ import annotations

import json

import pytest

from cordon import Scanner
from cordon.core.config import Config
from cordon.core.errors import ConfigError
from cordon.core.models import Category, Confidence
from cordon.core.registry import Registry
from cordon.detect.advisory import AdvisoryDetector
from cordon.intel.advisories import AdvisoryDatabase


def lockfile(entries) -> str:
    packages = {"": {"name": "app"}}
    for path, name, version in entries:
        packages[path] = {
            "version": version,
            "integrity": "sha512-x",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps({"lockfileVersion": 3, "packages": packages})


@pytest.fixture
def project(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}')
    return tmp_path


def scan(root, detectors=None):
    cfg = Config.default().with_overrides(use_cache=False)
    return Scanner(cfg, detectors=detectors).scan(root)


class TestBundledDatabase:
    def test_it_is_not_empty(self) -> None:
        assert len(AdvisoryDatabase.bundled()) >= 5

    def test_every_record_names_a_reference(self) -> None:
        """So a reader can check it rather than trust it."""
        from cordon.intel.advisories import BUNDLED

        for advisory in BUNDLED:
            assert advisory.reference.startswith("http"), advisory.name
            assert advisory.summary

    def test_it_matches_an_affected_version(self) -> None:
        db = AdvisoryDatabase.bundled()
        assert db.matching("npm", "event-stream", "3.3.6")

    def test_it_does_not_match_a_neighbouring_version(self) -> None:
        """The name is shared with every version that was never compromised."""
        db = AdvisoryDatabase.bundled()
        assert not db.matching("npm", "event-stream", "3.3.5")

    def test_a_dependency_with_no_version_never_matches(self) -> None:
        """Matching one would mean flagging a package by name alone."""
        db = AdvisoryDatabase.bundled()
        assert not db.matching("npm", "event-stream", None)

    def test_the_ecosystem_is_part_of_the_key(self) -> None:
        db = AdvisoryDatabase.bundled()
        assert not db.matching("pypi", "event-stream", "3.3.6")


class TestKnownMaliciousDependency:
    def test_it_is_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        assert "MALWARE.DEPENDENCY.KNOWN.001" in {f.rule_id for f in scan(project).findings}

    def test_it_is_the_one_place_confirmed_is_used(self, project) -> None:
        """An identity match against a recorded incident is the only thing that
        earns it: no inference, no heuristic, no pattern that might mean
        something else."""
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/ua-parser-js", "ua-parser-js", "0.7.29")])
        )
        finding = next(
            f for f in scan(project).findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"
        )
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.category is Category.MALICIOUS

    def test_it_fails_the_build(self, project) -> None:
        from cordon.core.errors import ExitCode
        from cordon.core.policy import PolicyGate

        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        cfg = Config.default().with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(cfg).scan(project), cfg.policy)
        assert verdict.exit_code is ExitCode.FINDINGS

    def test_an_unaffected_version_is_not_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.5")])
        )
        assert "MALWARE.DEPENDENCY.KNOWN.001" not in {f.rule_id for f in scan(project).findings}

    def test_an_ordinary_dependency_is_not_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/express", "express", "4.18.2")])
        )
        assert not [f for f in scan(project).findings if "KNOWN" in f.rule_id]

    def test_the_finding_anchors_to_the_lockfile(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        finding = next(
            f for f in scan(project).findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"
        )
        assert finding.location.path == "package-lock.json"
        assert finding.references


class TestVulnerableCategory:
    """Reachable at last. Previously no code path emitted it."""

    def custom(self, tmp_path, records):
        path = tmp_path / "advisories.json"
        path.write_text(json.dumps(records))
        database = AdvisoryDatabase.from_file(path)
        others = [d for d in Registry().detectors() if d.id != "advisory"]
        return [*others, AdvisoryDetector(database)]

    def test_a_vulnerable_dependency_is_reported(self, project, tmp_path) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/express", "express", "4.18.2")])
        )
        detectors = self.custom(
            tmp_path,
            [
                {
                    "ecosystem": "npm",
                    "name": "express",
                    "versions": ["4.18.2"],
                    "malicious": False,
                    "summary": "A worked example, not a real advisory.",
                    "reference": "https://example.invalid",
                    "id": "TEST-0001",
                }
            ],
        )
        findings = [
            f for f in scan(project, detectors).findings if f.category is Category.VULNERABLE
        ]
        assert findings
        assert findings[0].confidence is Confidence.CONFIRMED

    def test_a_supplied_database_replaces_the_bundled_one(self, project, tmp_path) -> None:
        """An organisation supplying its own is stating what it considers
        authoritative; merging a shipped list in would produce findings it did
        not choose to act on."""
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        detectors = self.custom(tmp_path, [])
        assert not [f for f in scan(project, detectors).findings if "KNOWN" in f.rule_id]


class TestLoadingAnExport:
    def test_a_malformed_file_is_a_config_error(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json")
        with pytest.raises(ConfigError):
            AdvisoryDatabase.from_file(path)

    def test_a_non_list_document_is_refused(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text('{"ecosystem": "npm"}')
        with pytest.raises(ConfigError, match="list"):
            AdvisoryDatabase.from_file(path)

    def test_a_missing_field_names_the_entry(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text('[{"ecosystem": "npm", "name": "x"}]')
        with pytest.raises(ConfigError, match="entry 0"):
            AdvisoryDatabase.from_file(path)

    def test_a_well_formed_export_loads(self, tmp_path) -> None:
        path = tmp_path / "ok.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "ecosystem": "pypi",
                        "name": "example",
                        "versions": ["1.0.0"],
                        "malicious": True,
                        "summary": "s",
                        "reference": "https://example.invalid",
                        "id": "X-1",
                    }
                ]
            )
        )
        database = AdvisoryDatabase.from_file(path)
        assert len(database) == 1
        assert database.matching("pypi", "example", "1.0.0")
