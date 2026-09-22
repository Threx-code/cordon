"""License policy findings, end to end through a real npm lockfile.

`LockEntry.license` is populated only from npm's v2/v3 `packages` map, where
the field is genuinely present in real lockfiles (npm caches it from registry
metadata at lock time) -- these fixtures use that exact shape rather than a
hand-built `Dependency`, so a regression in the lockfile parser's own
`license` extraction is caught here too, not just in the detector's unit
tests.
"""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Category


def lockfile(entries: list[tuple[str, str, str, str | None]]) -> str:
    packages = {"": {"name": "app"}}
    for path, name, version, license_str in entries:
        entry = {
            "version": version,
            "integrity": "sha512-x",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
        if license_str is not None:
            entry["license"] = license_str
        packages[path] = entry
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def project(tmp_path, entries):
    (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(lockfile(entries), encoding="utf-8")
    return tmp_path


def scan(root):
    cfg = Config.default().with_overrides(use_cache=False)
    return Scanner(cfg).scan(root)


class TestCopyleftLicense:
    def test_a_gpl_dependency_is_reported(self, tmp_path) -> None:
        root = project(tmp_path, [("node_modules/gpl-lib", "gpl-lib", "1.0.0", "GPL-3.0-only")])
        findings = [f for f in scan(root).findings if f.rule_id == "POLICY.LICENSE.COPYLEFT.001"]
        assert findings
        assert findings[0].category is Category.POLICY
        assert "gpl-lib" in findings[0].message

    def test_a_common_non_spdx_spelling_is_still_caught(self, tmp_path) -> None:
        root = project(tmp_path, [("node_modules/gpl-lib", "gpl-lib", "1.0.0", "GPLv3")])
        findings = [f for f in scan(root).findings if f.rule_id == "POLICY.LICENSE.COPYLEFT.001"]
        assert findings

    def test_the_finding_anchors_to_the_lockfile(self, tmp_path) -> None:
        root = project(tmp_path, [("node_modules/gpl-lib", "gpl-lib", "1.0.0", "GPL-3.0-only")])
        finding = next(f for f in scan(root).findings if f.rule_id == "POLICY.LICENSE.COPYLEFT.001")
        assert finding.location.path == "package-lock.json"


class TestWeakCopyleftLicense:
    def test_an_lgpl_dependency_is_reported_at_the_weaker_rule(self, tmp_path) -> None:
        root = project(tmp_path, [("node_modules/lgpl-lib", "lgpl-lib", "1.0.0", "LGPL-2.1-only")])
        findings = scan(root).findings
        assert any(f.rule_id == "POLICY.LICENSE.WEAK_COPYLEFT.001" for f in findings)
        assert not any(f.rule_id == "POLICY.LICENSE.COPYLEFT.001" for f in findings)


class TestPermissiveAndUnknownLicenses:
    def test_a_permissive_license_is_not_reported(self, tmp_path) -> None:
        root = project(tmp_path, [("node_modules/mit-lib", "mit-lib", "1.0.0", "MIT")])
        findings = [f for f in scan(root).findings if f.rule_id.startswith("POLICY.LICENSE.")]
        assert not findings

    def test_a_dependency_with_no_license_field_is_not_reported(self, tmp_path) -> None:
        """`None` means the lockfile carried no data, not "no license"."""
        root = project(tmp_path, [("node_modules/unknown-lib", "unknown-lib", "1.0.0", None)])
        findings = [f for f in scan(root).findings if f.rule_id.startswith("POLICY.LICENSE.")]
        assert not findings

    def test_an_unrecognised_license_string_is_not_reported(self, tmp_path) -> None:
        root = project(
            tmp_path, [("node_modules/custom-lib", "custom-lib", "1.0.0", "Some Custom EULA")]
        )
        findings = [f for f in scan(root).findings if f.rule_id.startswith("POLICY.LICENSE.")]
        assert not findings


class TestTaxonomy:
    def test_both_rules_are_classified_under_the_dependency_domain(self) -> None:
        from cordon_scanner.core.taxonomy import ThreatDomain, domain_of
        from cordon_scanner.detect.license import COPYLEFT_RULE, WEAK_COPYLEFT_RULE

        assert domain_of(COPYLEFT_RULE) is ThreatDomain.DEPENDENCY
        assert domain_of(WEAK_COPYLEFT_RULE) is ThreatDomain.DEPENDENCY
