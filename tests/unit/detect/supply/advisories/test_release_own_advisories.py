"""The scanned package's own release is matched against every advisory, not only the malicious ones.

A downloaded release -- an npm tarball, a wheel -- was checked against the malicious-package records
by its own manifest, and its known vulnerabilities were never looked up: `urllib3 1.26.4` downloaded
and scanned before install came back clean, while the same pin in a requirements.txt was flagged
(found writing the install-guard tutorial, 4 Nov). And only the first 20 releases were checked, so a
folder of 25 downloads had five never looked up at all.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.advisories.advisories import DATA_DIR


class ReleaseAdvisoryKit:
    @staticmethod
    def records(ecosystem: str) -> list[dict]:
        with gzip.open(DATA_DIR / f"advisories-{ecosystem}.json.gz") as handle:
            data = json.loads(handle.read())
        return data if isinstance(data, list) else data.get("advisories", data.get("records", []))

    @staticmethod
    def vulnerable(ecosystem: str) -> tuple[str, str]:
        """A release a high or critical vulnerability record names exactly, and nothing calls malicious."""
        malicious = {
            (r["name"].lower(), v)
            for r in ReleaseAdvisoryKit.records(ecosystem)
            if r.get("malicious")
            for v in r.get("versions") or []
        }
        for r in ReleaseAdvisoryKit.records(ecosystem):
            if r.get("malicious") or str(r.get("severity", "")).lower() not in ("high", "critical"):
                continue
            for version in r.get("versions") or []:
                if "/" not in r["name"] and (r["name"].lower(), version) not in malicious:
                    return r["name"], version
        raise AssertionError(f"no exact {ecosystem} vulnerability record")

    @staticmethod
    def malicious(count: int) -> list[tuple[str, str]]:
        found = [
            (r["name"], r["versions"][0])
            for r in ReleaseAdvisoryKit.records("npm")
            if r.get("malicious") and r.get("versions") and "/" not in r["name"]
        ]
        return found[:count]

    @staticmethod
    def rules(root: Path) -> list[str]:
        return [
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False, offline=True))
            .scan(root)
            .findings
        ]


class TestTheReleaseItselfIsCheckedForVulnerabilities:
    def test_an_npm_release(self, tmp_path) -> None:
        name, version = ReleaseAdvisoryKit.vulnerable("npm")
        (tmp_path / "package").mkdir()
        (tmp_path / "package" / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )
        assert "VULNERABLE.PACKAGE.KNOWN.001" in ReleaseAdvisoryKit.rules(tmp_path)

    def test_a_wheel(self, tmp_path) -> None:
        name, version = ReleaseAdvisoryKit.vulnerable("pypi")
        info = tmp_path / f"{name}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
        )
        assert "VULNERABLE.PACKAGE.KNOWN.001" in ReleaseAdvisoryKit.rules(tmp_path)

    def test_a_repository_sharing_the_name_is_not(self, tmp_path) -> None:
        name, version = ReleaseAdvisoryKit.vulnerable("npm")
        (tmp_path / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )
        assert "VULNERABLE.PACKAGE.KNOWN.001" not in ReleaseAdvisoryKit.rules(tmp_path)


class TestEveryReleaseIsLookedUp:
    def test_twenty_five_downloads_are_twenty_five_lookups(self, tmp_path) -> None:
        releases = ReleaseAdvisoryKit.malicious(25)
        assert len(releases) == 25
        for i, (name, version) in enumerate(releases):
            (tmp_path / f"r{i:02d}" / "package").mkdir(parents=True)
            (tmp_path / f"r{i:02d}" / "package" / "package.json").write_text(
                json.dumps({"name": name, "version": version}), encoding="utf-8"
            )
        assert ReleaseAdvisoryKit.rules(tmp_path).count("MALWARE.PACKAGE.KNOWN.001") == 25
