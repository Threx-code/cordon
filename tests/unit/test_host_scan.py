"""`scan --host`: an installed system's packages (advanced gap M7).

Before this, Cordon read OS packages and global installs only inside container images; a
developer laptop or CI runner had no inventory at all. The probes build a filesystem root from
package metadata only -- a dpkg database, site-packages, a global node_modules, a gem
specification, cargo's install record, a Homebrew receipt, a runtime's version file -- and check
each is read as the image readers read it, matched against advisories, and that nothing outside
the root is followed.
"""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.images.host import HostFilesystem
from imagekit import ImageKit


class HostHelpers:
    @staticmethod
    def root(tmp_path):
        root = tmp_path / "root"
        files = {
            "etc/os-release": b"ID=debian\nVERSION_ID=12\n",
            "var/lib/dpkg/status": ImageKit.dpkg_stanza("libc6", "2.36-9").encode(),
            "usr/lib/python3/dist-packages/requests-2.25.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n",
            "usr/local/lib/node_modules/npm/package.json": json.dumps(
                {"name": "npm", "version": "10.8.2"}
            ).encode(),
            "usr/local/lib/node_modules/npm/node_modules/semver/package.json": json.dumps(
                {"name": "semver", "version": "7.6.3"}
            ).encode(),
            "usr/local/lib/node_modules/npm/docs/package.json": json.dumps(
                {"name": "docs", "version": "0.0.0"}
            ).encode(),
            "var/lib/gems/3.1.0/specifications/rake-13.0.6.gemspec": b"# -*- encoding: utf-8 -*-\n",
            "usr/local/go/VERSION": b"go1.22.5\n",
            "opt/homebrew/Cellar/jq/1.7.1/INSTALL_RECEIPT.json": b"{}",
        }
        for relative, data in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_bytes(data)
        home = tmp_path / "home"
        (home / ".cargo").mkdir(parents=True)
        (home / ".cargo" / ".crates2.json").write_text(
            json.dumps(
                {
                    "installs": {
                        "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {}
                    }
                }
            )
        )
        site = home / ".local/lib/python3.12/site-packages/pyyaml-5.3.dist-info"
        site.mkdir(parents=True)
        (site / "METADATA").write_text("Metadata-Version: 2.1\nName: PyYAML\nVersion: 5.3\n")
        return root, home


class TestTheInventory:
    def test_every_installer_is_read(self, tmp_path) -> None:
        root, home = HostHelpers.root(tmp_path)
        inventory = HostFilesystem(root, home).inventory()
        assert [(p.name, p.version) for p in inventory.packages] == [("libc6", "2.36-9")]
        assert {(p.ecosystem, p.name, p.version) for p in inventory.language_packages} == {
            ("pypi", "requests", "2.25.0"),
            ("pypi", "pyyaml", "5.3"),
            ("npm", "npm", "10.8.2"),
            ("npm", "semver", "7.6.3"),
            ("rubygems", "rake", "13.0.6"),
            ("cargo", "ripgrep", "14.1.0"),
            ("runtime", "go", "1.22.5"),
            ("homebrew", "jq", "1.7.1"),
        }

    def test_a_link_out_of_the_root_is_not_followed(self, tmp_path) -> None:
        root = tmp_path / "root"
        (root / "var/lib/dpkg").mkdir(parents=True)
        outside = tmp_path / "elsewhere-status"
        outside.write_bytes(ImageKit.dpkg_stanza("intruder", "1.0").encode())
        (root / "var/lib/dpkg/status").symlink_to(outside)
        assert HostFilesystem(root).inventory().packages == []


class TestTheScan:
    def test_matched_against_advisories(self, tmp_path) -> None:
        root, home = HostHelpers.root(tmp_path)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan_host(root, home)
        assert result.target_kind == "host"
        # The one gap it admits: no advisory source covers Homebrew, and the jq formula was not
        # checked -- said, not passed.
        degraded = [f for f in result.findings if f.degrades_coverage]
        assert [f.rule_id for f in degraded] == [
            "OPERATIONAL.ADVISORY.NO_FEED.001"
        ] and "homebrew" in degraded[0].message
        vulnerable = {
            f.location.package.split("@")[0]
            for f in result.findings
            if f.rule_id.startswith("VULNERABLE.") and f.location.package
        }
        # PyYAML 5.3 runs arbitrary code from yaml.load (CVE-2020-1747); requests 2.25.0 leaks
        # Proxy-Authorization (CVE-2023-32681).
        assert {"pkg:pypi/pyyaml", "pkg:pypi/requests"} <= vulnerable
