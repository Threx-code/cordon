"""Container images: the OS inventory as the top layer leaves it, and matching it through OSV."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.images import oci, osv
from cordon_scanner.images import packages as pkgdb
from cordon_scanner.intel import exploited
from imagekit import (
    ALPINE_RELEASE,
    DEBIAN_RELEASE,
    ROCKY_RELEASE,
    bdb_packages,
    docker_save,
    dpkg_stanza,
    layer,
    ndb_packages,
    oci_layout,
    rpm_header,
    rpmdb,
)

STATUS = "var/lib/dpkg/status"


def _names(inventory) -> dict[str, str]:
    return {p.name: p.version for p in inventory.packages}


class TestLayers:
    def test_the_top_layer_s_database_wins(self) -> None:
        base = layer(
            {
                "etc/os-release": DEBIAN_RELEASE,
                STATUS: (
                    dpkg_stanza("openssl", "3.0.9-1") + "\n" + dpkg_stanza("curl", "7.88.1-10")
                ).encode(),
            }
        )
        upgrade = layer(
            {STATUS: dpkg_stanza("openssl", "3.0.11-1~deb12u2").encode()}, compress="gzip"
        )
        inventory = oci.read_image(docker_save([base, upgrade]))
        assert _names(inventory) == {"openssl": "3.0.11-1~deb12u2"}
        assert inventory.release.osv_ecosystem == "Debian:12"
        assert inventory.layers == 2 and not inventory.problems

    def test_a_whiteout_deletes_the_database(self) -> None:
        base = layer(
            {
                "etc/os-release": ALPINE_RELEASE,
                "lib/apk/db/installed": b"P:musl\nV:1.2.4-r1\no:musl\n\n",
            }
        )
        removed = layer({"lib/apk/db/installed": None})
        assert oci.read_image(docker_save([base, removed])).packages == []

    def test_an_opaque_directory_empties_what_was_under_it(self) -> None:
        base = layer(
            {
                STATUS: dpkg_stanza("a", "1").encode(),
                "var/lib/dpkg/status.d/b": dpkg_stanza("b", "2").encode(),
            }
        )
        opaque = layer({"var/lib/dpkg/.wh..wh..opq": b""})
        assert oci.read_image(docker_save([base, opaque])).packages == []

    def test_a_removed_package_is_not_reported(self) -> None:
        stanza = dpkg_stanza("telnet", "0.17", status="deinstall ok config-files")
        inventory = oci.read_image(docker_save([layer({STATUS: stanza.encode()})]))
        assert inventory.packages == []

    def test_distroless_status_d_and_source_versions(self) -> None:
        files = {
            "etc/os-release": DEBIAN_RELEASE,
            "var/lib/dpkg/status.d/libssl3": dpkg_stanza(
                "libssl3", "3.0.11-1~deb12u2+b1", source="openssl (3.0.11-1~deb12u2)", status=""
            ).encode(),
        }
        [package] = oci.read_image(docker_save([layer(files)])).packages
        assert (package.advisory_name, package.advisory_version) == ("openssl", "3.0.11-1~deb12u2")
        assert package.purl(pkgdb.os_release(DEBIAN_RELEASE)) == (
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2+b1?arch=amd64&distro=debian-12&upstream=openssl"
        )

    @pytest.mark.parametrize("nested", [False, True])
    def test_an_oci_layout(self, nested) -> None:
        image = oci_layout(
            [
                layer(
                    {
                        "etc/os-release": ALPINE_RELEASE,
                        "lib/apk/db/installed": b"P:libcrypto3\nV:3.1.4-r0\no:openssl\nA:x86_64\n\n",
                    }
                )
            ],
            nested_index=nested,
        )
        [package] = oci.read_image(image).packages
        assert (package.advisory_name, package.version) == ("openssl", "3.1.4-r0")

    def test_a_zstd_layer_is_reported_not_skipped(self) -> None:
        inventory = oci.read_image(docker_save([layer({STATUS: b""}, compress="zstd")]))
        assert any("zstd" in p for p in inventory.problems)

    def test_an_unreadable_legacy_rpm_database_is_reported_not_guessed(self) -> None:
        inventory = oci.read_image(docker_save([layer({"var/lib/rpm/Packages": b"\x00" * 64})]))
        assert any("was not read" in p for p in inventory.problems)

    def test_the_berkeley_db_and_ndb_formats(self) -> None:
        blobs = [
            rpm_header(
                {
                    1000: "glibc",
                    1001: "2.28",
                    1002: "236.el8",
                    1022: "x86_64",
                    1044: "glibc-2.28-236.el8.src.rpm",
                }
            ),
            rpm_header({1000: "bash", 1001: "4.4.20", 1002: "4.el8", 1003: 0, 1022: "x86_64"}),
            rpm_header({1000: "big", 1001: "1", 1002: "1", 1044: "x" * 9000 + "-1-1.src.rpm"}),
        ]
        for path, database in (
            ("var/lib/rpm/Packages", bdb_packages(blobs)),
            ("usr/lib/sysimage/rpm/Packages.db", ndb_packages(blobs)),
        ):
            inventory = oci.read_image(
                docker_save([layer({"etc/os-release": ROCKY_RELEASE, path: database})])
            )
            assert {p.name: p.version for p in inventory.packages} == {
                "glibc": "2.28-236.el8",
                "bash": "4.4.20-4.el8",
                "big": "1-1",
            }, path
            assert not inventory.problems


class TestRpm:
    def test_the_sqlite_database_is_read(self) -> None:
        database = rpmdb(
            [
                {
                    1000: "openssl-libs",
                    1001: "3.0.7",
                    1002: "24.el9",
                    1003: 1,
                    1022: "x86_64",
                    1044: "openssl-3.0.7-24.el9.src.rpm",
                },
                {1000: "gpg-pubkey", 1001: "5a6340b3", 1002: "6229229e"},
                {
                    1000: "bash",
                    1001: "5.1.8",
                    1002: "6.el9_1",
                    1022: "x86_64",
                    1044: "bash-5.1.8-6.el9_1.src.rpm",
                },
            ]
        )
        image = docker_save(
            [layer({"etc/os-release": ROCKY_RELEASE, "var/lib/rpm/rpmdb.sqlite": database})]
        )
        inventory = oci.read_image(image)
        by_name = {p.name: p for p in inventory.packages}
        assert set(by_name) == {"openssl-libs", "bash"}
        assert by_name["openssl-libs"].advisory_version == "1:3.0.7-24.el9"
        assert by_name["openssl-libs"].source == "openssl"
        assert inventory.release.osv_ecosystem == "Rocky Linux:9"

    def test_a_header_that_lies_about_its_size_is_refused(self) -> None:
        with pytest.raises(ValueError):
            pkgdb.rpm_header(b"\x00\x00\x00\x02\x7f\xff\xff\xff" + b"\x00" * 16)


class TestReleases:
    @pytest.mark.parametrize(
        ("text", "ecosystem"),
        [
            (
                'ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n',
                "Ubuntu:22.04:LTS",
            ),
            ('ID=ubuntu\nVERSION_ID="23.10"\nVERSION="23.10 (Mantic Minotaur)"\n', "Ubuntu:23.10"),
            ('ID=almalinux\nVERSION_ID="9.2"\n', "AlmaLinux:9"),
            ('ID="sles"\nVERSION_ID="15.5"\n', "SUSE:Linux Enterprise Server 15 SP5"),
            ('ID="opensuse-leap"\nVERSION_ID="15.5"\n', "openSUSE:Leap 15.5"),
            ("ID=wolfi\n", "Wolfi"),
            ("ID=arch\n", None),
        ],
    )
    def test_osv_ecosystem(self, text, ecosystem) -> None:
        assert pkgdb.os_release(text.encode()).osv_ecosystem == ecosystem


class TestCvss:
    @pytest.mark.parametrize(
        ("vector", "score"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ],
    )
    def test_base_scores_match_the_specification(self, vector, score) -> None:
        assert osv.cvss3_base(vector) == score


def _debian_image() -> bytes:
    status = (
        dpkg_stanza("openssl", "3.0.9-1")
        + "\n"
        + dpkg_stanza("zlib1g", "1:1.2.13.dfsg-1", source="zlib")
    )
    return docker_save([layer({"etc/os-release": DEBIAN_RELEASE, STATUS: status.encode()})])


class FakeOsv:
    def __init__(self) -> None:
        self.batches: list[dict] = []

    def post(self, url, body):
        self.batches.append(body)
        results = []
        for query in body["queries"]:
            vulns = (
                [{"id": "DEBIAN-CVE-2024-1111"}, {"id": "DEBIAN-CVE-2023-0001"}]
                if query["package"]["name"] == "openssl"
                else []
            )
            results.append({"vulns": vulns})
        return {"results": results}

    def get(self, url):
        identifier = url.rsplit("/", 1)[1]
        return {
            "id": identifier,
            "summary": "A flaw.",
            "upstream": [identifier.removeprefix("DEBIAN-")],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
            ],
            "affected": [
                {
                    "package": {"ecosystem": "Debian:12", "name": "openssl"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]}],
                }
            ],
        }


class TestScanningAnImage:
    def test_offline_inventories_and_says_it_did_not_match(self, tmp_path) -> None:
        target = tmp_path / "image.tar"
        target.write_bytes(_debian_image())
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        purls = {d.purl for d in result.dependencies}
        assert (
            "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-12&upstream=zlib"
            in purls
        )
        assert "OPERATIONAL.IMAGE.NOT_MATCHED" in {f.rule_id for f in result.findings}
        assert result.complete

    def test_online_matches_through_osv_and_marks_the_exploited_one(
        self, tmp_path, monkeypatch
    ) -> None:
        fake = FakeOsv()
        real_match = osv.match
        monkeypatch.setattr(
            osv, "match", lambda queries: real_match(queries, post=fake.post, get=fake.get)
        )
        entries = exploited.ExploitedCatalogue._parse(
            exploited.ExploitedCatalogue.build(
                {"vulnerabilities": [{"cveID": "CVE-2024-1111", "dateAdded": "2024-02-01"}]}, []
            )
        )
        monkeypatch.setattr(
            exploited.ExploitedCatalogue,
            "catalogue",
            lambda: exploited.Catalogue(entries, "x", "bundled"),
        )
        target = tmp_path / "image.tar"
        target.write_bytes(_debian_image())
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=False)).scan(
            target
        )
        by_rule = {}
        for finding in result.findings:
            by_rule.setdefault(finding.rule_id, []).append(finding)
        [exploited_finding] = by_rule["VULNERABLE.IMAGE.EXPLOITED.001"]
        [known] = by_rule["VULNERABLE.IMAGE.PACKAGE.001"]
        assert exploited_finding.severity.name == "CRITICAL"
        assert known.severity.name == "HIGH" and "Fixed in 3.0.11-1~deb12u2" in known.message
        assert known.location.package.startswith("pkg:deb/debian/openssl@3.0.9-1")
        assert result.complete, [
            f.rule_id for f in result.findings if f.category.value == "operational"
        ]
        [batch] = fake.batches
        assert {q["package"]["name"] for q in batch["queries"]} == {"openssl", "zlib"}
        assert all(q["package"]["ecosystem"] == "Debian:12" for q in batch["queries"])

    def test_an_unreachable_osv_is_incomplete_not_clean(self, tmp_path, monkeypatch) -> None:
        def down(queries):
            raise osv.OsvError("OSV could not be asked (URLError)")

        monkeypatch.setattr(osv, "match", down)
        target = tmp_path / "image.tar"
        target.write_bytes(_debian_image())
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=False)).scan(
            target
        )
        assert "OPERATIONAL.IMAGE.UNMATCHED" in {f.rule_id for f in result.findings}
        assert not result.complete

    def test_an_ordinary_tarball_is_not_an_image(self, tmp_path) -> None:
        target = tmp_path / "src.tar"
        target.write_bytes(layer({"README.md": b"hello\n"}))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        assert not [f for f in result.findings if "IMAGE" in f.rule_id]


class TestRpmVersionComparison:
    """Vectors from RPM's own test suite (tests/rpmvercmp.at)."""

    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1), ("2.0.1", "2.0.1", 0),
            ("2.0", "2.0.1", -1), ("2.0.1a", "2.0.1", 1), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
            ("10xyz", "10.1xyz", -1), ("xyz10", "xyz10.1", -1), ("xyz.4", "8", -1), ("1b.fc17", "1.fc17", -1),
            ("1.0010", "1.9", 1), ("1.05", "1.5", 0), ("1.0", "1", 1), ("2.50", "2.5", 1),
            ("fc4", "fc.4", 0), ("FC5", "fc4", -1), ("2a", "2.0", -1), ("1.0a", "1.0.1", -1),
            ("1.0~rc1", "1.0", -1), ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc1~git123", "1.0~rc1", -1),
            ("1.0^", "1.0", 1), ("1.0^git1", "1.0", 1), ("1.0^git1", "1.01", -1), ("1.0^git1", "1.0^git2", -1),
            ("1.0^git1", "1.0.1", -1), ("1.0^git1~pre", "1.0^git1", -1), ("1.0~rc1^git1", "1.0~rc1", 1),
        ],
    )  # fmt: skip
    def test_vercmp(self, a, b, expected) -> None:
        from cordon_scanner.images import alas

        assert alas.vercmp(a, b) == expected

    def test_epoch_dominates(self) -> None:
        from cordon_scanner.images import alas

        assert alas.evr_compare(("1", "1.0", "1"), ("0", "9.9", "9")) == 1
        assert alas.evr_compare(("", "1.0", "2.amzn2"), ("0", "1.0", "10.amzn2")) == -1


UPDATEINFO = b"""<?xml version="1.0" ?>
<updates>
 <update type="security"><id>ALAS2-2026-0001</id><title>curl update</title><severity>important</severity>
  <references><reference id="CVE-2026-1111" type="cve"/></references>
  <pkglist><collection>
   <package name="curl" epoch="0" version="8.3.0" release="1.amzn2.0.13" arch="x86_64"/>
   <package name="curl" epoch="0" version="8.3.0" release="1.amzn2.0.13" arch="src"/>
  </collection></pkglist></update>
 <update type="bugfix"><id>ALAS2-2026-0002</id><pkglist><collection>
   <package name="bash" epoch="0" version="9" release="1" arch="x86_64"/></collection></pkglist></update>
</updates>"""


class TestAmazonLinuxAdvisories:
    def test_parse_and_match(self) -> None:
        from cordon_scanner.images import alas
        from cordon_scanner.images.packages import OsPackage

        advisories = alas.parse(UPDATEINFO)
        assert [a.id for a in advisories] == ["ALAS2-2026-0001"], (
            "bug fixes are not security advisories"
        )
        installed = [
            OsPackage("rpm", "curl", "8.3.0-1.amzn2.0.12", "x86_64"),
            OsPackage("rpm", "bash", "4.2.46-34.amzn2", "x86_64"),
        ]
        [match] = alas.affected(installed, advisories)
        assert (match.package.name, match.fixed, match.advisory.severity) == (
            "curl",
            "8.3.0-1.amzn2.0.13",
            "high",
        )
        assert (
            alas.affected([OsPackage("rpm", "curl", "8.3.0-1.amzn2.0.13", "x86_64")], advisories)
            == []
        )

    def test_only_amazon_s_host_is_fetched(self) -> None:
        from cordon_scanner.images import alas

        with pytest.raises(alas.AlasError, match=r"off cdn\.amazonlinux\.com"):
            alas._get("https://example.com/updateinfo.xml")

    def test_amazon_linux_has_a_source(self) -> None:
        release = pkgdb.os_release(b'ID="amzn"\nVERSION_ID="2"\n')
        assert release.advisory_source == "alas"
        assert pkgdb.os_release(b"ID=arch\n").advisory_source is None


class TestWhatTheImageAdds:
    def _image(self, extra: dict[str, bytes]) -> bytes:
        status = dpkg_stanza("coreutils", "9.1-1").encode()
        files = {
            "etc/os-release": DEBIAN_RELEASE,
            STATUS: status,
            "var/lib/dpkg/info/coreutils.list": b"/.\n/bin\n/bin/cat\n/usr/share/doc/coreutils/copyright\n/etc/os-release\n",
            "usr/bin/cat": b"\x7fELF distribution binary",
            "usr/share/doc/coreutils/copyright": b"GPL",
        }
        files.update(extra)
        return docker_save([layer(files)])

    def test_only_unowned_files_are_scanned_and_merged_usr_is_understood(self) -> None:
        data = self._image(
            {"app/server.py": b"print('hi')\n", "usr/local/lib/python3.12/os.py": b"import sys\n"}
        )
        inventory = oci.read_image(data)
        added = dict(
            oci.added_files(data, inventory, max_file_bytes=1 << 20, max_total_bytes=1 << 26)
        )
        assert set(added) == {"app/server.py"}, "usr/bin/cat is owned through /bin/cat"
        assert inventory.skipped == {
            "a Python runtime built into the image": 1,
            "package-manager state and caches": 2,
        }

    def test_language_packages_are_inventoried_not_content_scanned(self) -> None:
        data = self._image(
            {
                "usr/local/lib/python3.12/site-packages/requests-2.25.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n\nbody",
                "usr/local/lib/python3.12/site-packages/requests/api.py": b"import os\n",
                "app/node_modules/lodash/package.json": b'{"name": "lodash", "version": "4.17.15"}',
                "app/node_modules/lodash/test/fixture/package.json": b'{"name": "fixture", "version": "0.0.1"}',
                "usr/local/bundle/specifications/rack-2.2.3.gemspec": b"spec",
            }
        )
        inventory = oci.read_image(data)
        added = dict(
            oci.added_files(data, inventory, max_file_bytes=1 << 20, max_total_bytes=1 << 26)
        )
        assert not any("site-packages" in p or "node_modules" in p for p in added)
        assert {(p.ecosystem, p.name, p.version) for p in inventory.language_packages} == {
            ("pypi", "requests", "2.25.0"),
            ("npm", "lodash", "4.17.15"),
            ("rubygems", "rack", "2.2.3"),
        }

    def test_an_added_loader_is_found_in_a_scan(self, tmp_path) -> None:
        loader = (
            Path(__file__).resolve().parents[2] / "corpus/malicious/xor-decode-loader/loader.py"
        ).read_bytes()
        target = tmp_path / "image.tar"
        target.write_bytes(self._image({"opt/app/loader.py": loader}))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        paths = {f.location.path for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"}
        assert paths == {"image.tar!opt/app/loader.py"}
        assert not [f for f in result.findings if f.rule_id == "POLICY.BINARY.COMMITTED.001"]

    def test_an_installed_vulnerable_language_package_is_matched_offline(self, tmp_path) -> None:
        target = tmp_path / "image.tar"
        target.write_bytes(
            self._image(
                {
                    "app/node_modules/event-stream/package.json": b'{"name": "event-stream", "version": "3.3.6"}'
                }
            )
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        [hit] = [f for f in result.findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"]
        assert hit.location.path == "app/node_modules/event-stream/package.json"

    def test_zstd_layers_are_reported_where_python_cannot_read_them(self) -> None:
        import sys

        inventory = oci.read_image(docker_save([layer({STATUS: b""}, compress="zstd")]))
        if sys.version_info < (3, 14):
            assert any("zstd" in p and "3.14" in p for p in inventory.problems)
