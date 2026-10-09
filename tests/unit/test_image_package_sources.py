"""What the 200-image comparison with Syft found Cordon did not read (`bench/image_agreement.py`).

* Wolfi and Chainguard keep apk's database at `usr/lib/apk/db/installed`; Cordon read none of
  their packages, then content-scanned the Go toolchain those packages install as if the image's
  own code (354 npm "dependencies" from a lockfile in Go's test data).
* Arch's pacman and Gentoo's portage databases were not read at all.
* A runtime installed from its release tarball (the official python, node, golang and
  eclipse-temurin images) had no version anywhere in the inventory.
* A Python package or jar the distribution installed was left out: its path is the distribution's.
* An aliased npm package (`wrap-ansi-cjs` -> wrap-ansi@7), Yarn 1 under /opt, a Go binary's own
  module, a jar with no pom.properties, and BusyBox copied in on its own.

Every fixture is package metadata or a version banner; none is code.
"""

from __future__ import annotations

import json

from test_binmeta import BinaryFixtures

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.images import oci
from cordon_scanner.images.binmeta import BinaryMetadata
from cordon_scanner.images.langpkgs import LanguagePackages
from cordon_scanner.images.packages import PackageDatabases
from imagekit import ImageKit

PACMAN_DESC = b"""%NAME%
acl

%VERSION%
2.4.0-1

%BASE%
acl

%ARCH%
x86_64

%REASON%
1

%DEPENDS%
glibc
attr>=2.5

%PROVIDES%
libacl.so=1-64

"""


class SourceHelpers:
    @staticmethod
    def inventory(files: dict[str, bytes | None]) -> oci.ImageInventory:
        data = ImageKit.docker_save([ImageKit.layer(files)])
        inventory = oci.ImageLayers.read_image(data)
        list(
            oci.ImageLayers.added_files(
                data, inventory, max_file_bytes=8 << 20, max_total_bytes=256 << 20
            )
        )
        return inventory

    @staticmethod
    def purls(files: dict[str, bytes | None], tmp_path) -> set[str]:
        image = tmp_path / "image.tar"
        image.write_bytes(ImageKit.docker_save([ImageKit.layer(files)]))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(image)
        return {d.purl.split("?", 1)[0] for d in result.dependencies}


class TestWolfi:
    def test_the_merged_usr_apk_database_is_read(self, tmp_path) -> None:
        installed = b"P:busybox\nV:1.38.0-r2\nA:x86_64\no:busybox\nF:usr/bin\nR:busybox\n\n"
        purls = SourceHelpers.purls(
            {
                "etc/os-release": b"ID=wolfi\nVERSION_ID=20230201\n",
                "usr/lib/apk/db/installed": installed,
            },
            tmp_path,
        )
        assert "pkg:apk/wolfi/busybox@1.38.0-r2" in purls

    def test_what_its_packages_install_is_theirs(self) -> None:
        installed = b"P:go\nV:1.25.0-r0\no:go\nF:usr/lib/go/src/cmd\nR:package-lock.json\n\n"
        inventory = SourceHelpers.inventory(
            {"usr/lib/apk/db/installed": installed, "usr/lib/go/src/cmd/package-lock.json": b"{}"}
        )
        assert "usr/lib/go/src/cmd/package-lock.json" in inventory.owned


class TestArch:
    def test_a_pacman_record(self) -> None:
        [package] = PackageDatabases.pacman({"var/lib/pacman/local/acl-2.4.0-1/desc": PACMAN_DESC})
        assert (package.name, package.version, package.arch) == ("acl", "2.4.0-1", "x86_64")
        assert package.requires == ("glibc", "attr") and package.provides == ("libacl.so",)
        assert package.requested is False  # %REASON% 1: installed as a dependency

    def test_its_purl_and_files(self, tmp_path) -> None:
        files = {
            "etc/os-release": b"ID=arch\n",
            "var/lib/pacman/local/acl-2.4.0-1/desc": PACMAN_DESC,
            "var/lib/pacman/local/acl-2.4.0-1/files": b"%FILES%\nusr/\nusr/bin/\nusr/bin/getfacl\n\n",
        }
        assert "pkg:alpm/arch/acl@2.4.0-1" in SourceHelpers.purls(files, tmp_path)
        assert "usr/bin/getfacl" in SourceHelpers.inventory(files).owned


class TestGentoo:
    def test_a_portage_record(self) -> None:
        root = "var/db/pkg/dev-libs/openssl-3.3.2-r1"
        packages = PackageDatabases.portage(
            {
                f"{root}/RDEPEND": b">=sys-libs/zlib-1.2.8-r1:= ssl? ( || ( dev-libs/a sys-libs/b-2.0[abi_x86_64(-)] ) )\n",
                f"{root}/CONTENTS": b"dir /usr\nobj /usr/bin/openssl 0123 1700000000\nsym /usr/lib/libssl.so -> libssl.so.3 1700000000\n",
                f"{root}/SLOT": b"0/3\n",
            }
        )
        [package] = packages
        assert (package.name, package.version) == ("dev-libs/openssl", "3.3.2-r1")
        assert package.requires == ("sys-libs/zlib", "dev-libs/a", "sys-libs/b")
        assert PackageDatabases.portage_owned(
            {
                f"{root}/CONTENTS": b"obj /usr/bin/openssl 0123 1700000000\nsym /usr/lib/libssl.so -> libssl.so.3 1\n"
            }
        ) == {
            "usr/bin/openssl",
            "usr/lib/libssl.so",
        }

    def test_its_purl_names_the_category(self, tmp_path) -> None:
        files = {
            "etc/os-release": b"ID=gentoo\n",
            "var/db/pkg/dev-libs/openssl-3.3.2-r1/SLOT": b"0\n",
        }
        assert "pkg:ebuild/dev-libs/openssl@3.3.2-r1" in SourceHelpers.purls(files, tmp_path)


class TestRuntimesFromTheirOwnReleases:
    def test_each_runtime_names_its_version(self, tmp_path) -> None:
        files = {
            "usr/local/include/python3.12/patchlevel.h": b'#define PY_VERSION "3.12.15"\n',
            "usr/local/include/node/node_version.h": b"#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 23\n#define NODE_PATCH_VERSION 3\n",
            "usr/local/go/VERSION": b"go1.24.13\ntime 2026-09-01T00:00:00Z\n",
            "opt/java/openjdk/release": b'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="17.0.20.1"\nJAVA_RUNTIME_VERSION="17.0.20.1+1"\n',
        }
        purls = SourceHelpers.purls(files, tmp_path)
        assert {
            "pkg:generic/python@3.12.15",
            "pkg:generic/node@22.23.3",
            "pkg:generic/go@1.24.13",
            "pkg:generic/oracle/openjdk@17.0.20.1+1",
        } <= purls

    def test_ruby_and_its_default_gems(self, tmp_path) -> None:
        files = {
            "usr/local/lib/ruby/3.3.0/x86_64-linux/rbconfig.rb": b'  CONFIG["RUBY_PROGRAM_VERSION"] = "3.3.12"\n',
            "usr/local/lib/ruby/gems/3.3.0/specifications/default/json-2.7.2.gemspec": b"# -*- encoding: utf-8 -*-\n",
            "usr/local/lib/ruby/gems/3.3.0/specifications/rake-13.1.0.gemspec": b"# -*- encoding: utf-8 -*-\n",
        }
        purls = SourceHelpers.purls(files, tmp_path)
        assert {"pkg:generic/ruby@3.3.12", "pkg:gem/json@2.7.2", "pkg:gem/rake@13.1.0"} <= purls

    def test_a_runtime_is_not_said_to_be_unchecked_by_a_missing_feed(self, tmp_path) -> None:
        image = tmp_path / "image.tar"
        image.write_bytes(
            ImageKit.docker_save([ImageKit.layer({"usr/local/go/VERSION": b"go1.24.13\n"})])
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(image)
        assert not [f for f in result.findings if f.rule_id == "OPERATIONAL.ADVISORY.NO_FEED.001"]

    def test_busybox_on_its_own_under_any_applets_name(self) -> None:
        banner = b"\x7fELF" + b"\x00" * 60 + b"BusyBox v1.37.0 (2024-09-26 21:31:42 UTC)\x00"
        # The busybox image's tar holds the bytes under whichever hard link it wrote first.
        for path in ("bin/busybox", "bin/["):
            [package] = BinaryMetadata.extract(path, banner)
            assert (package.ecosystem, package.name, package.version) == (
                "runtime",
                "busybox",
                "1.37.0",
            )

    def test_node_from_its_own_strings(self) -> None:
        from cordon_scanner.images.binmeta import BinaryClassifiers

        parts = [b"...https://nodejs.org/download/release/v22.22.0/node-v22.22.0-headers.tar.gz..."]
        [package] = BinaryClassifiers.from_strings("nodejs/bin/node", parts)
        assert package.purl == "pkg:generic/node@22.22.0"
        assert BinaryClassifiers.from_strings("usr/bin/other", parts) == []


class TestWhatTheDistributionInstalled:
    def test_its_python_packages_are_listed_under_both_names(self) -> None:
        """python3-iniparse is the OS package, and its egg-info is PyPI's iniparse as well, as Syft
        lists it: measured on ten images, listing these matched Syft everywhere and skipping
        them did not (odoo 0.85 skipped, 1.0 listed)."""
        egg = b"Metadata-Version: 1.1\nName: iniparse\nVersion: 0.4\n"
        lists = b"/usr/lib/python3.9/site-packages/iniparse-0.4-py3.9.egg-info\n/usr/lib/python3.9/site-packages/iniparse/__init__.py\n"
        inventory = SourceHelpers.inventory(
            {
                "var/lib/dpkg/status": ImageKit.dpkg_stanza("python3-iniparse", "0.4-1").encode(),
                "var/lib/dpkg/info/python3-iniparse.list": lists,
                "usr/lib/python3.9/site-packages/iniparse-0.4-py3.9.egg-info": egg,
                "usr/lib/python3.9/site-packages/iniparse/__init__.py": b"VERSION = '0.4'\n",
            }
        )
        assert ("pypi", "iniparse", "0.4") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }
        assert "python3-iniparse" in {p.name for p in inventory.packages}
        assert inventory.added_files == 0


class TestNpm:
    def test_an_aliased_package_is_the_package_it_names(self) -> None:
        package = LanguagePackages.parse(
            "usr/local/lib/node_modules/npm/node_modules/wrap-ansi-cjs/package.json",
            json.dumps({"name": "wrap-ansi", "version": "7.0.0"}).encode(),
        )
        assert package is not None and (package.name, package.version) == ("wrap-ansi", "7.0.0")

    def test_a_fixture_inside_a_package_is_still_not_one(self) -> None:
        assert (
            LanguagePackages.parse(
                "app/node_modules/left-pad/test/fixtures/package.json",
                json.dumps({"name": "fixture", "version": "1.0.0"}).encode(),
            )
            is None
        )

    def test_yarn_under_opt(self) -> None:
        path = "opt/yarn-v1.22.22/package.json"
        assert LanguagePackages.is_metadata(path)
        package = LanguagePackages.parse(
            path, json.dumps({"name": "yarn", "version": "1.22.22"}).encode()
        )
        assert package is not None and package.purl == "pkg:npm/yarn@1.22.22"


class TestCompiledArtefacts:
    def test_a_go_binarys_own_module_built_from_a_release(self) -> None:
        modules = "path\tgithub.com/example/tool\nmod\tgithub.com/example/tool\tv1.4.0\th1:abc=\ndep\tgolang.org/x/sys\tv0.20.0\th1:def=\n"
        found = {
            (p.name, p.version)
            for p in BinaryMetadata.go("usr/bin/tool", BinaryFixtures.go_binary(modules))
        }
        assert {("github.com/example/tool", "1.4.0"), ("golang.org/x/sys", "0.20.0")} <= found

    def test_a_module_replaced_by_a_local_directory_is_not_listed(self) -> None:
        modules = (
            "path\tgithub.com/example/tool\nmod\tgithub.com/example/tool\tv1.4.0\th1:abc=\n"
            "dep\tgithub.com/example/xorm\tv1.0.0\th1:def=\n=>\t./pkg/util/xorm\t(devel)\t\n"
        )
        names = {
            p.name for p in BinaryMetadata.go("usr/bin/tool", BinaryFixtures.go_binary(modules))
        }
        assert "github.com/example/xorm" not in names and "./pkg/util/xorm" not in names

    def test_a_jdks_own_jars_are_inventoried(self) -> None:
        jar = BinaryFixtures.jar(
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Version: 1.8.0_504\n"}
        )
        inventory = SourceHelpers.inventory({"opt/java/openjdk/jre/lib/jce.jar": jar})
        assert ("maven", "jce:jce", "1.8.0_504") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }

    def test_a_checkout_build_names_no_release(self) -> None:
        modules = "path\tgithub.com/example/tool\nmod\tgithub.com/example/tool\t(devel)\t\n"
        assert not [
            p
            for p in BinaryMetadata.go("usr/bin/tool", BinaryFixtures.go_binary(modules))
            if p.name == "github.com/example/tool"
        ]

    def test_a_jar_without_maven_metadata_is_named_by_its_file(self) -> None:
        jar = BinaryFixtures.jar(
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Version: 8.14.5\n"}
        )
        [package] = BinaryMetadata.java("opt/gradle/lib/gradle-antlr-8.14.5.jar", jar)
        assert (package.name, package.version, package.named_by_file) == (
            "gradle-antlr:gradle-antlr",
            "8.14.5",
            True,
        )

    def test_a_name_only_jar_is_never_asked_of_a_registry(self, tmp_path) -> None:
        from cordon_scanner.core.inventory import NAMED_BY_FILE

        jar = BinaryFixtures.jar({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
        image = tmp_path / "image.tar"
        image.write_bytes(
            ImageKit.docker_save([ImageKit.layer({"opt/gradle/lib/gradle-core-8.14.5.jar": jar})])
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(image)
        [jar_dependency] = [d for d in result.dependencies if d.name == "gradle-core:gradle-core"]
        assert jar_dependency.resolved_from == NAMED_BY_FILE
