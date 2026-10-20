"""What an image holds that Syft found and Cordon did not, read now (bench/image_agreement.py):
installed R packages, PECL extensions, Composer's install record, programs copied in without a
package database, a Go toolchain's own programs, and Maven groups for jars with no metadata."""

from __future__ import annotations

import json

from cordon_scanner.images.binmeta import KnownBinaries, KnownGroups
from cordon_scanner.images.langpkgs import LanguagePackages


class Found:
    @staticmethod
    def of(path: str, data: bytes) -> set[tuple[str, str, str]]:
        assert LanguagePackages.is_metadata(path)
        return {(p.ecosystem, p.name, p.version) for p in LanguagePackages.parse_all(path, data)}


class TestRPackages:
    def test_an_installed_r_package_is_read_from_its_description(self) -> None:
        description = b"Package: jsonlite\nType: Package\nVersion: 1.8.9\nTitle: A Simple\n  and Robust JSON Parser\n"
        assert Found.of("usr/local/lib/R/site-library/jsonlite/DESCRIPTION", description) == {
            ("cran", "jsonlite", "1.8.9")
        }

    def test_a_description_in_a_directory_not_named_for_it_is_not_a_package(self) -> None:
        assert (
            Found.of("usr/lib/R/library/base/DESCRIPTION", b"Package: other\nVersion: 1.0\n")
            == set()
        )


class TestPecl:
    def test_an_installed_extension_is_read_from_the_registry(self) -> None:
        record = (
            b'a:3:{s:4:"name";s:5:"redis";s:7:"version";a:2:{s:7:"release";s:5:"6.1.0";'
            b's:3:"api";s:5:"6.1.0";}s:7:"channel";s:12:"pecl.php.net";}'
        )
        path = "usr/local/lib/php/.registry/.channel.pecl.php.net/redis.reg"
        assert Found.of(path, record) == {("pecl", "redis", "6.1.0")}


class TestComposerInstalled:
    def test_both_formats_of_the_install_record(self) -> None:
        v2 = json.dumps({"packages": [{"name": "Symfony/Console", "version": "v7.1.0"}]}).encode()
        v1 = json.dumps([{"name": "monolog/monolog", "version": "2.9.1"}]).encode()
        path = "var/www/html/vendor/composer/installed.json"
        assert Found.of(path, v2) == {("composer", "symfony/console", "v7.1.0")}
        assert Found.of(path, v1) == {("composer", "monolog/monolog", "2.9.1")}


class TestKnownBinaries:
    ELF = b"\x7fELF" + b"\x00" * 60

    def test_each_program_by_the_version_its_build_embeds(self) -> None:
        cases = {
            "usr/bin/bash": (b"@(#)Bash version 5.2.37(1) release GNU\x00", "bash", "5.2.37"),
            "usr/bin/curl": (b"curl 8.12.1 (x86_64)\x00", "curl", "8.12.1"),
            "usr/bin/openssl": (b"OpenSSL 3.4.1 11 Feb 2025\x00", "openssl", "3.4.1"),
            "usr/lib64/libcrypto.so.3": (b"OpenSSL 3.4.1 11 Feb 2025\x00", "openssl", "3.4.1"),
            "usr/bin/xz": (b"xz (XZ Utils) 5.8.1\x00", "xz", "5.8.1"),
            "usr/bin/zstd": (b"Zstandard CLI\x00v1.5.7\x00", "zstd", "1.5.7"),
            "usr/bin/mount": (b"util-linux 2.40.4\x00", "util-linux", "2.40.4"),
        }
        for path, (strings, program, version) in cases.items():
            found = KnownBinaries.identify(path, TestKnownBinaries.ELF + strings)
            assert [(p.name, p.version) for p in found] == [(program, version)], path

    def test_only_its_own_program_and_only_an_elf(self) -> None:
        assert KnownBinaries.identify("usr/bin/other", self.ELF + b"curl 8.12.1 ") == []
        assert KnownBinaries.identify("usr/bin/curl", b"#!/bin/sh\ncurl 8.12.1 ") == []


class TestKnownGroups:
    def test_a_group_the_advisory_data_records_and_no_guess_otherwise(self) -> None:
        assert KnownGroups.of("ant") == "org.apache.ant"
        assert KnownGroups.of("no-such-artifact-anywhere") is None

    def test_a_module_name_used_as_a_group_drops_the_parts_naming_the_artifact(self) -> None:
        assert (
            KnownGroups.trimmed("org.apache.groovy.cli.commons", "groovy-cli-commons")
            == "org.apache.groovy"
        )
        assert KnownGroups.trimmed("org.apache.groovy.ant", "groovy-ant") == "org.apache.groovy"
        assert KnownGroups.trimmed("com.example.library", "unrelated") == "com.example.library"


class TestPhp:
    def test_the_php_binary_by_the_header_it_sends(self) -> None:
        data = b"\x7fELF" + b"\x00" * 60 + b"X-Powered-By: PHP/8.3.35\x00"
        assert [(p.name, p.version) for p in KnownBinaries.identify("usr/local/bin/php", data)] == [
            ("php-cli", "8.3.35")
        ]

    def test_apaches_php_module_beside_the_cli(self) -> None:
        """Syft's second PHP entry is not a second name for the CLI: it is Apache's module,
        /usr/lib/apache2/modules/libphp.so, whose purl Syft writes as pkg:generic/php."""
        data = b"\x7fELF" + b"\x00" * 60 + b"X-Powered-By: PHP/8.5.11\x00"
        found = KnownBinaries.identify("usr/lib/apache2/modules/libphp.so", data)
        assert [(p.name, p.version) for p in found] == [("php", "8.5.11")]
        assert KnownBinaries.identify("usr/lib/apache2/modules/libphp8.so", data)
        assert KnownBinaries.identify("usr/lib/apache2/modules/mod_ssl.so", data) == []

    def test_the_composer_phar_by_its_own_install_record(self) -> None:
        phar = (
            b"#!/usr/bin/env php\n<?php\n"
            b"'root' => array('pretty_version' => '2.10.3', 'version' => '2.10.3.0'),\n"
            b"'composer/ca-bundle' => array('pretty_version' => '1.5.8'),\n"
        )
        found = KnownBinaries.identify("usr/local/bin/composer", phar)
        assert [(p.name, p.version) for p in found] == [("composer", "2.10.3")]
        assert KnownBinaries.identify("usr/local/bin/composer", b"not a phar") == []


class TestJarGroupsAsSyftNamesThem:
    def test_the_curated_map(self) -> None:
        assert KnownGroups.curated("ant-antlr") == "org.apache.ant"
        assert KnownGroups.curated("bcutil-jdk18on") == "org.bouncycastle"
        assert KnownGroups.curated("no-such-artifact") is None

    def test_the_manifest_as_syft_reads_it(self) -> None:
        assert (
            KnownGroups.from_manifest(
                {"Main-Class": "org.gradle.launcher.daemon.bootstrap.GradleDaemon"}
            )
            == "org.gradle.launcher.daemon.bootstrap.GradleDaemon"
        )
        # Primary fields before secondary; within a tier, the first in sort order; an OSGi
        # directive removed; a value that does not start like a reverse domain ignored.
        manifest = {
            "Bundle-SymbolicName": "org.zeta.bundle;singleton:=true",
            "Implementation-Title": "com.alpha.title",
            "Implementation-Vendor": "The Apache Software Foundation",
            "Automatic-Module-Name": "com.aaa.module",
        }
        assert KnownGroups.from_manifest(manifest) == "com.alpha.title"
        assert KnownGroups.from_manifest({"Implementation-Vendor": "Gpars team"}) is None

    def test_a_jar_naming_its_own_group_is_believed_before_the_map(self) -> None:
        """The map has Groovy 4's jars under org.codehaus.groovy; they state org.apache.groovy."""
        import io
        import zipfile

        from cordon_scanner.images.binmeta import BinaryMetadata

        def jar(manifest: str) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
            return buffer.getvalue()

        groovy = jar("Manifest-Version: 1.0\nAutomatic-Module-Name: org.apache.groovy.ant\n")
        ant = jar("Manifest-Version: 1.0\nImplementation-Vendor: Apache Software Foundation\n")
        found = {
            p.name
            for path, data in (
                ("opt/groovy/lib/groovy-ant-4.0.33.jar", groovy),
                ("opt/groovy/lib/ant-antlr-1.10.15.jar", ant),
            )
            for p in BinaryMetadata.extract(path, data)
        }
        assert {"org.apache.groovy:groovy-ant", "org.apache.ant:ant-antlr"} <= found
