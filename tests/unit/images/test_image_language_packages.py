"""Language packages read from an image's own metadata files (`images/langpkgs`)."""

from __future__ import annotations

import json

import pytest

from cordon_scanner.images.langpkgs import LanguagePackage, LanguagePackages


class _Kit_package_json:
    @staticmethod
    def package_json(name: object, version: object = "1.0.0") -> bytes:
        return json.dumps({"name": name, "version": version}).encode()


package_json = _Kit_package_json.package_json


class TestPackageUrls:
    @pytest.mark.parametrize(
        ("ecosystem", "name", "purl"),
        [
            ("npm", "@scope/pkg", "pkg:npm/%40scope/pkg@1.0"),
            ("npm", "plain", "pkg:npm/plain@1.0"),
            ("maven", "org.x:lib", "pkg:maven/org.x/lib@1.0"),
            ("rubygems", "rake", "pkg:gem/rake@1.0"),
            ("gomod", "golang.org/x/net", "pkg:golang/golang.org/x/net@1.0"),
            ("runtime", "go", "pkg:generic/go@1.0"),
            ("pypi", "requests", "pkg:pypi/requests@1.0"),
        ],
    )
    def test_each_ecosystem_has_its_own_form(self, ecosystem: str, name: str, purl: str) -> None:
        assert LanguagePackage(ecosystem, name, "1.0", "p").purl == purl


class TestWhichFilesAreMetadata:
    @pytest.mark.parametrize(
        "path",
        [
            "usr/lib/python3/site-packages/x-1.dist-info/METADATA",
            "usr/lib/python3/site-packages/x.egg-info/PKG-INFO",
            "usr/lib/python3.9/site-packages/iniparse-0.4-py3.9.egg-info",
            "usr/lib/python3.9/dist-packages/iniparse-0.4-py3.9.egg-info",
            "app/package.json",
            "usr/local/go/VERSION",
            "usr/lib/R/library/stats/DESCRIPTION",
            "var/www/vendor/composer/installed.json",
            "usr/lib/ruby/gems/3.1.0/specifications/rake-13.gemspec",
            "usr/lib/ruby/gems/3.1.0/specifications/default/json-2.6.gemspec",
        ],
    )
    def test_recognised(self, path: str) -> None:
        assert LanguagePackages.is_metadata(path)

    @pytest.mark.parametrize(
        "path",
        [
            "usr/lib/python3/site-packages/x-1.dist-info/RECORD",
            "usr/lib/python3/other/x.egg-info",
            "usr/lib/ruby/gems/3.1.0/gems/rake-13.gemspec",
            "etc/passwd",
        ],
    )
    def test_not_recognised(self, path: str) -> None:
        assert not LanguagePackages.is_metadata(path)


class TestPythonMetadata:
    def test_a_name_and_version_in_the_headers_make_a_package(self) -> None:
        data = b"Metadata-Version: 2.1\nName: Requests\nVersion: 2.25.0\n\nVersion: 9.9\n"
        found = LanguagePackages.parse("s/requests-2.25.0.dist-info/METADATA", data)
        assert found == LanguagePackage(
            "pypi", "requests", "2.25.0", "s/requests-2.25.0.dist-info/METADATA"
        )

    def test_a_field_after_the_body_starts_is_not_a_header(self) -> None:
        data = b"Name: late\n\nVersion: 1.0\n"
        assert LanguagePackages.parse("s/late-1.dist-info/METADATA", data) is None

    def test_a_record_without_a_version_is_no_package(self) -> None:
        assert LanguagePackages.parse("s/x.egg-info/PKG-INFO", b"Name: x\n") is None


class TestNodePackages:
    @pytest.mark.parametrize(
        "data",
        [b"{not json", b"[1]", b'{"name": 3, "version": "1"}', b'{"name": "x", "version": 1}'],
    )
    def test_a_manifest_that_does_not_name_a_package_is_ignored(self, data: bytes) -> None:
        assert LanguagePackages.parse("app/node_modules/x/package.json", data) is None

    def test_an_application_names_itself_outside_node_modules(self) -> None:
        found = LanguagePackages.parse("var/www/app/package.json", package_json("my-app", "3.1.0"))
        assert found == LanguagePackage("npm", "my-app", "3.1.0", "var/www/app/package.json")

    def test_an_application_without_a_name_is_no_package(self) -> None:
        assert LanguagePackages.parse("var/www/app/package.json", package_json("")) is None

    def test_an_installed_package_must_sit_in_the_directory_of_its_name(self) -> None:
        good = LanguagePackages.parse("a/node_modules/x/package.json", package_json("x"))
        assert good is not None and good.name == "x"
        assert (
            LanguagePackages.parse("a/node_modules/x/test/package.json", package_json("y")) is None
        )

    def test_an_alias_installs_under_another_name(self) -> None:
        found = LanguagePackages.parse(
            "a/node_modules/wrap-ansi-cjs/package.json", package_json("wrap-ansi", "7.0.0")
        )
        assert found is not None and found.name == "wrap-ansi"

    def test_a_scoped_package_is_not_an_alias_of_an_unscoped_one(self) -> None:
        assert LanguagePackages.parse("a/node_modules/@s/p/package.json", package_json("p")) is None

    def test_yarn_is_read_where_the_node_image_unpacks_it(self) -> None:
        found = LanguagePackages.parse(
            "opt/yarn-v1.22.19/package.json", package_json("yarn", "1.22.19")
        )
        assert found is not None and found.version == "1.22.19"


class TestOtherEcosystems:
    def test_an_r_description_is_the_packages_own_only_in_its_directory(self) -> None:
        text = b"Package: stats\nVersion: 4.3.1\n  continued: x\n"
        good = LanguagePackages.parse("usr/lib/R/library/stats/DESCRIPTION", text)
        assert good == LanguagePackage(
            "cran", "stats", "4.3.1", "usr/lib/R/library/stats/DESCRIPTION"
        )
        assert LanguagePackages.parse("usr/lib/R/library/other/DESCRIPTION", text) is None
        assert (
            LanguagePackages.parse("usr/lib/R/library/stats/DESCRIPTION", b"Package: stats\n")
            is None
        )

    def test_a_pecl_registry_record(self) -> None:
        record = b'a:1:{s:4:"name";s:5:"redis";s:7:"version";a:1:{s:7:"release";s:5:"6.0.2";}}'
        path = "usr/local/lib/php/.registry/.channel.pecl.php.net/redis.reg"
        assert LanguagePackages.parse(path, record) == LanguagePackage(
            "pecl", "redis", "6.0.2", path
        )
        assert LanguagePackages.parse(path, b"garbage") is None

    def test_a_runtime_file_names_the_runtime(self) -> None:
        found = LanguagePackages.parse("usr/local/go/VERSION", b"go1.22.5\ntime 2024")
        assert found == LanguagePackage("runtime", "go", "1.22.5", "usr/local/go/VERSION")
        assert LanguagePackages.parse("usr/local/go/VERSION", b"unknown") is None

    def test_a_gemspec_names_a_gem_and_anything_else_names_nothing(self) -> None:
        found = LanguagePackages.parse("x/specifications/rake-13.0.6.gemspec", b"")
        assert found == LanguagePackage(
            "rubygems", "rake", "13.0.6", "x/specifications/rake-13.0.6.gemspec"
        )
        assert LanguagePackages.parse("x/readme.txt", b"") is None


class TestComposer:
    PATH = "var/www/vendor/composer/installed.json"

    def test_composer_2_and_composer_1_records_list_every_package(self) -> None:
        entries = [
            {"name": "Vendor/Pkg", "version": "v1.2.3"},
            {"name": "nosuffix", "version": "1"},
        ]
        for document in ({"packages": entries}, entries):
            found = LanguagePackages.parse_all(self.PATH, json.dumps(document).encode())
            assert found == [LanguagePackage("composer", "vendor/pkg", "v1.2.3", self.PATH)]

    def test_damaged_or_odd_records_name_nothing(self) -> None:
        assert LanguagePackages.parse_all(self.PATH, b"{broken") == []
        assert LanguagePackages.parse_all(self.PATH, b'{"packages": "x"}') == []
        mixed = json.dumps(
            {"packages": ["x", {"name": 1, "version": "1"}, {"name": "a/b", "version": 2}]}
        )
        assert LanguagePackages.parse_all(self.PATH, mixed.encode()) == []

    def test_other_files_give_one_package_or_none(self) -> None:
        data = package_json("my-app")
        assert [p.name for p in LanguagePackages.parse_all("var/www/app/package.json", data)] == [
            "my-app"
        ]
        assert LanguagePackages.parse_all("var/www/app/readme", data) == []
