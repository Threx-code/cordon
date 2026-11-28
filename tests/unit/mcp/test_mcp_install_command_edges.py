"""Install commands that name nothing to check, name something that is not a registry package, or name a version that is no version (`mcp/packages.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.mcp.packages import InstallCommand, PackageError, PackageSpec


class TestRefusals:
    def test_a_command_longer_than_the_limit_is_refused(self) -> None:
        with pytest.raises(PackageError, match="longer than 16000 characters"):
            InstallCommand.parse("npm install " + "a" * 16_000)

    def test_a_version_that_is_not_a_version_is_refused_by_name(self) -> None:
        with pytest.raises(PackageError, match="not a valid version for left-pad"):
            PackageSpec.of("npm", "left-pad", "not a version!")

    def test_an_ecosystem_with_no_files_is_refused_when_its_project_is_asked_for(self) -> None:
        with pytest.raises(PackageError, match="unsupported ecosystem"):
            PackageSpec.of("not-an-ecosystem", "x", None)


class TestNothingToCheck:
    @pytest.mark.parametrize(
        "command",
        [
            ";; ;",
            "npm frobnicate left-pad",
            "pip frobnicate requests",
            "pipx frobnicate requests",
            "uv frobnicate requests",
            "pipenv frobnicate requests",
            "composer frobnicate vendor/pkg",
            "dotnet add App.csproj reference Other.csproj",
            "conda frobnicate numpy",
        ],
    )
    def test_a_known_tool_with_a_subcommand_that_installs_nothing_finds_nothing(
        self, command: str
    ) -> None:
        parsed = InstallCommand.parse(command)
        assert parsed.packages == [] and parsed.unchecked == []

    def test_a_conda_install_is_said_to_be_checked_by_scanning_an_environment_file(self) -> None:
        parsed = InstallCommand.parse("conda install numpy")
        assert any("conda" in note for note in parsed.unchecked)


class TestWords:
    def test_an_npm_alias_names_the_real_package_and_the_npm_prefix_is_dropped(self) -> None:
        labels = [
            p.label
            for p in InstallCommand.parse("npm install alias@npm:real@1.0.0 npm:left-pad").packages
        ]
        assert labels == ["npm:real@1.0.0", "npm:left-pad"]

    def test_a_requirement_that_is_not_a_name_is_said_not_a_package_name(self) -> None:
        parsed = InstallCommand.parse("pip install '!!!'")
        assert parsed.unchecked == ["!!!: not a package name"]

    def test_a_source_that_is_not_a_registry_package_is_said_so(self) -> None:
        parsed = InstallCommand.parse("pip install git+https://example.invalid/x.git")
        assert any("not a registry package" in note for note in parsed.unchecked)

    def test_a_version_range_given_as_a_tag_is_chosen_at_install_time(self) -> None:
        spec = InstallCommand.parse("cargo install ripgrep --version ^13").packages[0]
        assert spec.version is None
        assert "a range or tag" in spec.note


class TestStandInProjects:
    def test_an_ecosystem_that_cannot_write_a_project_is_refused_for_pinned_and_for_loose_names(
        self,
    ) -> None:
        from cordon_scanner.mcp.packages import Lockfiles

        spec = PackageSpec("no-such-ecosystem", "x", "1", "")
        with pytest.raises(PackageError, match="unsupported ecosystem"):
            Lockfiles._pinned("no-such-ecosystem", [spec])
        with pytest.raises(PackageError, match="unsupported ecosystem"):
            Lockfiles._loose("no-such-ecosystem", [spec])

    def test_an_ecosystem_that_records_nothing_without_a_version_says_so(self) -> None:
        from cordon_scanner.mcp.packages import Lockfiles

        with pytest.raises(PackageError, match="needs a version"):
            Lockfiles._loose("helm", [PackageSpec("helm", "redis", None, "")])


class TestMoreCommands:
    def test_a_privilege_prefix_with_nothing_after_it_is_nothing(self) -> None:
        parsed = InstallCommand.parse("sudo")
        assert parsed.packages == [] and parsed.unchecked == []

    def test_generic_tools_with_an_unknown_subcommand_and_poetry_with_no_add_find_nothing(
        self,
    ) -> None:
        for command in (
            "cargo frobnicate x",
            "gem frobnicate x",
            "go frobnicate x",
            "poetry frobnicate x",
        ):
            assert InstallCommand.parse(command).packages == [], command

    def test_pipenv_install_names_its_packages(self) -> None:
        assert [p.label for p in InstallCommand.parse("pipenv install requests").packages] == [
            "pypi:requests"
        ]

    def test_a_git_url_given_to_a_generic_tool_is_not_a_registry_package(self) -> None:
        parsed = InstallCommand.parse("cargo install --git https://example.invalid/x.git ripgrep")
        assert parsed.packages or parsed.unchecked

    def test_a_name_the_ecosystem_refuses_is_said_in_the_unchecked_list(self) -> None:
        parsed = InstallCommand.parse("cargo install '!!!'")
        assert parsed.packages == []
        assert parsed.unchecked


class TestTablesTheCodeConsults:
    def test_an_ecosystem_whose_own_purl_type_no_scan_target_takes_is_fetched_by_the_type_that_names_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.mcp.packages import Fetchable
        from cordon_scanner.sources.package import PackageTarget

        monkeypatch.setattr(PackageTarget, "TYPES", {"zzz": "npm"})
        assert Fetchable.kinds() == {"npm": "zzz"}

    def test_an_ecosystem_with_no_archive_source_has_no_package_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.mcp import packages

        monkeypatch.setattr(packages, "FETCHABLE", {})
        assert PackageSpec.of("npm", "left-pad", "1.0.0").purl is None

    def test_a_version_the_ecosystem_normalises_to_nothing_is_no_version(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.mcp import packages

        monkeypatch.setattr(
            packages.RegistryFacts, "normalised_version", staticmethod(lambda eco, v: "")
        )
        assert PackageSpec.of("npm", "left-pad", "v").version is None
