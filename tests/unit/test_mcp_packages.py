"""MCP package checks (`mcp/packages`): install commands read exactly, and each ecosystem's
stand-in lockfile giving the scanner's real verdict for a real affected release."""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cordon_scanner.intel.advisories import AdvisoryDatabase
from cordon_scanner.mcp.packages import (
    ECOSYSTEMS,
    InstallCommand,
    Lockfiles,
    PackageError,
    PackageSpec,
)
from cordon_scanner.mcp.untrusted import Untrusted
from cordon_scanner.mcp.workspace import OutsideWorkspace, Workspace


class Commands:
    @staticmethod
    def labels(command: str) -> list[str]:
        return [p.label for p in InstallCommand.parse(command).packages]


class TestInstallCommands:
    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("npm install left-pad@1.3.0 express", ["npm:left-pad@1.3.0", "npm:express"]),
            ("npm i -D @types/node@20.1.0 --save-exact", ["npm:@types/node@20.1.0"]),
            ("yarn add react@18.2.0", ["npm:react@18.2.0"]),
            ("yarn global add typescript", ["npm:typescript"]),
            ("pnpm add -w lodash@4.17.21", ["npm:lodash@4.17.21"]),
            ("bun add zod", ["npm:zod"]),
            ("npx -y create-react-app my-app", ["npm:create-react-app"]),
            ("npx -p cowsay@1.5.0 cowsay hi", ["npm:cowsay@1.5.0"]),
            ("pnpm dlx degit user/repo", ["npm:degit"]),
            ("npm install alias@npm:real-pkg@2.0.0", ["npm:real-pkg@2.0.0"]),
            ("pip install requests==2.31.0 flask", ["pypi:requests@2.31.0", "pypi:flask"]),
            ("python3 -m pip install 'django[argon2]==4.2.1'", ["pypi:django@4.2.1"]),
            ("pip3 install --user numpy>=1.20", ["pypi:numpy"]),
            ("uv pip install httpx", ["pypi:httpx"]),
            ("uv add pydantic==2.5.0", ["pypi:pydantic@2.5.0"]),
            ("poetry add black", ["pypi:black"]),
            ("pipx install ruff==0.4.0", ["pypi:ruff@0.4.0"]),
            ("uvx mcp-server-fetch", ["pypi:mcp-server-fetch"]),
            ("cargo add serde@1.0.190", ["cargo:serde@1.0.190"]),
            ("cargo install ripgrep --version 14.0.0", ["cargo:ripgrep@14.0.0"]),
            ("gem install rails -v 7.1.0", ["rubygems:rails@7.1.0"]),
            ("bundle add devise", ["rubygems:devise"]),
            ("go get github.com/gin-gonic/gin@v1.9.1", ["gomod:github.com/gin-gonic/gin@v1.9.1"]),
            ("go install golang.org/x/tools/gopls@latest", ["gomod:golang.org/x/tools/gopls"]),
            (
                "dotnet add package Newtonsoft.Json --version 13.0.1",
                ["nuget:Newtonsoft.Json@13.0.1"],
            ),
            ("composer require monolog/monolog:3.5.0", ["composer:monolog/monolog@3.5.0"]),
            ("sudo FOO=1 npm install -g pm2", ["npm:pm2"]),
            ("cd app && npm ci && npm install axios@1.6.0", ["npm:axios@1.6.0"]),
        ],
    )
    def test_packages_are_read_as_the_tool_reads_them(
        self, command: str, expected: list[str]
    ) -> None:
        assert Commands.labels(command) == expected

    def test_sources_that_are_not_registry_names_are_said_not_checked(self) -> None:
        parsed = InstallCommand.parse(
            "npm install git+https://example.invalid/x.git ./local.tgz user/repo && pip install https://example.invalid/a.whl -r reqs.txt"
        )
        assert parsed.packages == []
        assert len(parsed.unchecked) == 5

    def test_a_second_index_is_warned_as_dependency_confusion(self) -> None:
        parsed = InstallCommand.parse(
            "pip install --extra-index-url https://pkgs.example.invalid/simple internal-lib"
        )
        assert [p.label for p in parsed.packages] == ["pypi:internal-lib"]
        assert any("dependency confusion" in w for w in parsed.warnings)

    def test_registry_flags_are_per_tool(self) -> None:
        # -i is pip's index but gem's install directory: only pip's is a warning.
        assert InstallCommand.parse("pip install -i https://idx.example.invalid/simple x").warnings
        assert not InstallCommand.parse("gem install -i /opt/gems rake").warnings

    def test_ranges_are_checked_by_name_and_say_so(self) -> None:
        spec = InstallCommand.parse("pip install 'urllib3<2'").packages[0]
        assert spec.version is None and "range" in spec.note

    def test_commands_that_install_nothing_find_nothing(self) -> None:
        assert InstallCommand.parse("ls -la && echo hi && npm test").packages == []

    def test_system_package_managers_are_said_not_checked(self) -> None:
        assert InstallCommand.parse("brew install jq").unchecked

    def test_unreadable_shell_is_an_error(self) -> None:
        with pytest.raises(PackageError):
            InstallCommand.parse("pip install 'unterminated")


class TestSpecs:
    @pytest.mark.parametrize(
        ("alias", "ecosystem"),
        [
            ("pip", "pypi"),
            ("go", "gomod"),
            ("gem", "rubygems"),
            ("crates.io", "cargo"),
            ("NPM", "npm"),
        ],
    )
    def test_common_names_for_ecosystems(self, alias: str, ecosystem: str) -> None:
        assert PackageSpec.of(alias, "x").ecosystem == ecosystem

    @pytest.mark.parametrize(
        ("ecosystem", "name"),
        [("npm", "../etc/passwd"), ("pypi", "a b"), ("maven", "no-colon"), ("npm", "")],
    )
    def test_unusable_names_are_refused(self, ecosystem: str, name: str) -> None:
        with pytest.raises(PackageError):
            PackageSpec.of(ecosystem, name)

    def test_purls_for_fetchable_ecosystems(self) -> None:
        assert PackageSpec.of("npm", "@scope/x", "1.0.0").purl == "pkg:npm/@scope/x@1.0.0"
        assert PackageSpec.of("maven", "org.a:b", "2").purl == "pkg:maven/org.a/b@2"
        assert PackageSpec.of("cran", "x", "1").purl is None


class Records:
    @staticmethod
    def affected(ecosystem: str) -> tuple[str, str, str]:
        """A real record from the bundled database whose affected version can be named exactly."""
        database = AdvisoryDatabase.bundled()
        database._load(ecosystem)
        names = itertools.islice(database._sources.get(ecosystem, {}), 20000)
        keys = [(ecosystem, name) for name in names] + [
            k for k in database._by_key if k[0] == ecosystem
        ]
        for key in keys[:20000]:
            for advisory in database.for_package(*key):
                if advisory.malicious or not advisory.identifier:
                    continue
                version = (
                    advisory.versions[0]
                    if advisory.versions
                    else (advisory.introduced if advisory.introduced not in (None, "0") else None)
                )
                if (
                    version
                    and advisory.affects(version)
                    and all(c.isalnum() or c in "-_.:/@" for c in advisory.name)
                ):
                    return advisory.name, version, advisory.identifier
        pytest.skip(f"no exact-version {ecosystem} record in this database")


@pytest.mark.slow
class TestLockfilesGiveTheRealVerdict:
    @pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
    def test_a_known_affected_release_is_reported(self, ecosystem: str, tmp_path: Path) -> None:
        name, version, identifier = Records.affected(ecosystem)
        for relative, body in Lockfiles.write([PackageSpec.of(ecosystem, name, version)]).items():
            target = tmp_path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(tmp_path),
                "--offline",
                "--format",
                "json",
                "--no-cache",
                "--severity",
                "info",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        findings = json.loads(run.stdout)["findings"]
        assert any(identifier in json.dumps(f) for f in findings), (
            f"{ecosystem} {name}@{version} {identifier}"
        )


class TestUntrusted:
    def test_invisible_and_direction_characters_are_removed(self) -> None:
        # Built with chr(): the formatter would turn escapes into the characters themselves.
        zero_width, override, tag = chr(0x200B), chr(0x202E), chr(0xE0041)
        text = f"safe{zero_width} text{override} reversed{tag} tag" + chr(7) + " bell"
        cleaned = Untrusted.text(text)
        assert cleaned == "safe text reversed tag bell"
        assert Untrusted.hidden_count(text) == 4

    def test_long_text_is_capped(self) -> None:
        assert len(Untrusted.text("x" * 5000, 100)) == 100

    def test_nested_values_are_cleaned_to_a_bounded_depth(self) -> None:
        zero_width = chr(0x200B)
        value: object = f"{zero_width}deep"
        for _ in range(20):
            value = [value]
        assert zero_width not in json.dumps(Untrusted.tree(value), ensure_ascii=False)


class TestWorkspace:
    def test_paths_resolve_inside_a_root(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        assert Workspace.of([str(tmp_path)]).resolve("a") == (tmp_path / "a").resolve()

    def test_paths_outside_every_root_are_refused(self, tmp_path: Path) -> None:
        with pytest.raises(OutsideWorkspace):
            Workspace.of([str(tmp_path)]).resolve("/etc")
        with pytest.raises(OutsideWorkspace):
            Workspace.of([str(tmp_path)]).resolve("../")

    def test_a_symbolic_link_out_of_the_root_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "escape").symlink_to("/etc")
        with pytest.raises(OutsideWorkspace):
            Workspace.of([str(root)]).resolve("escape")

    def test_a_filesystem_root_cannot_be_a_workspace(self) -> None:
        with pytest.raises(ValueError, match="filesystem root"):
            Workspace.of(["/"])

    def test_without_roots_every_path_is_refused_with_how_to_add_one(self) -> None:
        with pytest.raises(OutsideWorkspace, match="--root"):
            Workspace(()).resolve(".")
