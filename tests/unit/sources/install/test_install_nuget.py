"""NuGet through Cordon (`sources/install/nuget.py`, `cli/commands/install/dotnet.py`)."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest

from cordon_scanner.cli.commands.install.dotnet import DotnetTools
from cordon_scanner.sources.install.nuget import NuGetPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from cordon_scanner.sources.install.registries import InstallRegistries

NUPKG = b"PK\x03\x04 a nupkg"
HASH = base64.b64encode(hashlib.sha512(NUPKG).digest()).decode()


class NuGetKit:
    CSPROJ = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>'

    @staticmethod
    def lock(**extra: Any) -> str:
        return json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "requested": "[13.0.3, )",
                            "resolved": "13.0.3",
                            "contentHash": HASH,
                        },
                        "app.lib": {"type": "Project"},
                        **extra,
                    }
                },
            }
        )

    @staticmethod
    def done(code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, "", stderr)


class TestWhatInstalls:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["restore"], True),
            (["build", "-c", "Release"], True),
            (["build", "--no-restore"], False),
            (["add", "package", "Newtonsoft.Json"], True),
            (["add", "app.csproj", "package", "Newtonsoft.Json"], True),
            (["add", "reference", "../lib/lib.csproj"], False),
            (["tool", "install", "-g", "dotnet-ef"], True),
            (["tool", "list"], False),
            (["--info"], False),
        ],
    )
    def test_the_commands_that_restore_or_install(self, args: list[str], installs: bool) -> None:
        assert NuGetPlanner.installs(args) is installs


class TestTheLock:
    def test_packages_with_their_sha512_and_projects_left_local(self) -> None:
        files = NuGetPlanner.files(NuGetKit.lock())
        assert [(f.name, f.version) for f in files] == [("Newtonsoft.Json", "13.0.3")]
        assert files[0].url == (
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
        )
        files[0].verify(NUPKG)
        with pytest.raises(InstallRefused):
            files[0].verify(NUPKG + b"tampered")

    def test_a_package_without_a_hash_is_refused(self) -> None:
        lock = NuGetKit.lock(Serilog={"type": "Transitive", "resolved": "3.1.1"})
        with pytest.raises(InstallRefused, match="Serilog"):
            NuGetPlanner.files(lock)

    def test_a_name_that_is_not_a_package_id_is_refused(self) -> None:
        with pytest.raises(InstallRefused):
            NuGetPlanner.package_file("../../etc", "1.0.0", b"\0" * 64)


class TestTheProjectResolve:
    def test_the_resolve_downloads_privately_and_a_failure_puts_the_project_back(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "app.csproj").write_text(NuGetKit.CSPROJ, encoding="utf-8")
        seen: list[tuple[list[str], dict[str, str]]] = []

        def runner(
            argv: list[str], cwd: Path, env: dict[str, str]
        ) -> subprocess.CompletedProcess[str]:
            seen.append((argv, env))
            (tmp_path / "app.csproj").write_text("changed", encoding="utf-8")
            (tmp_path / "packages.lock.json").write_text("{}", encoding="utf-8")
            return NuGetKit.done(1, "NU1101: Unable to find package")

        with pytest.raises(InstallRefused, match="NU1101"):
            NuGetPlanner.project(["restore"], runner, "dotnet", tmp_path, tmp_path / "pkgs")
        argv, env = seen[0]
        assert argv[:3] == ["dotnet", "restore", "--use-lock-file"]
        assert env["NUGET_PACKAGES"] == str(tmp_path / "pkgs")
        assert (tmp_path / "app.csproj").read_text(encoding="utf-8") == NuGetKit.CSPROJ
        assert not (tmp_path / "packages.lock.json").exists()

    def test_the_locks_under_the_project_are_read_build_output_skipped(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "app.csproj").write_text(NuGetKit.CSPROJ, encoding="utf-8")

        def runner(
            argv: list[str], cwd: Path, env: dict[str, str]
        ) -> subprocess.CompletedProcess[str]:
            (cwd / "packages.lock.json").write_text(NuGetKit.lock(), encoding="utf-8")
            (cwd / "obj").mkdir(exist_ok=True)
            (cwd / "obj" / "packages.lock.json").write_text("not read", encoding="utf-8")
            return NuGetKit.done()

        plan = NuGetPlanner.project(["build"], runner, "dotnet", tmp_path, tmp_path / "pkgs")
        assert [f.name for f in plan.files] == ["Newtonsoft.Json"]
        assert "saved:app.csproj" in plan.manifests

    def test_the_command_then_runs_in_locked_mode(self) -> None:
        assert NuGetPlanner.locked(["restore"]) == ["restore", "--locked-mode"]
        assert NuGetPlanner.locked(["run", "--", "--port", "1"]) == [
            "run",
            "-p:RestoreLockedMode=true",
            "--",
            "--port",
            "1",
        ]
        assert NuGetPlanner.locked(["add", "package", "x"]) == []


class TestTools:
    def test_the_tool_line_names_one_package_and_its_version(self) -> None:
        names, version = DotnetTools._tool_args(
            ["-g", "dotnet-ef", "--version", "8.0.4", "--tool-path", "/opt/t"]
        )
        assert (names, version) == (["dotnet-ef"], "8.0.4")

    def test_the_catalog_sha512_is_the_tool_package_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers = {
            "https://api.nuget.org/v3-flatcontainer/dotnet-ef/index.json": {
                "versions": ["8.0.4", "9.0.0-rc.1"]
            },
            "https://api.nuget.org/v3/registration5-semver1/dotnet-ef/8.0.4.json": {
                "catalogEntry": "https://api.nuget.org/v3/catalog0/data/x/dotnet-ef.8.0.4.json"
            },
            "https://api.nuget.org/v3/catalog0/data/x/dotnet-ef.8.0.4.json": {
                "id": "dotnet-ef",
                "packageHash": HASH,
                "packageHashAlgorithm": "SHA512",
            },
        }
        monkeypatch.setattr(
            InstallRegistries, "fetch", lambda self, url, eco: json.dumps(answers[url]).encode()
        )
        plan = NuGetPlanner.tool("dotnet-ef", "", InstallRegistries())
        (file,) = plan.files
        assert (file.version, file.requested) == ("8.0.4", True)
        file.verify(NUPKG)

    def test_a_tool_from_another_source_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match=r"nuget\.org only"):
            DotnetTools._tool(
                "dotnet", ["install", "x", "--add-source", "https://evil.invalid"], None
            )  # type: ignore[arg-type]

    def test_the_tool_config_names_only_the_scanned_folder(self, tmp_path: Path) -> None:
        folder = tmp_path / 'a "b" <c>'
        sources = ElementTree.fromstring(NuGetPlanner.tool_config(folder)).find("packageSources")
        assert sources is not None
        assert [child.tag for child in sources] == ["clear", "add"]
        assert sources[1].get("value") == str(folder)
