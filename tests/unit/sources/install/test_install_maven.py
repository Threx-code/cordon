"""Maven through Cordon (`sources/install/managers/maven.py`, `cli/commands/install/maven.py`)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.maven import MavenPlanner
from cordon_scanner.sources.install.plan import InstallRefused

SHA1 = "4bfc12adfe4842bf07b657f0369c4cb522955686"


class MavenKit:
    @staticmethod
    def artifact(
        repo: Path, origin: str = "central-8fac3ebd6edbaca3c794783fa38088af0aa128e7"
    ) -> Path:
        folder = repo / "commons-logging" / "commons-logging" / "1.2"
        folder.mkdir(parents=True)
        jar = folder / "commons-logging-1.2.jar"
        jar.write_bytes(b"PK jar")
        (folder / "commons-logging-1.2.jar.sha1").write_text(
            SHA1 + "  commons-logging-1.2.jar\n", encoding="utf-8"
        )
        (folder / "commons-logging-1.2.pom").write_text("<project/>", encoding="utf-8")
        (folder / "_remote.repositories").write_text(
            f"#NOTE\ncommons-logging-1.2.jar>{origin}=\ncommons-logging-1.2.pom>{origin}=\n",
            encoding="utf-8",
        )
        return jar


class TestWhatBuilds:
    @pytest.mark.parametrize(
        ("args", "builds"),
        [
            (["package"], True),
            (["-B", "clean", "install", "-DskipTests"], True),
            (["dependency:tree"], True),
            (["clean"], False),
            (["-v"], False),
            (["--help"], False),
        ],
    )
    def test_the_commands_that_resolve_and_run(self, args: list[str], builds: bool) -> None:
        assert MavenPlanner.installs(args) is builds


class TestTheRepository:
    def test_every_jar_is_held_to_centrals_sha1(self, tmp_path: Path) -> None:
        MavenKit.artifact(tmp_path)
        known: set[str] = set()
        (file,) = MavenPlanner.plan(tmp_path, known).files
        assert (file.name, file.version, file.algorithm) == (
            "commons-logging:commons-logging",
            "1.2",
            "sha1",
        )
        assert file.url == (
            "https://repo.maven.apache.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
        )
        assert file.digest == bytes.fromhex(SHA1)
        assert MavenPlanner.plan(tmp_path, known).files == []  # each jar is checked once

    def test_the_older_origin_spelling_is_central_too(self, tmp_path: Path) -> None:
        MavenKit.artifact(tmp_path, origin="central")
        assert len(MavenPlanner.plan(tmp_path, set()).files) == 1

    def test_a_jar_from_another_repository_is_refused(self, tmp_path: Path) -> None:
        MavenKit.artifact(tmp_path, origin="corp-nexus")
        with pytest.raises(InstallRefused, match="other than Maven Central"):
            MavenPlanner.plan(tmp_path, set())

    def test_the_scanned_bytes_are_what_the_build_reads(self, tmp_path: Path) -> None:
        repo, scanned, local = tmp_path / "repo", tmp_path / "scanned", tmp_path / "local"
        MavenKit.artifact(repo)
        scanned.mkdir()
        (file,) = MavenPlanner.plan(repo, set()).files
        (scanned / file.filename).write_bytes(b"scanned bytes")
        MavenPlanner.seed(repo, [file], scanned, local)
        folder = local / "commons-logging" / "commons-logging" / "1.2"
        assert (folder / "commons-logging-1.2.jar").read_bytes() == b"scanned bytes"
        assert (folder / "commons-logging-1.2.pom").read_text(encoding="utf-8") == "<project/>"


class TestTheBuild:
    def test_extensions_are_refused_before_anything_runs(self, tmp_path: Path) -> None:
        (tmp_path / "pom.xml").write_text(
            "<project><build><extensions>\n <extension><groupId>x</groupId></extension>"
            "</extensions></build></project>",
            encoding="utf-8",
        )
        with pytest.raises(InstallRefused, match="extensions"):
            MavenPlanner.go_offline(["package"], lambda *a: None, "mvn", tmp_path, tmp_path / "r")  # type: ignore[arg-type,return-value]

    def test_the_resolve_keeps_profiles_and_properties_not_the_local_repository(self) -> None:
        args = ["-P", "ci", "-DskipTests", "-Dmaven.repo.local=/x", "-pl", "core", "package"]
        assert MavenPlanner.resolve_args(args) == ["-P", "ci", "-DskipTests", "-pl", "core"]

    def test_an_artifact_the_offline_build_stopped_on_is_named(self) -> None:
        output = (
            "[ERROR] Failed to execute goal ... The following artifacts could not be resolved: "
            "org.apache.maven.surefire:surefire-junit-platform:jar:3.6.0 (absent): Cannot access "
            "central in offline mode"
        )
        assert MavenPlanner.missing(output) == [
            ("org.apache.maven.surefire", "surefire-junit-platform", "3.6.0")
        ]

    def test_the_build_runs_offline(self) -> None:
        assert MavenPlanner.offline("mvn", ["-o", "package"]) == ["mvn", "--offline", "package"]

    def test_a_failed_resolve_is_a_refusal(self, tmp_path: Path) -> None:
        def runner(
            argv: list[str], cwd: Path, env: dict[str, str]
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 1, "[ERROR] Could not resolve demo:x:1.0", "")

        with pytest.raises(InstallRefused, match="demo:x"):
            MavenPlanner.go_offline(["package"], runner, "mvn", tmp_path, tmp_path / "r")


class TestAVulnerableDependencyThePlanDoesNotInstall:
    """A fetched jar's embedded POM names what Maven resolves from; the plan is what it installs."""

    @staticmethod
    def finding(rule: str, purl: str):
        from types import SimpleNamespace

        location = SimpleNamespace(
            path="maven-artifact-transfer.jar!META-INF/maven/x/y/pom.xml", package=purl
        )
        return SimpleNamespace(rule_id=rule, location=location)

    def test_blocks_only_when_that_package_is_installed(self) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard

        installed = {InstallGuard._identity("org.apache.maven:maven-core", "3.9.9")}
        named = self.finding(
            "VULNERABLE.DEPENDENCY.KNOWN.001", "pkg:maven/org.apache.maven/maven-core@3.0"
        )
        assert not InstallGuard._installs(named, installed)
        installed.add(InstallGuard._identity("org.apache.maven:maven-core", "3.0"))
        assert InstallGuard._installs(named, installed)

    def test_malware_always_blocks(self) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard

        malicious = self.finding("MALWARE.DEPENDENCY.KNOWN.001", "pkg:maven/evil/evil@1.0")
        assert InstallGuard._installs(malicious, set())
