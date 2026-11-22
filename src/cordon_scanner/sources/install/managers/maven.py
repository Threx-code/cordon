"""Maven (`mvn package`, `install`, `test`, ...): every jar, the build's plugins among them, scanned
before a build runs it.

The resolve runs no artifact code: `dependency:go-offline` with the person's profiles and properties,
into a private local repository Cordon deletes, reads POMs and downloads every dependency and plugin
with the checksum Maven Central publishes beside it. Each jar is fetched again from Central, held to
that published sha1 and scanned. The scanned jars (and the POMs and metadata beside them) go into
the person's local repository, and the build runs `--offline`: nothing it loads was not scanned.

go-offline cannot see what a plugin resolves while it runs (surefire picks its JUnit provider at test
time). When the offline build stops on an artifact it has not got, that artifact alone is fetched
into the private repository with `dependency:get`, scanned the same way, and the build runs again.

Maven core and build extensions (`.mvn/extensions.xml`, `<extensions>`) load third-party code before
any goal runs, the resolve included; a project that declares them is refused rather than resolved.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class MavenPlanner:
    CENTRAL: ClassVar[str] = "https://repo.maven.apache.org/maven2"
    #: Options that do not build: nothing is resolved or run.
    INERT: ClassVar[frozenset[str]] = frozenset({"-v", "--version", "-h", "--help"})
    #: Options that change what the build resolves, kept for the resolve.
    RESOLVE_VALUED: ClassVar[frozenset[str]] = frozenset(
        {"-f", "--file", "-P", "--activate-profiles", "-pl", "--projects", "-s", "--settings"}
    )
    #: An artifact the offline build stopped on: `group:artifact:jar[:classifier]:version (absent)`.
    MISSING: ClassVar[re.Pattern[str]] = re.compile(
        r"\b([A-Za-z0-9_.\-]{1,200}):([A-Za-z0-9_.\-]{1,200}):(?:jar|pom|maven-plugin)"
        r"(?::[A-Za-z0-9_.\-]{1,100})?:([A-Za-z0-9_.\-]{1,100})"
        r"(?: \(absent\)| has not been downloaded)"
    )

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        goals = [a for a in args if not a.startswith("-")]
        return bool(goals) and not cls.INERT & set(args) and set(goals) != {"clean"}

    @classmethod
    def refuse_extensions(cls, project: Path) -> None:
        declared = (project / ".mvn" / "extensions.xml").is_file()
        pom = project / "pom.xml"
        if pom.is_file():
            text = re.sub(r"\s", "", pom.read_text(encoding="utf-8", errors="replace"))
            # `<extensions>true</extensions>` on a plugin, or a `<build><extensions>` block.
            declared = declared or "<extensions>true<" in text or "<extensions><extension>" in text
        if declared:
            raise InstallRefused(
                "this project declares Maven extensions, which load third-party code before any "
                "goal runs, the resolve included; Cordon cannot scan them first"
            )

    @classmethod
    def resolve_args(cls, args: Sequence[str]) -> list[str]:
        """The person's options that shape the resolve: profiles, modules, the POM, settings and
        `-D` properties (except the local repository, which is Cordon's here)."""
        kept: list[str] = []
        values = iter(args)
        for arg in values:
            if arg in cls.RESOLVE_VALUED:
                kept += [arg, next(values, "")]
            elif (arg.startswith("-D") and not arg.startswith("-Dmaven.repo.local")) or any(
                arg.startswith(f"{o}=") for o in cls.RESOLVE_VALUED if o.startswith("--")
            ):
                kept.append(arg)
        return kept

    @classmethod
    def go_offline(
        cls, args: Sequence[str], runner: Runner, mvn: str, project: Path, repo: Path
    ) -> None:
        cls.refuse_extensions(project)
        cls._maven(runner, mvn, project, repo, [*cls.resolve_args(args), "dependency:go-offline"])

    @classmethod
    def fetch_missing(
        cls, coordinates: Iterable[tuple[str, str, str]], runner: Runner, mvn: str, project: Path,
        repo: Path,
    ) -> None:  # fmt: skip
        for group, artifact, version in coordinates:
            cls._maven(
                runner, mvn, project, repo,
                ["dependency:get", f"-Dartifact={group}:{artifact}:{version}", "-Dtransitive=true"],
            )  # fmt: skip

    @staticmethod
    def _maven(runner: Runner, mvn: str, project: Path, repo: Path, goal: list[str]) -> None:
        done = runner(
            [mvn, "-B", "-q", f"-Dmaven.repo.local={repo}", *goal], project, {**os.environ}
        )
        if done.returncode != 0:
            raise InstallRefused(
                "Maven could not resolve:\n" + (done.stdout or done.stderr or "").strip()[-2000:]
            )

    @classmethod
    def plan(cls, repo: Path, known: set[str]) -> InstallPlan:
        """Every jar in the private repository not yet checked, held to Central's published sha1."""
        files: list[PackageFile] = []
        for jar in sorted(repo.rglob("*.jar")):
            relative = jar.relative_to(repo).as_posix()
            if relative in known:
                continue
            known.add(relative)
            files.append(cls.package_file(repo, jar))
        return InstallPlan("maven", files)

    @classmethod
    def package_file(cls, repo: Path, jar: Path) -> PackageFile:
        relative = jar.relative_to(repo)
        parts = relative.parts
        if len(parts) < 4:
            raise InstallRefused(f"{relative.as_posix()} is not where Maven keeps an artifact")
        group, artifact, version = ".".join(parts[:-3]), parts[-3], parts[-2]
        remote = jar.parent / "_remote.repositories"
        origin = remote.read_text(encoding="utf-8", errors="replace") if remote.is_file() else ""
        # `central=`, or `central-<hash>=` from newer resolvers. A mirror calling itself central is
        # caught after: every jar is fetched again from Central itself and held to this sha1.
        if not re.search(rf"^{re.escape(jar.name)}>central(?:-[0-9a-f]{{8,64}})?=", origin, re.M):
            raise InstallRefused(
                f"{group}:{artifact}:{version} came from a repository other than Maven Central"
            )
        checksum = jar.with_name(jar.name + ".sha1")
        digest = (
            checksum.read_text(encoding="ascii", errors="replace").split()[0].lower()
            if checksum.is_file()
            else ""
        )
        if not re.fullmatch(r"[0-9a-f]{40}", digest):
            raise InstallRefused(f"{group}:{artifact}:{version} has no sha1 from Maven Central")
        return PackageFile(
            "maven",
            f"{group}:{artifact}",
            version,
            f"{cls.CENTRAL}/{relative.as_posix()}",
            "sha1",
            bytes.fromhex(digest),
            separator=":",
        )

    @classmethod
    def seed(cls, repo: Path, files: Sequence[PackageFile], scanned: Path, local: Path) -> None:
        """The private repository into the person's local one: POMs and metadata as Maven wrote
        them, every jar as the bytes Cordon scanned."""
        jars = {f.url.removeprefix(cls.CENTRAL + "/"): f for f in files}
        for source in repo.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(repo).as_posix()
            target = local / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative in jars:
                target.write_bytes((scanned / jars[relative].filename).read_bytes())
            elif not relative.endswith(".jar"):
                shutil.copyfile(source, target)

    @classmethod
    def missing(cls, output: str) -> list[tuple[str, str, str]]:
        return sorted(set(cls.MISSING.findall(output)))

    @classmethod
    def local_repository(cls, args: Sequence[str], project: Path | None = None) -> Path:
        """Where the build reads artifacts, found as Maven finds it: `-Dmaven.repo.local` on the
        command line, in `MAVEN_ARGS`, `MAVEN_OPTS` or `.mvn/maven.config`; else the user settings'
        `<localRepository>`; else `.m2/repository` under Java's `user.home`."""
        words = [*args, *os.environ.get("MAVEN_ARGS", "").split()]
        words += os.environ.get("MAVEN_OPTS", "").split()
        config = (project or Path.cwd()) / ".mvn" / "maven.config"
        if config.is_file():
            words += config.read_text(encoding="utf-8", errors="replace").split()
        for word in words:
            if word.startswith("-Dmaven.repo.local="):
                return Path(word.partition("=")[2]).expanduser()
        home = cls.java_home(words)
        settings = home / ".m2" / "settings.xml"
        if settings.is_file():
            text = settings.read_text(encoding="utf-8", errors="replace")
            start = text.find("<localRepository>")
            end = text.find("</localRepository>", start)
            value = text[start + len("<localRepository>") : end].strip() if 0 <= start < end else ""
            if value and "${" not in value and len(value) <= 500:
                return Path(value).expanduser()
        return home / ".m2" / "repository"

    @staticmethod
    def java_home(words: Sequence[str]) -> Path:
        """Java's `user.home`: `-Duser.home` if given, else the account's home directory, which is
        not always `$HOME` (Java reads the account database, not the environment)."""
        for word in words:
            if word.startswith("-Duser.home="):
                return Path(word.partition("=")[2]).expanduser()
        try:
            import pwd

            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        except (ImportError, KeyError, AttributeError):
            return Path.home()

    @staticmethod
    def offline(mvn: str, args: Sequence[str]) -> list[str]:
        return [mvn, "--offline", *(a for a in args if a not in ("-o", "--offline"))]


__all__ = ["MavenPlanner"]
