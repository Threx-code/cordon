"""RubyGems and Bundler: every gem scanned before RubyGems builds its native extension (`extconf.rb`
runs at install) or Bundler loads it.

    gem install <name> [-v V]   `gem install --explain` lists the gems it would install, running none
    bundle install|update|add   `bundle lock` (with `--update`/`--add` as typed) writes Gemfile.lock

Gemfile.lock is saved first and put back if anything blocks (the Gemfile itself is the person's own
Ruby, which Bundler evaluates either way). Each gem's sha256 comes from Gemfile.lock's CHECKSUMS
section when Bundler wrote one, else from rubygems.org's own record of that version; Cordon fetches the
`.gem`, verifies and scans it. Then exactly those files are installed: `gem install --local
--ignore-dependencies <scanned .gem files>`, or `bundle install --local` with the scanned gems as its
cache (`BUNDLE_CACHE_PATH`), so neither reaches the network for a gem Cordon did not read.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


class GemSpec:
    """`name-1.2.3` or `name-1.2.3-x86_64-linux` (a platform gem), as RubyGems spells a full name."""

    FULL: ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]{0,99}?)-(\d[A-Za-z0-9.]{0,49})(?:-([A-Za-z0-9_.-]{1,60}))?$"
    )

    @classmethod
    def split(cls, full: str) -> tuple[str, str, str]:
        m = cls.FULL.match(full)
        if m is None:
            raise InstallRefused(f"{full[:100]!r} is not a gem name RubyGems would write")
        return m.group(1), m.group(2), m.group(3) or ""


class GemPlanner:
    GEM_VERBS: ClassVar[frozenset[str]] = frozenset({"install", "i", "update"})
    BUNDLE_VERBS: ClassVar[frozenset[str]] = frozenset({"install", "update", "add", "lock", "exec"})
    #: `gem install` options that let RubyGems fetch, or change where from, after the scan: the
    #: install that follows runs `--local` from the scanned files only, and these would undo it.
    FETCHING_OPTIONS: ClassVar[frozenset[str]] = frozenset(
        {"-r", "--remote", "-b", "--both", "-s", "--source", "--clear-sources", "--update-sources"}
    )

    @classmethod
    def local_options(cls, args: Sequence[str]) -> list[str]:
        """The user's own `gem install` options, kept for the local install; one that would let
        RubyGems fetch is refused before anything is resolved."""
        options = [a for a in args if a.startswith("-") and a not in {"-v", "--version"}]
        for option in options:
            if option.partition("=")[0] in cls.FETCHING_OPTIONS:
                raise InstallRefused(
                    f"{option.partition('=')[0]} would let RubyGems fetch after Cordon's scan; "
                    "Cordon installs only the files it scanned. Name another gem source with "
                    "--cordon-registry-token instead"
                )
        return options

    SAVED: ClassVar[tuple[str, ...]] = ("Gemfile", "Gemfile.lock")
    HOST: ClassVar[str] = "https://rubygems.org"

    @classmethod
    def gem_install(
        cls, args: Sequence[str], runner: Runner, gem: str, registries: InstallRegistries, cwd: Path
    ) -> InstallPlan:
        done = runner([gem, "install", *args, "--explain"], cwd, {**os.environ})
        if done.returncode != 0:
            raise InstallRefused(
                f"gem could not resolve the install:\n{(done.stderr or done.stdout).strip()[-2000:]}"
            )
        fulls = [line.strip() for line in (done.stdout or "").splitlines() if line.startswith("  ")]
        files = [cls._file(GemSpec.split(full), registries, {}) for full in fulls]
        return InstallPlan("rubygems", files)

    @classmethod
    def bundle(
        cls,
        verb: str,
        args: Sequence[str],
        runner: Runner,
        bundle: str,
        registries: InstallRegistries,
        project: Path,
    ) -> InstallPlan:
        saved = {n: (project / n).read_bytes() for n in cls.SAVED if (project / n).is_file()}
        if "Gemfile" not in saved:
            raise InstallRefused("no Gemfile here: Bundler has no bundle to install")
        argv = [bundle, "lock"]
        if verb == "update":
            argv += ["--update", *[a for a in args if not a.startswith("-")]]
        elif verb == "add":
            argv = [bundle, "add", *args, "--skip-install"]
        done = runner(argv, project, {**os.environ, "BUNDLE_FROZEN": "false"})
        if done.returncode != 0:
            cls.restore(project, saved)
            raise InstallRefused(
                f"Bundler could not lock the bundle:\n{(done.stderr or done.stdout).strip()[-2000:]}"
            )
        try:
            plan = InstallPlan(
                "rubygems",
                cls.locked((project / "Gemfile.lock").read_text(encoding="utf-8"), registries),
            )
        except (InstallRefused, OSError) as exc:
            cls.restore(project, saved)
            raise (
                exc if isinstance(exc, InstallRefused) else InstallRefused("no Gemfile.lock")
            ) from exc
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @staticmethod
    def restore(project: Path, saved: dict[str, bytes]) -> None:
        for name in GemPlanner.SAVED:
            target = project / name
            if name in saved:
                target.write_bytes(saved[name])
            elif target.is_file():
                target.unlink()

    @classmethod
    def locked(cls, text: str, registries: InstallRegistries) -> list[PackageFile]:
        """The rubygems.org gems of a Gemfile.lock (`GEM` sections whose remote is rubygems.org)."""
        section, remote, checksums = "", "", cls.checksums(text)
        out: list[PackageFile] = []
        for line in text.splitlines():
            if line and not line.startswith(" "):
                section, remote = line.strip(), ""
                continue
            if section == "GIT" and line.startswith("  remote:"):
                raise InstallRefused(
                    f"the bundle has a git gem ({line.split(':', 1)[1].strip()[:100]}): not checked"
                )
            if section != "GEM":
                continue
            if line.startswith("  remote:"):
                remote = line.split(":", 1)[1].strip().rstrip("/")
            elif line.startswith("    ") and not line.startswith("     "):
                name, _, rest = line.strip().partition(" (")
                version_platform = rest.rstrip(")")
                if remote != cls.HOST:
                    raise InstallRefused(f"{name} comes from {remote[:100]}: not rubygems.org")
                version, _, platform = version_platform.partition("-")
                out.append(cls._file((name, version, platform), registries, checksums))
        return out

    @staticmethod
    def checksums(text: str) -> dict[str, bytes]:
        """Bundler 2.5+'s `CHECKSUMS` section: `name (version[-platform]) sha256=<hex>`."""
        out: dict[str, bytes] = {}
        inside = False
        for line in text.splitlines():
            if line and not line.startswith(" "):
                inside = line.strip() == "CHECKSUMS"
                continue
            if inside and "sha256=" in line:
                spec, _, digest = line.strip().partition(" sha256=")
                if re.fullmatch(r"[0-9a-f]{64}", digest):
                    name, _, version = spec.partition(" (")
                    out[f"{name}-{version.rstrip(')')}"] = bytes.fromhex(digest)
        return out

    @classmethod
    def _file(
        cls, spec: tuple[str, str, str], registries: InstallRegistries, checksums: dict[str, bytes]
    ) -> PackageFile:
        name, version, platform = spec
        full = f"{name}-{version}" + (f"-{platform}" if platform and platform != "ruby" else "")
        digest = checksums.get(full) or cls._published(name, version, platform, registries)
        return PackageFile(
            "rubygems",
            name,
            version + (f"-{platform}" if platform and platform != "ruby" else ""),
            f"{cls.HOST}/gems/{urllib.parse.quote(full)}.gem",
            "sha256",
            digest,
            separator=" ",
        )

    @classmethod
    def _published(
        cls, name: str, version: str, platform: str, registries: InstallRegistries
    ) -> bytes:
        # Without a platform the record may be any platform's (racc 1.7.3 answers with java's).
        query = f"?platform={urllib.parse.quote(platform or 'ruby')}"
        url = f"{cls.HOST}/api/v2/rubygems/{urllib.parse.quote(name)}/versions/{urllib.parse.quote(version)}.json{query}"
        try:
            record = json.loads(registries.fetch(url, "rubygems"))
        except (ValueError, RuntimeError, OSError) as exc:
            raise InstallRefused(f"rubygems.org has no record of {name} {version}: {exc}") from exc
        sha = str(record.get("sha") or "") if isinstance(record, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise InstallRefused(f"rubygems.org publishes no sha256 for {name} {version}")
        return bytes.fromhex(sha)


__all__ = ["GemPlanner", "GemSpec"]
