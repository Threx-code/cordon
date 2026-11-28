"""CocoaPods (`pod install`): every podspec and every pod source Podfile.lock pins, scanned before CocoaPods runs them.

CocoaPods evaluates each pod's podspec and runs its `prepare_command` (a shell command the podspec carries) as it downloads the pod,
so the code of a dependency runs while dependencies are being got. What Cordon checks is `Podfile.lock`:

* `SPEC CHECKSUMS` holds the SHA-1 of each trunk pod's podspec. The podspec is fetched from the CDN (its path is the first three hex
  digits of the MD5 of the pod's name), held to that checksum, and scanned: `prepare_command` lives there.
* The pod's source is what that podspec names: a git repository at a commit, or an archive with a SHA-1 or SHA-256, both of which
  CocoaPods itself checks as it downloads. It is fetched, held to that pin, and scanned. `pod install` then runs with `--deployment`, so
  it uses exactly the pinned pods.

A pod whose source is a bare git tag is REFUSED, and this will be often, because most trunk pods name a tag: a tag can move between this
scan and CocoaPods' own download, and nothing in the lock fixes it. The refusal names the pod and says how to pin the commit
(`git ls-remote <url> refs/tags/<tag>`). A pod from a podspec URL, from git without a pinned commit, from a spec repository other than
trunk, or from a path outside the project is refused for the same reason; a `:path` pod inside the project is the project's own code.
`pod update` chooses versions and is refused. Cordon seeds nothing into CocoaPods' cache: CocoaPods does not store a pod as downloaded
(it runs `prepare_command` and removes the files the spec's platforms do not use), so the pins are what keep the scanned bytes and the
installed bytes the same.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class CocoaPodsPlanner:
    CDN: ClassVar[str] = "https://cdn.cocoapods.org/Specs"
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_+.-]{1,100}")
    SHA1: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    POD: ClassVar[re.Pattern[str]] = re.compile(r'  - "?([^\s"(]+)"? \(([^)]+)\)')
    CHECKSUM: ClassVar[re.Pattern[str]] = re.compile(r'  "?([^:"\s]+)"?: ([0-9a-f]{40})')
    OPTION: ClassVar[re.Pattern[str]] = re.compile(r"    :(\w+): (.*)")
    ARGUMENT: ClassVar[str] = "--deployment"

    @staticmethod
    def command(args: Sequence[str]) -> tuple[int, str] | None:
        """The pod subcommand and where it is: the first word that is not an option."""
        for index, word in enumerate(args):
            if not word.startswith("-"):
                return index, word
        return None

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        found = cls.command(args)
        return found is not None and found[1] in ("install", "update")

    @classmethod
    def arguments(cls, args: Sequence[str]) -> list[str]:
        out = list(args)
        found = cls.command(out)
        if found is not None:
            out.insert(found[0] + 1, cls.ARGUMENT)
        return out

    @classmethod
    def plan(cls, args: Sequence[str], project: Path, fetch: Callable[[str], bytes]) -> InstallPlan:
        found = cls.command(args)
        if found is not None and found[1] == "update":
            raise InstallRefused(
                "`pod update` chooses pod versions, and CocoaPods runs each podspec's prepare_command as it downloads the pod: Cordon cannot "
                "scan them first. Update Podfile.lock where you trust the pods, then run `pod install` through Cordon"
            )
        lock = project / "Podfile.lock"
        if not lock.is_file():
            raise InstallRefused(
                "no Podfile.lock here: `pod install` would resolve the pods and run their prepare_command as it downloads them. Write the lock "
                "where you trust the pods, then run this again"
            )
        return cls.files(lock.read_text(encoding="utf-8", errors="replace"), project, fetch)

    @classmethod
    def sections(cls, text: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        current = ""
        for line in text.splitlines():
            if line and not line.startswith(" "):
                current = line.partition(":")[0]
                out.setdefault(current, [])
            elif current:
                out[current].append(line)
        return out

    @classmethod
    def blocks(cls, lines: Sequence[str]) -> dict[str, list[str]]:
        """A section of `  name:` entries, each with its own indented lines."""
        out: dict[str, list[str]] = {}
        current = ""
        for line in lines:
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                current = line.strip().rstrip(":").strip('"')
                out[current] = []
            elif current:
                out[current].append(line)
        return out

    @classmethod
    def files(cls, text: str, project: Path, fetch: Callable[[str], bytes]) -> InstallPlan:
        sections = cls.sections(text)
        versions: dict[str, str] = {}
        for line in sections.get("PODS", []):
            found = cls.POD.fullmatch(line.rstrip(":"))
            if found:
                versions.setdefault(found.group(1).split("/")[0], found.group(2))
        repos = cls.blocks(sections.get("SPEC REPOS", []))
        trunk = {
            pod.strip().lstrip("- ").strip('"').split("/")[0] for pod in repos.get("trunk", [])
        }
        others = sorted(name for name in repos if name != "trunk" and repos[name])
        if others:
            raise InstallRefused(
                f"the lock lists pods from the spec repository {others[0][:60]}: Cordon checks pods from trunk, by the checksum of each podspec"
            )
        checksums = {
            m.group(1): m.group(2)
            for line in sections.get("SPEC CHECKSUMS", [])
            if (m := cls.CHECKSUM.fullmatch(line))
        }
        external = {
            name: cls.options(lines)
            for name, lines in cls.blocks(sections.get("EXTERNAL SOURCES", [])).items()
        }
        checkout = {
            name: cls.options(lines)
            for name, lines in cls.blocks(sections.get("CHECKOUT OPTIONS", [])).items()
        }
        plan = InstallPlan("cocoapods")
        for name, version in versions.items():
            if name in external:
                cls.external(plan, name, external[name], checkout.get(name, {}), project)
            elif name in trunk:
                plan.files.extend(cls.trunk(name, version, checksums.get(name), fetch))
            else:
                raise InstallRefused(
                    f"{name[:60]}: the lock does not say where this pod comes from"
                )
        return plan

    @classmethod
    def options(cls, lines: Sequence[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in lines:
            found = cls.OPTION.fullmatch(line.rstrip())
            if found:
                out[found.group(1)] = found.group(2).strip().strip('"')
        return out

    @classmethod
    def external(
        cls,
        plan: InstallPlan,
        name: str,
        options: dict[str, str],
        checked: dict[str, str],
        project: Path,
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.git_sourced import Repo

        if "path" in options:
            target = (project / options["path"]).resolve()
            if not target.is_relative_to(project.resolve()):
                raise InstallRefused(
                    f"{name[:60]} is a :path pod outside this project ({options['path'][:80]}): its podspec is code CocoaPods runs. "
                    "Scan the folder it lives in, or vendor it into the project"
                )
            if target.is_dir():
                plan.local.append(target)
            return
        commit = checked.get("commit", "")
        repo = Repo.of(options.get("git", ""))
        if "git" in options and repo is not None and cls.SHA1.fullmatch(commit):
            plan.files.append(
                PackageFile(
                    "cocoapods",
                    name,
                    commit[:12],
                    Repo.tarball(repo[0], repo[1], commit),
                    "git-commit",
                    bytes.fromhex(commit),
                )
            )
            return
        raise InstallRefused(
            f"{name[:60]} comes from {'a podspec at ' + options['podspec'][:80] if 'podspec' in options else 'git without a commit Cordon can fetch'}: "
            "a podspec URL or a git source is checked only when it is pinned to a commit on GitHub"
        )

    @classmethod
    def trunk(
        cls, name: str, version: str, checksum: str | None, fetch: Callable[[str], bytes]
    ) -> list[PackageFile]:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        if not cls.NAME.fullmatch(name) or not version or checksum is None:
            raise InstallRefused(f"{name[:60]}: Podfile.lock has no podspec checksum for it")
        shard = hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()[:3]
        url = f"{cls.CDN}/{'/'.join(shard)}/{name}/{version}/{name}.podspec.json"
        data = fetch(url)
        if hashlib.sha1(data, usedforsecurity=False).hexdigest() != checksum:
            raise InstallRefused(
                f"{name} {version}: the CDN's podspec is not the one Podfile.lock's SPEC CHECKSUMS pins"
            )
        try:
            spec = json.loads(data)
        except ValueError as exc:
            raise InstallRefused(f"{name} {version}: a podspec Cordon cannot read") from exc
        podspec = PackageFile(
            "cocoapods", f"{name}.podspec", version, url, "sha1", bytes.fromhex(checksum)
        )
        source = spec.get("source") if isinstance(spec, dict) else None
        archive = ArchiveSources.of("cocoapods")
        found = (
            archive.locate(name, version, {"podspec": spec})
            if archive is not None and isinstance(source, dict)
            else None
        )
        if found is None or not found.digests:
            raise InstallRefused(
                f"{name} {version}: its podspec names no source Cordon can fetch and check (an https archive with a sha1 or sha256, or git on GitHub)"
            )
        algorithm, digest = found.digests[0]
        if algorithm == "git-tag":
            tag = str(source.get("tag", "")) if isinstance(source, dict) else ""
            address = str(source.get("git", "")) if isinstance(source, dict) else ""
            raise InstallRefused(
                f"{name} {version}: its source is the git tag {tag[:60]!r} of {address[:100]}: a tag can move between this scan and CocoaPods' own "
                f"download. Pin :commit (`git ls-remote {address[:100]} refs/tags/{tag[:60]}` gives it)"
            )
        if algorithm not in ("sha256", "sha1", "git-commit"):
            raise InstallRefused(
                f"{name} {version}: its source is checked by {algorithm}, which Cordon does not hold a download to"
            )
        return [
            podspec,
            PackageFile("cocoapods", name, version, found.url, algorithm, bytes.fromhex(digest)),
        ]


__all__ = ["CocoaPodsPlanner"]
