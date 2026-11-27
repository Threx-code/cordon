"""Bazel (`bazel build`, `fetch`, `run`, ...): every module file and archive the lock names, scanned before Bazel evaluates them.

Bazel evaluates each dependency's `MODULE.bazel` while it resolves, and runs the repository rules that fetch and build what the
modules ship, so the code of a dependency runs before anything is built. What Cordon checks is `MODULE.bazel.lock`, which pins
every registry file by its sha256: each `MODULE.bazel`, and each module's `source.json`, which in turn names the module's archive
by an SRI integrity (and its patches and overlay files by theirs). Every file is fetched, held to its pin, and scanned. The
archives and files a module extension's generated repositories download (`http_archive`, `http_file`, `http_jar`) are held to the
integrity or sha256 the lock records for them. Bazel is then run with `--lockfile_mode=error`, so it checks the same pins itself
and the bytes it evaluates are the bytes scanned. A repository rule that fetches from git, a module taken from git or a local
path, and a download without a pin are refused: nothing fixes their bytes. A repository rule's own code that downloads (a rule
written in a dependency) is the one thing a lock does not show; the module that ships the rule is scanned.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class BazelPlanner:
    #: The commands that evaluate modules or run repository rules.
    VERBS: ClassVar[frozenset[str]] = frozenset(
        {
            "build",
            "test",
            "run",
            "fetch",
            "sync",
            "coverage",
            "cquery",
            "aquery",
            "query",
            "vendor",
            "mod",
        }
    )
    MODULE_FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"(.+)/modules/([^/]+)/([^/]+)/(MODULE\.bazel|source\.json)"
    )
    SRI: ClassVar[re.Pattern[str]] = re.compile(
        r"(sha256|sha384|sha512)-([A-Za-z0-9+/]{40,200}={0,2})"
    )
    HEX: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
    HTTP_RULES: ClassVar[tuple[str, ...]] = (
        "http.bzl%http_archive",
        "http.bzl%http_file",
        "http.bzl%http_jar",
    )
    GIT_RULES: ClassVar[tuple[str, ...]] = ("git.bzl%git_repository", "git.bzl%new_git_repository")
    LOCK_MODE: ClassVar[str] = "--lockfile_mode=error"

    @classmethod
    def command(cls, args: Sequence[str]) -> int | None:
        """The index of the Bazel command in `args` (startup options come first), or None."""
        for index, word in enumerate(args):
            if not word.startswith("-"):
                return index
        return None

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        index = cls.command(args)
        return index is not None and args[index] in cls.VERBS

    @classmethod
    def arguments(cls, args: Sequence[str]) -> list[str]:
        """The command line Cordon runs: the person's, with the lock checked by Bazel as well."""
        out = list(args)
        start = cls.command(out) or 0
        end = out.index("--", start) if "--" in out[start:] else len(out)
        out.insert(end, cls.LOCK_MODE)
        return out

    @classmethod
    def plan(cls, project: Path, fetch: Callable[[str], bytes]) -> InstallPlan:
        lock = project / "MODULE.bazel.lock"
        if not (project / "MODULE.bazel").is_file():
            raise InstallRefused(
                "no MODULE.bazel here: Cordon checks Bazel builds against the modules a lock pins, "
                "and a WORKSPACE build names no lock"
            )
        if not lock.is_file():
            raise InstallRefused(
                "no MODULE.bazel.lock here: Bazel evaluates every dependency's MODULE.bazel while it resolves. "
                "Write the lock where you trust the modules (`bazel mod deps --lockfile_mode=update`), then run this again"
            )
        return InstallPlan(
            "bazel", cls.files(lock.read_text(encoding="utf-8", errors="replace"), fetch)
        )

    @classmethod
    def files(cls, text: str, fetch: Callable[[str], bytes]) -> list[PackageFile]:
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("MODULE.bazel.lock is not JSON Cordon can read") from exc
        hashes = document.get("registryFileHashes") if isinstance(document, dict) else None
        if not isinstance(hashes, dict):
            raise InstallRefused(
                "MODULE.bazel.lock names no registry files: nothing to check Bazel's modules against"
            )
        files: list[PackageFile] = []
        for url, pin in hashes.items():
            found = cls.MODULE_FILE.fullmatch(str(url))
            if found is None:
                continue
            registry, name, version, kind = found.groups()
            if not isinstance(pin, str) or not cls.HEX.fullmatch(pin):
                raise InstallRefused(
                    f"{name} {version}: the lock's hash for {kind} is not a sha256"
                )
            if kind == "MODULE.bazel":
                files.append(PackageFile("bazel", name, version, url, "sha256", bytes.fromhex(pin)))
            else:
                files.extend(cls.source(registry, name, version, url, pin, fetch))
        files.extend(cls.generated(document.get("moduleExtensions")))
        return files

    @classmethod
    def source(
        cls,
        registry: str,
        name: str,
        version: str,
        url: str,
        pin: str,
        fetch: Callable[[str], bytes],
    ) -> list[PackageFile]:
        """The archive, patches and overlay a module's `source.json` names, once that file is held to its pin."""
        data = fetch(url)
        if hashlib.sha256(data).hexdigest() != pin:
            raise InstallRefused(
                f"{name} {version}: the registry's source.json is not the one MODULE.bazel.lock pins"
            )
        try:
            source = json.loads(data)
        except ValueError as exc:
            raise InstallRefused(f"{name} {version}: a source.json Cordon cannot read") from exc
        if not isinstance(source, dict) or source.get("type") not in (None, "archive"):
            raise InstallRefused(
                f"{name} {version} comes from {str(source.get('type'))[:30] if isinstance(source, dict) else 'an unknown source'}: "
                "Cordon checks Bazel modules by the integrity of their archive"
            )
        files = [
            cls.integrity(name, version, str(source.get("url") or ""), source.get("integrity"))
        ]
        for folder in ("patches", "overlay"):
            for member, integrity in (source.get(folder) or {}).items():
                if not re.fullmatch(
                    r"[A-Za-z0-9._+-][A-Za-z0-9._+/-]{0,150}", str(member)
                ) or ".." in str(member):
                    raise InstallRefused(f"{name} {version}: a {folder} name Cordon cannot read")
                files.append(
                    cls.integrity(
                        name,
                        version,
                        f"{registry}/modules/{name}/{version}/{folder}/{member}",
                        integrity,
                    )
                )
        return files

    @classmethod
    def integrity(cls, name: str, version: str, url: str, value: object) -> PackageFile:
        found = cls.SRI.fullmatch(value) if isinstance(value, str) else None
        if found is None:
            raise InstallRefused(
                f"{name} {version}: {url[:80]} has no integrity in the registry's source.json"
            )
        return PackageFile(
            "bazel", name, version, url, found.group(1), base64.b64decode(found.group(2))
        )

    @classmethod
    def generated(cls, extensions: object) -> list[PackageFile]:
        """What a module extension's generated repositories download: held to the pin the lock records."""
        out: list[PackageFile] = []
        if not isinstance(extensions, dict):
            return out
        for extension, usages in extensions.items():
            for usage in (usages or {}).values() if isinstance(usages, dict) else ():
                repositories = usage.get("generatedRepoSpecs") if isinstance(usage, dict) else None
                for repo, spec in (repositories or {}).items():
                    rule = str(spec.get("repoRuleId", "")) if isinstance(spec, dict) else ""
                    label = f"{str(repo)[:60]} (from {str(extension)[:60]})"
                    if rule.endswith(cls.GIT_RULES):
                        raise InstallRefused(f"{label} is fetched from git: nothing pins its bytes")
                    if not rule.endswith(cls.HTTP_RULES):
                        continue
                    out.append(cls.download(label, spec.get("attributes") or {}))
        return out

    @classmethod
    def download(cls, label: str, attributes: dict[str, object]) -> PackageFile:
        urls = attributes.get("urls") or ([attributes["url"]] if attributes.get("url") else [])
        url = urls[0] if isinstance(urls, list) and urls else None
        integrity, sha256 = attributes.get("integrity"), attributes.get("sha256")
        if isinstance(integrity, str) and integrity:
            return cls.integrity(label, "", str(url), integrity)
        if isinstance(sha256, str) and cls.HEX.fullmatch(sha256) and isinstance(url, str):
            return PackageFile("bazel", label, "", url, "sha256", bytes.fromhex(sha256))
        raise InstallRefused(
            f"{label} downloads {str(url)[:80]} with no integrity or sha256 in the lock"
        )


__all__ = ["BazelPlanner"]
