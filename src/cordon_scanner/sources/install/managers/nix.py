"""Nix flakes (`nix build`, `run`, `develop`, `flake check`, ...): every input the lock pins, scanned before Nix evaluates it.

Evaluating a flake runs Nix code: each input's `flake.nix` is evaluated as it is fetched, so the code of a dependency runs while the
dependencies are being got. What Cordon checks is `flake.lock`, which records for every input the commit (`rev`) and the `narHash`,
the SHA-256 of the input's files serialised as a NAR, which Nix checks of what it fetches. Each locked GitHub, GitLab and SourceHut
input is fetched as the forge's tarball of that commit, held to the `narHash` (recomputed over the tarball's tree), and scanned. Nix
is then run with `--no-update-lock-file`, so it fetches the same inputs and checks the same hashes itself. An input taken from git
or a path, a remote flake named on the command line (`github:owner/repo`, `nixpkgs#hello`: resolved at run time, not by this lock),
and every command that rewrites the lock (`flake update`, `flake lock`, `--update-input`) are refused: they choose code Cordon has
not scanned. `nix-build` and `nix-shell` read no lock and are not covered.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Sequence


class NixPlanner:
    #: The `nix` subcommands that evaluate a flake.
    VERBS: ClassVar[frozenset[str]] = frozenset(
        {
            "build",
            "run",
            "develop",
            "shell",
            "eval",
            "flake",
            "profile",
            "bundle",
            "fmt",
            "repl",
            "print-dev-env",
            "path-info",
        }
    )
    LOCKING_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {"--update-input", "--recreate-lock-file", "--override-input", "--refresh", "--impure"}
    )
    SRI: ClassVar[re.Pattern[str]] = re.compile(r"sha256-([A-Za-z0-9+/]{43}=)")
    REV: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"~?[A-Za-z0-9][A-Za-z0-9._-]{0,100}")
    FORGES: ClassVar[dict[str, str]] = {
        "github": "https://codeload.github.com/{owner}/{repo}/tar.gz/{rev}",
        "gitlab": "https://gitlab.com/api/v4/projects/{project}/repository/archive.tar.gz?sha={rev}",
        "sourcehut": "https://git.sr.ht/{owner}/{repo}/archive/{rev}.tar.gz",
    }
    ARGUMENT: ClassVar[str] = "--no-update-lock-file"

    @classmethod
    def verb(cls, args: Sequence[str]) -> tuple[int, str] | None:
        """The first word that names an evaluating subcommand: an option's value (`--option NAME VALUE`) is no command, so each
        word before `--` is tried."""
        for index, word in enumerate(args):
            if word == "--":
                return None
            if not word.startswith("-") and word in cls.VERBS:
                return index, word
        return None

    @staticmethod
    def remote(word: str) -> bool:
        """A flake reference that is not the project's own: a URL (`github:o/r`, `path:` excepted) or a registry name (`nixpkgs#hello`)."""
        if word.startswith(("-", ".", "/", "~", "path:")):
            return False
        reference = word.partition("#")[0]
        return bool(re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", reference)) or (
            bool(reference) and "#" in word
        )

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        return cls.verb(args) is not None

    @classmethod
    def arguments(cls, args: Sequence[str]) -> list[str]:
        out = list(args)
        found = cls.verb(out)
        out.insert(found[0] + 1 if found else 0, cls.ARGUMENT)
        return out

    @classmethod
    def plan(cls, args: Sequence[str], project: Path) -> InstallPlan:
        found = cls.verb(args)
        rest = list(args[found[0] + 1 :]) if found else []
        if (
            found
            and found[1] == "flake"
            and rest[:1]
            and rest[0] in ("update", "lock", "init", "new")
        ) or any(a.split("=")[0] in cls.LOCKING_FLAGS for a in args):
            raise InstallRefused(
                "this command rewrites flake.lock or evaluates without it, choosing inputs whose flake.nix Nix evaluates as it fetches "
                "them: Cordon cannot scan them first. Update the lock where you trust the inputs, then run the command again"
            )
        for word in rest[: rest.index("--")] if "--" in rest else rest:
            if cls.remote(word):
                raise InstallRefused(
                    f"`{word[:60]}` is a flake resolved at run time (a URL or the flake registry), not by this project's lock: "
                    "name a local flake, or pin it where you trust it"
                )
        lock = project / "flake.lock"
        if not lock.is_file():
            raise InstallRefused(
                "no flake.lock here: Nix evaluates each input's flake.nix as it fetches it. Write the lock where you trust "
                "the inputs (`nix flake lock`), then run this again"
            )
        return InstallPlan("nix", cls.files(lock.read_text(encoding="utf-8", errors="replace")))

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("flake.lock is not JSON Cordon can read") from exc
        nodes = document.get("nodes") if isinstance(document, dict) else None
        if not isinstance(nodes, dict):
            raise InstallRefused("flake.lock names no inputs Cordon can read")
        out: list[PackageFile] = []
        for name, node in nodes.items():
            locked = node.get("locked") if isinstance(node, dict) else None
            if locked is None:
                continue  # the root, or an input that follows another
            out.append(cls.input(str(name), locked))
        return out

    @classmethod
    def input(cls, name: str, locked: object) -> PackageFile:
        if not isinstance(locked, dict):
            raise InstallRefused(f"{name[:60]}: a flake.lock entry Cordon cannot read")
        kind = str(locked.get("type"))
        sri = cls.SRI.fullmatch(str(locked.get("narHash") or ""))
        rev = str(locked.get("rev") or "")
        if kind not in cls.FORGES:
            raise InstallRefused(
                f"{name[:60]} is a {kind[:20]} input: Cordon checks flake inputs on GitHub, GitLab and SourceHut by their narHash"
            )
        owner, repo = str(locked.get("owner")), str(locked.get("repo"))
        if not (
            cls.NAME.fullmatch(owner)
            and cls.NAME.fullmatch(repo)
            and cls.REV.fullmatch(rev)
            and sri
        ):
            raise InstallRefused(f"{name[:60]}: a flake.lock entry Cordon cannot read")
        project = urllib.parse.quote(f"{owner}/{repo}", safe="")
        url = cls.FORGES[kind].format(owner=owner, repo=repo, rev=rev, project=project)
        return PackageFile(
            "nix", f"{owner}/{repo}", rev, url, "nar-sha256", base64.b64decode(sri.group(1))
        )


__all__ = ["NixPlanner"]
