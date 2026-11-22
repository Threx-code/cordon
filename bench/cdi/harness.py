"""The invariants of a paired run: two scanner trees scored on the same units, one called the base and one the candidate.

A pair only means something if each side is exactly the tree it says it is. So before a run:

    declared   each side names its commit and the digest of its files, and which side is the base
    checked    the files on disk are digested again; a side whose files differ from its declaration is an edited tree, and
               the run is refused naming the side (never a silent run on whatever happens to be checked out)
    distinct   the base and the candidate are two different trees

A row the run writes is stamped with the harness version and a digest of its content, and is never edited afterwards: a row whose
content no longer matches its digest, or that has no harness version, is refused when it is read back. Nothing here reads a package;
it digests the scanner's own source."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

HARNESS_VERSION: Final = "1"
SIDES: Final = ("base", "candidate")


class EditedTree(ValueError):
    """A side's files differ from the digest it declared."""


class BadDeclaration(ValueError):
    """A side is missing, misnamed, malformed, or the two sides are the same tree."""


class EditedRow(ValueError):
    """A row's content no longer matches its digest, or it carries no harness version."""


class TreeDigest:
    @staticmethod
    def of_files(files: Mapping[str, bytes]) -> str:
        """The digest of a tree: each path with the sha256 of its bytes, in path order."""
        lines = [f"{path}\0{hashlib.sha256(files[path]).hexdigest()}" for path in sorted(files)]
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()

    @classmethod
    def of_directory(cls, root: Path, suffixes: tuple[str, ...] = (".py", ".yaml", ".yml", ".json", ".toml")) -> str:
        """The digest of the files under `root` with one of the suffixes, by their path relative to it."""
        base = Path(root)
        files = {
            str(p.relative_to(base)): p.read_bytes()
            for p in base.rglob("*")
            if p.is_file() and p.suffix in suffixes and "__pycache__" not in p.parts
        }
        return cls.of_files(files)


class PairRun:
    @staticmethod
    def declare(side: str, commit: str, tree_digest: str) -> dict[str, str]:
        if side not in SIDES:
            raise BadDeclaration(f"a side is the base or the candidate, not {side!r}")
        if not commit or any(c not in "0123456789abcdef" for c in commit) or not 7 <= len(commit) <= 40:
            raise BadDeclaration(f"the {side} commit is not a commit hash")
        if len(tree_digest) != 64 or any(c not in "0123456789abcdef" for c in tree_digest):
            raise BadDeclaration(f"the {side} tree digest is not a sha256")
        return {"side": side, "commit": commit, "tree_digest": tree_digest}

    @classmethod
    def start(cls, base: Mapping[str, str], candidate: Mapping[str, str], actual: Mapping[str, str]) -> dict[str, Any]:
        """The record of a run that may begin. `actual` is the digest of each side's files as they are now, by side name.

        Raises `BadDeclaration` for a missing or mislabelled side or two identical trees, and `EditedTree` for a side whose
        files are not the ones declared."""
        for want, declared in (("base", base), ("candidate", candidate)):
            if declared.get("side") != want:
                raise BadDeclaration(f"the {want} side is not declared as the {want}")
            cls.declare(want, declared.get("commit", ""), declared.get("tree_digest", ""))
        if base["tree_digest"] == candidate["tree_digest"] or base["commit"] == candidate["commit"]:
            raise BadDeclaration("the base and the candidate are the same tree: a pair measures nothing")
        for side, declared in (("base", base), ("candidate", candidate)):
            if actual.get(side) != declared["tree_digest"]:
                raise EditedTree(f"the {side} tree was edited since it was declared: the run is refused")
        return {"harness": HARNESS_VERSION, "base": dict(base), "candidate": dict(candidate)}


class Row:
    @staticmethod
    def digest(body: Mapping[str, Any]) -> str:
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    @classmethod
    def seal(cls, body: Mapping[str, Any]) -> dict[str, Any]:
        """The row as written: its content, the harness version, and a digest of both."""
        content = {**body, "harness": HARNESS_VERSION}
        return {**content, "row_digest": cls.digest(content)}

    @classmethod
    def read(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        """The row's content, or `EditedRow` when it has no harness version or its content no longer matches its digest."""
        content = {k: v for k, v in row.items() if k != "row_digest"}
        if not content.get("harness"):
            raise EditedRow("the row carries no harness version")
        if row.get("row_digest") != cls.digest(content):
            raise EditedRow("the row was edited after it was written")
        return content
