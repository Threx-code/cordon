"""The digest an artifact is identified by (design spec 3.2): the exact bytes a decision binds to.

```
  package      sha256 of the exact file a registry serves (a tarball, a wheel, a crate, a gem)
  skill        sha256 over a canonical tree listing: sorted (path, mode, sha256(content))
  MCP remote   sha256 of the canonicalised tools/list response: names, schemas, descriptions
  model        sha256 of each weight and config file, and the sha256 of the sorted listing of those
```

Two observations are one artifact if and only if their digests are equal (3.3). Every digest is written
`sha256:<64 lower-case hex>`. Pure: nothing here reads a file, the clock or the environment.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any, Final

ALGORITHM: Final = "sha256"


class ArtifactDigests:
    """Compute the digest of each kind of artifact from the bytes (or the listing) it is made of."""

    @staticmethod
    def of_bytes(content: bytes) -> str:
        """The digest of one file's exact bytes: a package archive as a registry serves it."""
        return f"{ALGORITHM}:{hashlib.sha256(content).hexdigest()}"

    @staticmethod
    def is_digest(text: str) -> bool:
        """Whether `text` is a digest in the form this module writes."""
        prefix, _, hexdigest = text.partition(":")
        return (
            prefix == ALGORITHM
            and len(hexdigest) == 64
            and all(char in "0123456789abcdef" for char in hexdigest)
        )

    @classmethod
    def of_tree(cls, entries: Iterable[tuple[str, str, bytes]]) -> str:
        """A folder's digest: the sha256 of its sorted listing, one line per file,
        `<path>\\0<mode>\\0<sha256 of the content>\\n`. `entries` are (path relative to the folder with
        `/` separators, mode as an octal string such as `644`, content). Order does not matter; two
        files at one path, or a path that leaves the folder, are refused."""
        lines: dict[str, str] = {}
        for path, mode, content in entries:
            cls._check_path(path)
            if path in lines:
                raise ValueError(f"path {path!r} is listed twice")
            lines[path] = f"{path}\0{mode}\0{hashlib.sha256(content).hexdigest()}\n"
        listing = "".join(
            lines[path] for path in sorted(lines, key=lambda item: item.encode("utf-8"))
        )
        return cls.of_bytes(listing.encode("utf-8"))

    @classmethod
    def of_model(cls, files: Mapping[str, str]) -> str:
        """A model's tree digest from the digest of each of its files (`path -> sha256:<hex>`): the sha256
        of the sorted lines `<path>\\0<digest>\\n`, the set of files being the artifact."""
        lines = []
        for path in sorted(files, key=lambda item: item.encode("utf-8")):
            cls._check_path(path)
            if not cls.is_digest(files[path]):
                raise ValueError(f"{path!r}: {files[path]!r} is not a digest")
            lines.append(f"{path}\0{files[path]}\n")
        return cls.of_bytes("".join(lines).encode("utf-8"))

    @classmethod
    def of_git_commit(cls, commit: str) -> str:
        """A CI action's artifact: the commit its tag or branch points at (row BP-3-5). The commit id is a SHA-1 or SHA-256 object
        name of 40 or 64 hex digits; the digest is the sha256 of `git-commit\\0<id in lower case>`, so it has the one form every
        schema takes, and the same commit is the same digest however the tool wrote the id. A moved tag is another commit, so another
        digest: a decision made for the old one is not the new one's."""
        text = commit.strip().lower()
        if len(text) not in (40, 64) or not all(char in "0123456789abcdef" for char in text):
            raise ValueError(f"{commit!r} is not a git commit id (40 or 64 hex digits)")
        return cls.of_bytes(f"git-commit\0{text}".encode())

    @classmethod
    def of_tool_list(cls, tools: Iterable[Mapping[str, Any]]) -> str:
        """A remote MCP server's artifact: the sha256 of its tools/list response canonicalised. Each
        tool keeps its name, description and input schema (the other fields of a response are not what the
        server tells the agent it can do); tools are sorted by name; text is NFC; JSON is written with
        sorted keys, no blanks and UTF-8, so the same list is one digest wherever it was serialised."""
        kept = []
        for tool in tools:
            if "name" not in tool:
                raise ValueError("a tool without a name")
            kept.append(
                {
                    "name": cls._text(tool["name"]),
                    "description": cls._text(tool.get("description", "")),
                    "inputSchema": cls._canonical(tool.get("inputSchema", {})),
                }
            )
        kept.sort(key=lambda tool: tool["name"].encode("utf-8"))
        names = [tool["name"] for tool in kept]
        if len(set(names)) != len(names):
            raise ValueError("two tools have one name")
        return cls.of_bytes(cls.canonical_json(kept))

    @staticmethod
    def canonical_json(value: Any) -> bytes:
        """`value` as the bytes every digest of a JSON document is taken over: sorted keys, `,` and
        `:` with no blanks, non-ASCII written as UTF-8, no NaN."""
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")

    @staticmethod
    def _text(value: Any) -> str:
        return unicodedata.normalize("NFC", str(value))

    @classmethod
    def _canonical(cls, value: Any) -> Any:
        """A JSON value with every string normalised to NFC (keys included)."""
        if isinstance(value, str):
            return cls._text(value)
        if isinstance(value, Mapping):
            return {cls._text(key): cls._canonical(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._canonical(item) for item in value]
        return value

    @staticmethod
    def _check_path(path: str) -> None:
        pieces = path.split("/")
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or any(piece in ("", ".", "..") for piece in pieces)
        ):
            raise ValueError(f"{path!r} is not a path inside the folder")


__all__ = ["ALGORITHM", "ArtifactDigests"]
