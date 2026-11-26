"""Archives of a git revision: what the revision is, read from the archive itself.

A code host's tarball of a commit carries the commit's id in its pax header (`git archive` writes it), so the archive says which commit it
is of; and a git tree hash (Julia's `git-tree-sha1`) is a hash of the files themselves, so it checks the bytes with no trust in the host."""

from __future__ import annotations

import hashlib
import io
import tarfile
from typing import Any, ClassVar

MAX_FILES = 200_000
MAX_DEPTH = 64
GIT_COMMIT = "git-commit"
GIT_TAG = "git-tag"
GIT_TREE = "git-tree-sha1"


class GitTar:
    #: The git modes a tree entry has.
    FILE: ClassVar[bytes] = b"100644"
    EXECUTABLE: ClassVar[bytes] = b"100755"
    LINK: ClassVar[bytes] = b"120000"
    TREE: ClassVar[bytes] = b"40000"

    @staticmethod
    def commit(data: bytes) -> str:
        """The commit id a code host's tarball says it is of (its pax header `comment`), or "" when it says none."""
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                comment = str(archive.pax_headers.get("comment") or "").strip().lower()
        except (tarfile.TarError, OSError, EOFError, ValueError):
            return ""
        return (
            comment if len(comment) in (40, 64) and set(comment) <= set("0123456789abcdef") else ""
        )

    @staticmethod
    def _blob(content: bytes) -> bytes:
        return hashlib.sha1(b"blob %d\0" % len(content) + content, usedforsecurity=False).digest()

    @classmethod
    def _tree(cls, node: dict[str, Any]) -> bytes:
        """The id of a directory: its entries, each `<mode> <name>\\0<id>`, sorted as git sorts them (a directory as `name/`)."""
        entries: list[tuple[bytes, bytes]] = []
        for name, child in node.items():
            raw = name.encode("utf-8")
            if isinstance(child, dict):
                digest = cls._tree(child)
                entries.append((raw + b"/", cls.TREE + b" " + raw + b"\0" + digest))
            else:
                mode, digest = child
                entries.append((raw, mode + b" " + raw + b"\0" + digest))
        payload = b"".join(entry for _, entry in sorted(entries))
        return hashlib.sha1(b"tree %d\0" % len(payload) + payload, usedforsecurity=False).digest()

    @classmethod
    def tree_sha1(cls, data: bytes) -> str:
        """The git tree hash of the files in a tar (a tree of the archive's own paths: empty directories are not part of one),
        or "" when the archive cannot be read as one tree."""
        root: dict[str, Any] = {}
        count = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive:
                    parts = member.name.strip("/").split("/")
                    if member.name.startswith("/"):
                        return ""
                    if member.isdir():
                        continue
                    count += 1
                    if (
                        count > MAX_FILES
                        or len(parts) > MAX_DEPTH
                        or any(p in ("", ".", "..") for p in parts)
                        or not (member.isfile() or member.issym())
                    ):
                        return ""
                    if member.issym():
                        mode, content = cls.LINK, member.linkname.encode("utf-8")
                    else:
                        handle = archive.extractfile(member)
                        content = handle.read() if handle else b""
                        mode = cls.EXECUTABLE if member.mode & 0o111 else cls.FILE
                    node = root
                    for part in parts[:-1]:
                        child = node.setdefault(part, {})
                        if not isinstance(child, dict):
                            return ""
                        node = child
                    if parts[-1] in node:
                        return ""
                    node[parts[-1]] = (mode, cls._blob(content))
        except (tarfile.TarError, OSError, EOFError, ValueError):
            return ""
        return cls._tree(root).hex()
