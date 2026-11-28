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
GO_H1 = "go-h1"


class Unpacked:
    """How much a downloaded archive may expand to: what it holds is read member by member, and the sum of what the members declare is
    held to a bound, so a small download cannot become gigabytes in memory."""

    LIMIT: ClassVar[int] = 512 << 20
    RATIO: ClassVar[int] = 20
    FLOOR: ClassVar[int] = 4 << 20

    @classmethod
    def bound(cls, data: bytes) -> int:
        return min(cls.LIMIT, max(cls.RATIO * len(data), cls.FLOOR))


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
            with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as archive:
                archive.next()
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
        or "" when the archive cannot be read as one tree or expands past `Unpacked.bound`."""
        root: dict[str, Any] = {}
        count, total, bound = 0, 0, Unpacked.bound(data)
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as archive:
                for member in archive:
                    total += member.size + 512
                    if total > bound:
                        return ""
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


class GoZip:
    """Go's `h1:` hash of a module zip (`golang.org/x/mod/sumdb/dirhash` Hash1): the SHA-256 of one `<sha256 hex>  <name>` line per file,
    sorted by name, which is what go.sum and the checksum database record, so a proxy's zip is checked against the log, not itself."""

    @staticmethod
    def h1(data: bytes) -> str:
        import base64
        import zipfile

        lines = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                total, bound = 0, Unpacked.bound(data)
                for info in sorted(archive.infolist(), key=lambda i: i.filename):
                    if info.is_dir():
                        continue
                    total += info.file_size
                    if total > bound:
                        return ""
                    if "\n" in info.filename:
                        return ""
                    lines.append(
                        f"{hashlib.sha256(archive.read(info)).hexdigest()}  {info.filename}\n"
                    )
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return ""
        return "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()
