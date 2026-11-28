"""(Moved from the platform's fix helpers, which proved it against real locks: github, gitlab and sourcehut.)

The hash Nix records for a source tree: the SHA-256 of the tree's NAR serialisation (files with their executable
bit, directories in name order, symlinks), written as an SRI string (`sha256-` and base64), and the tree's modification
time. The tree is a forge's source tarball with its single top directory removed, as Nix unpacks it. Nothing is written
to disk and no entry is followed: a tarball with a device, a hard link or a name that is not one path component is
refused."""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from typing import Any, ClassVar


class NarRefused(ValueError):
    """The tarball is not a source tree this reader can hash."""


class NarHash:
    MOST_BYTES: ClassVar[int] = 256 * 1024 * 1024
    MOST_ENTRIES: ClassVar[int] = 200_000

    @staticmethod
    def string(value: bytes) -> bytes:
        return len(value).to_bytes(8, "little") + value + b"\0" * (-len(value) % 8)

    @classmethod
    def of_tarball(cls, archive: bytes) -> tuple[str, int]:
        """`(the SRI hash, the newest modification time)` of the tree in a gzip tarball."""
        tree: dict[bytes, Any] = {}
        newest = total = count = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                for member in tar:
                    count += 1
                    if count > cls.MOST_ENTRIES:
                        raise NarRefused("the tarball holds too many entries")
                    parts = [p for p in member.name.split("/") if p not in ("", ".")]
                    if not parts or any(p == ".." or "\0" in p for p in parts):
                        raise NarRefused("the tarball names a path outside itself")
                    if len(parts) == 1 and member.isdir():
                        continue
                    if len(parts) < 2:
                        raise NarRefused("the tarball has no single top directory")
                    newest = max(newest, int(member.mtime))
                    node = tree
                    for part in parts[1:-1]:
                        node = node.setdefault(part.encode(), {})
                        if not isinstance(node, dict):
                            raise NarRefused("the tarball puts a directory under a file")
                    leaf = parts[-1].encode()
                    if member.isdir():
                        node.setdefault(leaf, {})
                    elif member.isreg():
                        total += member.size
                        if total > cls.MOST_BYTES:
                            raise NarRefused("the tarball unpacks to too much")
                        source = tar.extractfile(member)
                        node[leaf] = (bool(member.mode & 0o100), source.read() if source else b"")
                    elif member.issym():
                        node[leaf] = member.linkname.encode()
                    else:
                        raise NarRefused(
                            "the tarball holds an entry that is neither file, directory nor symlink"
                        )
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise NarRefused(f"the tarball could not be read ({type(exc).__name__})") from None
        digest = hashlib.sha256()
        digest.update(cls.string(b"nix-archive-1"))
        cls._node(tree, digest)
        return "sha256-" + base64.b64encode(digest.digest()).decode(), newest

    @classmethod
    def _node(cls, node: Any, digest: Any) -> None:
        s = cls.string
        digest.update(s(b"("))
        digest.update(s(b"type"))
        if isinstance(node, dict):
            digest.update(s(b"directory"))
            for name in sorted(node):
                digest.update(s(b"entry") + s(b"(") + s(b"name") + s(name) + s(b"node"))
                cls._node(node[name], digest)
                digest.update(s(b")"))
        elif isinstance(node, bytes):
            digest.update(s(b"symlink") + s(b"target") + s(node))
        else:
            executable, contents = node
            digest.update(s(b"regular"))
            if executable:
                digest.update(s(b"executable") + s(b""))
            digest.update(s(b"contents") + s(contents))
        digest.update(s(b")"))
