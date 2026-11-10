"""The hashes registries publish for a package file, checked over the bytes Cordon fetched.

`sha512`, `sha256`: of the file itself (npm integrity; PyPI, crates.io, RubyGems). `h1`: Go's hash of a
module zip's *contents* (golang.org/x/mod/sumdb/dirhash Hash1), recomputed in memory.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from typing import ClassVar


class ArchiveDigest:
    @staticmethod
    def of(algorithm: str, data: bytes) -> bytes:
        if algorithm == "h1":
            return GoModuleHash.of_zip(data)
        if algorithm == "commit":
            return CommitArchive.of_zip(data)
        return hashlib.new(algorithm, data).digest()


class CommitArchive:
    """`commit`: the git commit a code host's archive of one commit names, for a registry that
    publishes no file hash (Composer's GitHub dists). GitHub writes the full commit hash as the zip's
    comment and roots every file in one folder ending in its first seven characters
    (`Seldaek-monolog-f4393b6/`); both must name the same commit, and the hash is what is checked."""

    @staticmethod
    def of_zip(data: bytes) -> bytes:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                comment = zf.comment.decode("ascii", "replace").strip()
                roots = {name.split("/", 1)[0] for name in zf.namelist()}
        except (zipfile.BadZipFile, OSError, EOFError) as exc:
            raise ValueError("an archive that cannot be read") from exc
        if len(comment) != 40 or any(c not in "0123456789abcdef" for c in comment):
            raise ValueError("an archive that does not name the commit it was made from")
        if len(roots) != 1 or not next(iter(roots)).endswith("-" + comment[:7]):
            raise ValueError("an archive whose folder does not name its commit")
        return bytes.fromhex(comment)


class GoModuleHash:
    """Go's `h1:` hash (golang.org/x/mod/sumdb/dirhash Hash1) of a module zip, computed in memory."""

    MAX_FILES: ClassVar[int] = 100_000

    @classmethod
    def of_zip(cls, data: bytes) -> bytes:
        lines: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = [i.filename for i in zf.infolist() if not i.is_dir()]
                if len(names) > cls.MAX_FILES:
                    raise ValueError("a module zip with more files than Cordon reads")
                for name in sorted(names):
                    if "\n" in name:
                        raise ValueError("a module zip with a newline in a file name")
                    digest = hashlib.sha256(zf.read(name)).hexdigest()
                    lines.append(f"{digest}  {name}\n")
        except (zipfile.BadZipFile, OSError, EOFError) as exc:
            raise ValueError("a module zip that cannot be read") from exc
        return hashlib.sha256("".join(lines).encode()).digest()

    @staticmethod
    def parse(value: str) -> bytes | None:
        if not value.startswith("h1:"):
            return None
        try:
            digest = base64.b64decode(value[3:], validate=True)
        except ValueError:
            return None
        return digest if len(digest) == 32 else None


__all__ = ["ArchiveDigest", "CommitArchive", "GoModuleHash"]
