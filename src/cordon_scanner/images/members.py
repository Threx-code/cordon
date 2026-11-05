"""Reading an image archive's members: a member name as the image's filesystem path, the members
by that path, and one member's bytes within a bound. Below the layer reader and the identity reader
that both use them."""

from __future__ import annotations

import posixpath
import tarfile


class ImageArchive:
    @staticmethod
    def normalise(name: str) -> str:
        return posixpath.normpath("/" + name).lstrip("/")

    @staticmethod
    def members_by_path(archive: tarfile.TarFile) -> dict[str, str]:
        return {ImageArchive.normalise(m.name): m.name for m in archive.getmembers()}

    @staticmethod
    def read_member(archive: tarfile.TarFile, name: str, limit: int = 16 << 20) -> bytes:
        member = archive.getmember(name)
        if not member.isfile() or member.size > limit:
            raise ValueError(f"{name} is not a readable file within limits")
        handle = archive.extractfile(member)
        if handle is None:
            raise ValueError(f"{name} could not be opened")
        return handle.read()


__all__ = ["ImageArchive"]
