"""An archive member's name, made safe and made text, the shape of a link member, and whether a
member named as an archive is one: the name-level half of `sources/archive.py`'s `ArchiveReader`,
which keeps them under their old names (items 34 and 27)."""

from __future__ import annotations

import io
import tarfile
from pathlib import PurePosixPath

from cordon_scanner.foundation.files.names import Names
from cordon_scanner.sources.zip_entries import ZipEntries


class MemberNames:
    @staticmethod
    def safe_member_name(name: str, *, collapse: bool = False) -> str | None:
        """`normalise_member_name`, made text (`Names.text`): what a member is stored and reported
        as. Made text after normalising, never before: the `\\` of a `\\xNN` is then never read
        as a separator, and as no normalised name holds a backslash, no escaped name equals a real
        one. A check on the path's shape (`link_stays_inside`) takes the normalised form."""
        normal = MemberNames.normalise_member_name(name, collapse=collapse)
        return None if normal is None else Names.text(normal)

    @staticmethod
    def normalise_member_name(name: str, *, collapse: bool = False) -> str | None:
        """Normalise a member name, or return None if it is unsafe.

        Rejected: absolute paths, drive letters, any traversal segment, and names
        containing NUL. The check is on the *normalised* form, so ``a/../../b`` is
        caught even though no single component looks wrong.

        With `collapse`, a `..` that stays inside the archive is resolved instead
        (`pkg-0.3.1/../README.md` is `README.md`, which some sdist builders write);
        one that climbs above the archive's root is still refused. Callers pass it
        only while no link member has come before this one: an extractor writes
        `a/../x` through `a` once `a` is a symlink, so then the name is refused.
        """
        if not name or "\x00" in name:
            return None

        cleaned = name.replace("\\", "/")

        if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
            return None

        parts = PurePosixPath(cleaned).parts
        if any(part == ".." for part in parts):
            if not collapse:
                return None
            kept: list[str] = []
            for part in parts:
                if part == "..":
                    if not kept:
                        return None
                    kept.pop()
                elif part not in {".", ""}:
                    kept.append(part)
            parts = tuple(kept)

        normalised = PurePosixPath(*(p for p in parts if p not in {".", ""}))
        text = str(normalised)
        return None if text in {".", ""} else text

    #: Headers a reader decompresses or opens whatever the name says: gzip, bzip2, xz, zstd, lz4, 7z.
    _OPENED_HEADERS: tuple[bytes, ...] = (
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"\x28\xb5\x2f\xfd",
        b"\x04\x22\x4d\x18",
        b"7z\xbc\xaf\x27\x1c",
    )

    @staticmethod
    def not_an_archive(data: bytes) -> str | None:
        """ "empty" for 0 bytes, "text" for bytes that every archive reader declines, that are text,
        and that hold no archive; else None (an archive that would not open, which stays refused, a
        gap that blocks). Declined by all three, never by the first bytes alone: a zip may carry any
        prefix (a self-extracting stub, a polyglot), so a zip entry is looked for anywhere. And never
        by "it decodes" alone: a stored zip of text entries is valid UTF-8, and one Python refuses
        while another extractor opens it would be scanned as text with its members never read
        (basedpyright's zipfs/corrupt.* shape). A zip entry is one an extractor finds, a local header
        that reads as one or a directory pointing at one (`ZipEntries.present`, item 76), not a
        signature alone: a zip library's own source carries every signature as a constant."""
        if not data:
            return "empty"
        if ZipEntries.present(data):
            return None
        if data[257:262] == b"ustar" or data.startswith(MemberNames._OPENED_HEADERS):
            return None
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
                if tar.next() is not None:
                    return None  # an old-style tar header reads
        except (tarfile.TarError, EOFError, OSError, ValueError):
            pass
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return "text"

    @staticmethod
    def link_stays_inside(member: str, target: str, *, hard: bool = False) -> bool:
        """Whether a link member points at another path inside the same archive.

        Such a link is never followed, and it carries no content of its own: what it names is a
        member read in its own right. Refused, it marked the scan incomplete -- 470 of 3,000 nix
        repositories and 504 of 3,000 bazel archives were scored "not fully examined" for symlinks
        such as `include/alsa -> ../alsa` (review 98). A target that is absolute or climbs out of
        the archive stays refused: that link is how an extractor is made to read or write outside.
        """
        if not target or "\x00" in target:
            return False
        cleaned = target.replace("\\", "/")
        if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
            return False
        # A hard link names an archive path; a symbolic link is relative to its own directory.
        base = () if hard else PurePosixPath(member.replace("\\", "/")).parent.parts
        depth: list[str] = [p for p in base if p not in {".", ""}]
        for part in PurePosixPath(cleaned).parts:
            if part in {".", ""}:
                continue
            if part == "..":
                if not depth:
                    return False
                depth.pop()
            else:
                depth.append(part)
        return bool(depth)


__all__ = ["MemberNames"]
