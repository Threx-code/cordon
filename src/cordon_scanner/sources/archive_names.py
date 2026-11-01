"""An archive member's name, made safe and made text, and the shape of a link member: the
name-level half of `sources/archive.py`'s `ArchiveReader`, which keeps them under their old names
(moved for the module's length, item 34)."""

from __future__ import annotations

from pathlib import PurePosixPath

from cordon_scanner.foundation.files.names import Names


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
