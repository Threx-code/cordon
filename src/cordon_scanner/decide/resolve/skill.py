"""BP-3-13: a skill folder is resolved by computing its tree digest locally.

A skill (`.claude/skills/deploy/` and the like) is a folder of files an agent reads. Its artifact is the digest of that folder
(`ArtifactDigests.of_tree`): each file's path relative to the folder, its mode and the hash of its bytes, sorted, so the same folder is
the same digest on every machine and any change to a file, its path or whether it is executable is another digest.

What the digest takes and what it refuses, so two machines cannot disagree about it:

* the mode is `755` when the owner may execute the file and `644` otherwise (the umask of the machine that made the checkout is not
  part of the skill);
* a `.git` folder is not part of the skill, and nothing else is skipped (hidden files are read: an agent reads them too);
* a symbolic link is refused (`symlink`): reading through it can leave the folder, and what it points at can change under a
  digest taken once;
* a folder over `MAX_FILES` files or `MAX_BYTES` bytes is refused (`too_large`), and one with a file that cannot be read, or a name the
  tree rule does not take, is `unreadable` or `unsupported_path`: never a digest of part of the folder.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import CanonicalIds, InvalidSubject, SubjectKind
from cordon_scanner.decide.resolve.resolution import Resolution


class SkillResolver:
    MAX_FILES: ClassVar[int] = 5000
    MAX_BYTES: ClassVar[int] = 64 * 1024 * 1024
    SKIPPED: ClassVar[tuple[str, ...]] = (".git",)

    @classmethod
    def resolve(cls, folder: Path, *, root: Path | None = None) -> Resolution:
        """The skill at `folder`: subject `skill:local/<folder relative to root>` (the folder's own name without a root) and the
        tree digest of its files."""
        kind = SubjectKind.AGENT_SKILL.value
        try:
            relative = folder.relative_to(root).as_posix() if root is not None else folder.name
            subject = CanonicalIds.canonical_id(
                SubjectKind.AGENT_SKILL, {"source": "local", "locator": relative}
            )
        except (ValueError, InvalidSubject):
            return Resolution.failed(kind, Resolution.stand_in("skill", str(folder)), "unparseable")
        if folder.is_symlink() or not folder.is_dir():
            return Resolution.failed(
                kind, subject, "symlink" if folder.is_symlink() else "not_a_folder"
            )
        entries: list[tuple[str, str, bytes]] = []
        total = 0
        try:
            for path in sorted(folder.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")):
                relative_path = path.relative_to(folder).as_posix()
                if relative_path.split("/", 1)[0] in cls.SKIPPED:
                    continue
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return Resolution.failed(kind, subject, "symlink")
                if stat.S_ISDIR(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode):
                    return Resolution.failed(kind, subject, "unreadable")
                total += info.st_size
                if len(entries) >= cls.MAX_FILES or total > cls.MAX_BYTES:
                    return Resolution.failed(kind, subject, "too_large")
                mode = "755" if info.st_mode & stat.S_IXUSR else "644"
                entries.append((relative_path, mode, path.read_bytes()))
        except OSError:
            return Resolution.failed(kind, subject, "unreadable")
        try:
            digest = ArtifactDigests.of_tree(entries)
        except ValueError:
            return Resolution.failed(kind, subject, "unsupported_path")
        return Resolution(kind=kind, subject_id=subject, status="resolved", digest=digest)


__all__ = ["SkillResolver"]
