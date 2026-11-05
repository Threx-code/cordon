"""Whether a cache file is this user's own, and closed to everyone else.

The caches Cordon keeps (the scan cache, the rule-file match and compile caches, the expander's
spill directories) refuse an entry another user could have written. On POSIX that is the owner
and the mode bits. Windows has neither `os.getuid` nor permission bits that mean anything (a file's
`st_mode` there is 0o666 whatever its ACL says), so the rule-engine caches crashed on Windows and,
had they not, would have refused every entry they kept. There the cache sits in the user's own
profile directory, closed to other users by its ACL, and these checks defer to that, as the scan
cache's own check already did.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from os import stat_result


class Ownership:
    """The three questions the caches ask of a file's stat."""

    @staticmethod
    def windows() -> bool:
        return os.name == "nt"

    @staticmethod
    def mine(st: stat_result) -> bool:
        """Owned by the user this process runs as."""
        return Ownership.windows() or st.st_uid == os.getuid()

    @staticmethod
    def private(st: stat_result) -> bool:
        """Mine, and nobody else can read or write it."""
        return Ownership.mine(st) and (Ownership.windows() or not st.st_mode & 0o077)

    @staticmethod
    def others_cannot_write(st: stat_result) -> bool:
        """Mine, and nobody else can write it."""
        return Ownership.mine(st) and (Ownership.windows() or not st.st_mode & 0o022)
