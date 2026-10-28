"""Where a manifest says its dependencies come from: registries, indexes, git, archives, local paths.

A dependency source is an execution vector of its own: a git commit runs that commit's install
scripts, an index merged with a private one lets the highest version anywhere win, a source over
plain HTTP is whatever the network serves.
"""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


_FULL_COMMIT = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")


class DeclaredSource:
    """What a non-registry specification points at.

    ```
      inside    a path within this repository (file:, link:, portal:, workspace:, ./, ../)
      outside   a path that leaves the repository, or an absolute one
      pinned    a git reference to a full commit SHA: immutable
      mutable   a git reference to a branch, a tag or nothing: a push re-points it
      url       a download URL (an archive, a tarball)
    ```
    """

    GIT = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh://", "gist:")

    @staticmethod
    def kind(spec: str, manifest_path: str) -> str:
        text = spec.strip()
        lowered = text.lower()
        if lowered.startswith("workspace:"):
            return "inside"
        path: str | None = None
        for prefix in ("file:", "link:", "portal:", "path:"):
            if lowered.startswith(prefix):
                path = text[len(prefix) :]
                break
        else:
            if lowered.startswith(("./", "../", "/", "~")):
                path = text
        if path is not None:
            if path.startswith(("/", "~")):
                return "outside"
            base = manifest_path.rpartition("/")[0]
            joined = posixpath.normpath(posixpath.join(base, path) if base else path)
            return "outside" if joined == ".." or joined.startswith("../") else "inside"
        # `.git` as a path's suffix, not as a substring: `raw.githubusercontent.com` is not a git
        # URL, and read as one, a pinned raw file was reported as a movable git reference.
        is_git = (
            lowered.startswith(DeclaredSource.GIT)
            or re.search(r"\.git(?:$|[#/@?])", lowered)
            or re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", lowered)
        )
        if is_git:
            return "pinned" if _FULL_COMMIT.search(text) else "mutable"
        return "url"


__all__ = ["DeclaredSource"]
