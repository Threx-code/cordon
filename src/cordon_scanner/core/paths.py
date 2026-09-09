"""Reading a path that may name something inside a container.

An archive member is addressed as `archive.zip!member/path`, and every path
helper in the codebase split on `/` to find a basename. For a member at the
archive *root* there is no `/`, so the basename became the whole string
`archive.zip!package.json` -- which matches no manifest glob, no lockfile glob
and no language extension.

The consequence was a one-line evasion. The same malicious `package.json` was
found as a loose file and inside `package/` in a tarball, and disappeared at an
archive root:

    package.json                 manifest=npm    lang=json
    pkg.zip!package.json         manifest=None   lang=json     <- root member
    a.nupkg!lib.nuspec           manifest=None   lang=None     <- root member
    w.whl!setup.py               manifest=None   lang=python   <- root member

Manifest parsing, lockfile parsing, dependency-graph construction, install-hook
context and language selection all failed together, and `w.whl!setup.py` lost
its install-time risk multiplier as well. npm tarballs were safe only because
their convention puts everything under `package/`, and packaging the payload
differently is free.

So the split happens in one place, here, and the helpers use it rather than each
reimplementing `rpartition("/")` against a string that may not be a plain path.
"""

from __future__ import annotations

CONTAINER = "!"
"""Separates a container from the path inside it, as `walk_archive` writes it."""


def within_container(path: str) -> str:
    """The path relative to whatever contains it.

    `a.zip!b/c.py` is `b/c.py`; `a.zip!c.py` is `c.py`; a plain path is itself.
    Nested containers use the last separator, because that is the innermost
    container and the one whose layout the name describes.
    """
    return path.rpartition(CONTAINER)[2] if CONTAINER in path else path


def basename(path: str) -> str:
    """The final component, correct for members at a container root."""
    return within_container(path).rpartition("/")[2]


def parent(path: str) -> str:
    """The directory part within the container, empty at its root."""
    return within_container(path).rpartition("/")[0]


__all__ = ["CONTAINER", "basename", "parent", "within_container"]
