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


class ContainerPaths:
    """Paths inside archives and images, compared as files on disk are."""

    @staticmethod
    def within_container(path: str) -> str:
        """The path relative to whatever contains it.

        `a.zip!b/c.py` is `b/c.py`; `a.zip!c.py` is `c.py`; a plain path is itself.
        Nested containers use the last separator, because that is the innermost
        container and the one whose layout the name describes.
        """
        return path.rpartition(CONTAINER)[2] if CONTAINER in path else path

    @staticmethod
    def basename(path: str) -> str:
        """The final component, correct for members at a container root."""
        return ContainerPaths.within_container(path).rpartition("/")[2]

    @staticmethod
    def parent(path: str) -> str:
        """The directory part within the container, empty at its root."""
        return ContainerPaths.within_container(path).rpartition("/")[0]

    @staticmethod
    def under_fixture_directory(path: str) -> bool:
        """Whether a directory on this path is, by its whole name, a test or example directory.

        Exact segments only. `@antv-data-samples/` is a package whose name contains a word, not a
        directory of samples.
        """
        return any(segment.lower() in FIXTURE_DIRECTORIES for segment in path.split("/")[:-1])


__all__ = ["CONTAINER", "ContainerPaths"]


FIXTURE_DIRECTORIES = frozenset(
    {
        "test",
        "tests",
        "testing",
        "benchmark",
        "benchmarks",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "demo",
        "demos",
        "e2e",
        "integration",
        "spec",
        "specs",
        "testdata",
    }
)
"""Directories whose packaging scripts are INPUTS to a test suite.

A build file here is not the distribution's install hook. `pip install` runs the
`setup.py` at the distribution root; `test/cpp_extensions/setup.py` is a fixture
that pytorch's own test suite compiles, and nothing a consumer does executes it.

The distinction is not cosmetic, because a hook seeds an import closure. That
fixture does `from torch.utils.cpp_extension import ...`, which pulled 507 files
-- the closure's whole 500-file budget -- of `torch` into `install_hook_paths`.
Every `MALWARE.*` composite is gated on exactly that, so `torch/hub.py` reading
`GITHUB_TOKEN` beside an `api.github.com` call became `MALWARE.EXFIL.001` at
CRITICAL, and three ordinary `getattr` sites became
`MALWARE.DYNAMIC_DISPATCH.001`, on the claim that they "execute automatically on
every install". The real `setup.py` at pytorch's root does not import torch at
all: its closure is EMPTY.

The same shape put `six.py` in servo (`tests/wpt/tests/tools/third_party/`) and
two vendored modules in mongodb (`src/third_party/wiredtiger/test/3rdparty/`)
into the same category. `Engine._hook_executes` already refuses a `setup.py`
inside a package directory and a `.git/hooks/*.sample`; this is the third member
of that family and the one that reaches furthest, because of the closure.

No recall is traded. A package's install runs the build file at its root, so a
payload that wants to run on install has to be reachable from THAT one.
"""
