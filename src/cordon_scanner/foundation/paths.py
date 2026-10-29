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

import functools
import os
import sys
from pathlib import Path

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


class StatePaths:
    """Where Cordon keeps what it remembers between runs: the cache's entries, which the
    environment may direct, and the keys that authenticate them, which it may not. The scan
    cache, the evidence key and the intelligence caches all ask here, so the rule about what an
    environment variable can move is stated once."""

    @staticmethod
    def default_cache_dir() -> Path:
        """Where cache *entries* live when the user has not chosen.

        Honours ``XDG_CACHE_HOME`` on Unix so it lands with everything else rather
        than in the middle of the repository being scanned, which would then have to
        be excluded and would appear in status output.

        Environment-directed, and deliberately so -- CI needs to point this at a
        restorable path. See `key_dir`, which is not, and why.
        """
        override = os.environ.get("CORDON_CACHE_DIR")
        if override:
            return Path(override)
        xdg = os.environ.get("XDG_CACHE_HOME")
        if xdg:
            return Path(xdg) / "cordon"
        return Path.home() / ".cache" / "cordon"

    @staticmethod
    def synced_intel_dir() -> Path:
        """Where `advisories sync` and the feed write what they fetch: the advisory database, the
        feed's overlays and rules, the OS databases. Inside the cache root (`default_cache_dir`),
        so it moves with it."""
        return StatePaths.default_cache_dir() / "advisories"

    @staticmethod
    def key_dir() -> Path:
        """Where the authentication key lives. Not environment-directed.

        The key used to live beside the entries, which meant one variable
        decided both: anything able to set `CORDON_CACHE_DIR` in a build could
        point it at a directory it had already filled with entries and a key of
        its own, and every forged `{"findings": []}` would verify.

        Moving it to `Path.home()` did not fix that. `Path.home()` reads `$HOME`,
        which is a variable too -- the most basic one -- and the same attacker
        sets it in the same `env:` block. An audit demonstrated the full bypass
        against exactly that: plant a key under a redirected `$HOME`, compute
        the cache key for each payload file from inputs that are all public,
        write a correctly-MAC'd empty result, and the scan exits 0 over code it
        never examined. The reasoning in this docstring was right and stopped
        one variable short of applying it.

        The password database is not a variable. `getpwuid` answers from the
        system's own account store, so nothing in the process environment moves
        it. `$HOME` is used only where that lookup is unavailable -- Windows, or
        a container with no passwd entry for the running uid -- and there the
        binding in `_mac` is what carries the weight instead.
        """
        return StatePaths._home() / ".cache" / "cordon"

    @staticmethod
    def _home() -> Path:
        """The running user's home directory, from the account store.

        Falls back to `Path.home()` when there is no account entry, which is
        ordinary inside minimal containers. The fallback is weaker and is not
        silent: `_mac` binds the resolved key path, so a key obtained from a
        different location does not validate entries.
        """
        try:
            import pwd

            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        except (ImportError, KeyError, AttributeError, OSError):
            # pragma: no cover - Windows, or a uid with no passwd entry
            return Path.home()


__all__ = ["CONTAINER", "ContainerPaths", "StatePaths"]


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
into the same category. `Hooks.hook_executes` already refuses a `setup.py`
inside a package directory and a `.git/hooks/*.sample`; this is the third member
of that family and the one that reaches furthest, because of the closure.

No recall is traded. A package's install runs the build file at its root, so a
payload that wants to run on install has to be reachable from THAT one.
"""


class PackagePaths:
    """Where the scanner's own files are: found from the package itself, not from how deep the
    module asking sits, so a module moved into a subfolder still finds its data (reviews
    20-PACKAGE-STRUCTURE.md)."""

    @staticmethod
    @functools.cache
    def root() -> Path:
        """The `cordon_scanner` package directory."""
        return Path(str(sys.modules["cordon_scanner"].__file__)).resolve().parent

    @staticmethod
    def data(area: str) -> Path:
        """An area's bundled data directory: `detect`, `intel`."""
        return PackagePaths.root() / area / "data"
