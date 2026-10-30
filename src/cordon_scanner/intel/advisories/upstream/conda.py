"""conda packages: the recipe a package was built from, and the sibling packages built from it."""

from __future__ import annotations

import contextlib
import io
import json
import re
import tarfile
import time
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.network.downloads import BUDGET_SECONDS, Download
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.intel.advisories.upstream.base import (
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.fetch import Fetch

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.results import Dependency


class CondaPackage:
    """The rendered recipe inside a conda package, read without downloading the package.

    A `.conda` file is a zip whose `info-*.tar.zst` member holds `info/`; its central directory is
    at the end, so two range requests reach it: the tail, then the member. That member is zstd,
    which the standard library reads from Python 3.14 (`compression.zstd`); before it, the
    `zstandard` package if installed, else the core's own decoder (`intel/zstd`).
    A legacy `.tar.bz2` is read as a stream, to a bound.
    """

    #: A font, or what ships beside one (its licence, fontconfig's configuration): data, not code.
    FONT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\.(?:ttf|otf|ttc|pfb|pfa|afm|pcf(?:\.gz)?|bdf|woff2?)$|(?:^|/)(?:LICEN[CS]E|COPYING|NOTICE|README)[\w.-]*$|^etc/fonts/.*\.conf$"
    )
    RECIPES: ClassVar[tuple[str, ...]] = (
        "info/recipe/meta.yaml",
        "info/recipe/rendered_recipe.yaml",
    )
    #: An info member holds a package's test suite too (pillow's, with its images, is 45 MB).
    MAX_INFO_BYTES: ClassVar[int] = 64 << 20
    #: Bytes read on the way to the recipe, never kept: a test suite's data may come first.
    MAX_STREAM_BYTES: ClassVar[int] = 512 << 20

    @staticmethod
    def _range(url: str, header: str, limit: int) -> tuple[bytes, int]:
        import urllib.request

        request = urllib.request.Request(  # noqa: S310 - https, checked by the caller
            url, headers={"Range": header, "User-Agent": "cordon-scanner"}
        )
        with urllib.request.build_opener(NoRedirects).open(request, timeout=60) as response:
            if response.status != 206:
                raise ValueError("the server does not answer a byte range")
            total = int(str(response.headers.get("Content-Range", "/0")).rpartition("/")[2] or 0)
            body: bytes = Download.read(response, limit + 1)
        if len(body) > limit:
            raise ValueError("range too large")
        return body, total

    @staticmethod
    def _zstd_stream(blob: bytes) -> io.RawIOBase:
        """`blob` decompressed as it is read, to at most MAX_STREAM_BYTES."""
        try:
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

            stream: Any = zstd.ZstdFile(io.BytesIO(blob))
        except ImportError:
            from cordon_scanner.intel.store.zstd import Zstd

            # The core's own decoder: no third-party dependency (CONSTRAINT C1).
            stream = Zstd.Reader(blob, CondaPackage.MAX_STREAM_BYTES)
        return CondaPackage._Bounded(stream, CondaPackage.MAX_STREAM_BYTES)

    class _Bounded(io.RawIOBase):
        """A stream that fails once more than `limit` bytes are read from it."""

        def __init__(self, inner: Any, limit: int) -> None:
            self.inner, self.left = inner, limit

        def readable(self) -> bool:
            return True

        def readinto(self, buffer: Any) -> int:
            data = self.inner.read(len(buffer))
            self.left -= len(data)
            if self.left < 0:
                raise ValueError("info too large")
            buffer[: len(data)] = data
            return len(data)

    @staticmethod
    def _from_tar(archive: tarfile.TarFile, seen: dict[str, int] | None = None) -> str | None:
        """The recipe; and, into `seen`, how many files `info/paths.json` lists where it comes before
        the recipe. With `seen["want_paths"]` set, read on past the recipe to paths.json (for a
        package whose recipe names no source; a metapackage's info/ is small)."""
        recipe: str | None = None
        for member in archive:
            if member.name == "info/paths.json" and member.isfile() and seen is not None:
                handle = archive.extractfile(member)
                if handle is not None:
                    with contextlib.suppress(ValueError):
                        listed = json.loads(handle.read(CondaPackage.MAX_INFO_BYTES))
                        if isinstance(listed, dict) and isinstance(listed.get("paths"), list):
                            seen["paths"] = len(listed["paths"])
                            installed = [
                                str(p.get("_path") or "") if isinstance(p, dict) else ""
                                for p in listed["paths"]
                            ]
                            if installed and all(CondaPackage.FONT.search(p) for p in installed):
                                seen["fonts_only"] = 1
                continue
            if member.name in CondaPackage.RECIPES and member.isfile() and recipe is None:
                handle = archive.extractfile(member)
                if handle is not None:
                    recipe = handle.read(CondaPackage.MAX_INFO_BYTES).decode("utf-8", "replace")
            if recipe is not None and not (seen and seen.get("want_paths") and "paths" not in seen):
                return recipe
        return recipe

    @staticmethod
    def recipe(url: str, seen: dict[str, int] | None = None) -> str | None:
        import struct

        if url.endswith(".tar.bz2"):
            import urllib.request

            request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
            with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
                # The whole stream within the budget, not each read (`foundation/network/downloads.py`).
                deadline = time.monotonic() + BUDGET_SECONDS

                class Bounded(io.RawIOBase):
                    read_so_far = 0

                    def readable(self) -> bool:
                        return True

                    def readinto(self, buffer: Any) -> int:
                        chunk = Download.read(
                            response,
                            min(len(buffer), 1 << 16),
                            budget=max(0.0, deadline - time.monotonic()),
                        )
                        Bounded.read_so_far += len(chunk)
                        if Bounded.read_so_far > CondaPackage.MAX_STREAM_BYTES:
                            raise ValueError("package too large to read its recipe")
                        buffer[: len(chunk)] = chunk
                        return len(chunk)

                with tarfile.open(fileobj=io.BufferedReader(Bounded()), mode="r|bz2") as archive:
                    return CondaPackage._from_tar(archive, seen)
        if not url.endswith(".conda"):
            return None
        tail, total = CondaPackage._range(url, "bytes=-65536", 65536)
        end = tail.rfind(b"PK\x05\x06")
        if end < 0:
            raise ValueError("no zip directory at the end of the package")
        size, offset = struct.unpack("<II", tail[end + 12 : end + 20])
        if 0xFFFFFFFF in (size, offset):
            # ZIP64 (APPNOTE 4.3.14-15): the locator just before the end record names the ZIP64
            # end record, which holds the directory's 8-byte size and offset.
            locator = tail.rfind(b"PK\x06\x07", 0, end)
            record_at = (
                struct.unpack("<Q", tail[locator + 8 : locator + 16])[0] if locator >= 0 else -1
            )
            start = record_at - (total - len(tail))
            if locator < 0 or start < 0 or not tail.startswith(b"PK\x06\x06", start):
                raise ValueError("a ZIP64 package whose directory could not be found")
            size, offset = struct.unpack("<QQ", tail[start + 40 : start + 56])
        start_of_tail = total - len(tail)
        if offset >= start_of_tail:
            directory = tail[offset - start_of_tail : offset - start_of_tail + size]
        else:
            directory, _ = CondaPackage._range(url, f"bytes={offset}-{offset + size - 1}", size)
        position = 0
        while directory.startswith(b"PK\x01\x02", position):
            method, compressed = (
                struct.unpack("<H", directory[position + 10 : position + 12])[0],
                struct.unpack("<I", directory[position + 20 : position + 24])[0],
            )
            name_len, extra_len, comment_len = struct.unpack(
                "<HHH", directory[position + 28 : position + 34]
            )
            local = struct.unpack("<I", directory[position + 42 : position + 46])[0]
            name = directory[position + 46 : position + 46 + name_len].decode("utf-8", "replace")
            # ZIP64 (APPNOTE 4.5.3): a field written 0xFFFFFFFF is in the extra field's 0x0001
            # block, 8 bytes each, in the order uncompressed size, compressed size, offset.
            uncompressed = struct.unpack("<I", directory[position + 24 : position + 28])[0]
            extra = directory[position + 46 + name_len : position + 46 + name_len + extra_len]
            compressed, local, uncompressed = CondaPackage._zip64_fields(
                extra, uncompressed, compressed, local
            )
            position += 46 + name_len + extra_len + comment_len
            if not (name.startswith("info-") and name.endswith(".tar.zst")) or method != 0:
                continue
            if compressed > CondaPackage.MAX_INFO_BYTES:
                raise ValueError("info too large")
            head, _ = CondaPackage._range(url, f"bytes={local}-{local + 29}", 30)
            skip = 30 + sum(struct.unpack("<HH", head[26:30]))
            body, _ = CondaPackage._range(
                url, f"bytes={local + skip}-{local + skip + compressed - 1}", compressed
            )
            # Read as a stream, to the recipe: info/ may hold far more than the recipe (a test
            # suite, every path), so it is never decompressed whole.
            with tarfile.open(fileobj=CondaPackage._zstd_stream(body), mode="r|") as archive:
                return CondaPackage._from_tar(archive, seen)
        return None

    @staticmethod
    def _zip64_fields(
        extra: bytes, uncompressed: Any, compressed: Any, local: Any
    ) -> tuple[Any, Any, Any]:
        """A central-directory entry's sizes and offset, from its ZIP64 extra field where the entry defers to it."""
        import struct

        at = 0
        while at + 4 <= len(extra):
            kind, length = struct.unpack("<HH", extra[at : at + 4])
            if kind == 1:
                wide = iter(
                    struct.unpack(
                        f"<{min(length, 24) // 8}Q",
                        extra[at + 4 : at + 4 + length // 8 * 8][:24],
                    )
                )
                fields = [uncompressed, compressed, local]
                fields = [next(wide, f) if f == 0xFFFFFFFF else f for f in fields]
                uncompressed, compressed, local = fields
            at += 4 + length
        return compressed, local, uncompressed


class CondaSiblings:
    """A conda package naming no source of its own -- one output of a multi-output recipe
    (glib-tools of glib) -- built in the same feedstock commit as another package of the same
    lock that does name one: the same recipe, built once, from the same source.

    conda-smithy writes the feedstock and commit a package was built from into its rendered
    recipe (`extra: remote_url, sha`); two packages with the same pair came from one build."""

    #: The ecosystem whose builds share one upstream source (conda's, from one feedstock).
    ECOSYSTEM: ClassVar[str] = "conda"

    _built: ClassVar[dict[str, tuple[str, str]]] = {}

    @staticmethod
    def record(url: str, data: object) -> None:
        extra = data.get("extra") if isinstance(data, dict) else None
        if not isinstance(extra, dict):
            return
        remote, sha = str(extra.get("remote_url") or ""), str(extra.get("sha") or "")
        repository = RepositoryArchive.repository(remote)
        if repository and re.fullmatch(r"[0-9a-f]{40}", sha):
            CondaSiblings._built[url] = (repository, sha)

    @staticmethod
    def resolve(
        dependencies: Sequence[Dependency], answers: Sequence[Upstream | Unnamed]
    ) -> list[Upstream | Unnamed]:
        named: dict[tuple[str, str], Upstream] = {}
        for dependency, answer in zip(dependencies, answers, strict=True):
            build = CondaSiblings._built.get(dependency.resolved_from or "")
            if (
                dependency.ecosystem == CondaSiblings.ECOSYSTEM
                and build
                and isinstance(answer, Upstream)
            ):
                named.setdefault(build, answer)
        out = list(answers)
        for i, (dependency, answer) in enumerate(zip(dependencies, answers, strict=True)):
            build = CondaSiblings._built.get(dependency.resolved_from or "")
            if (
                dependency.ecosystem == CondaSiblings.ECOSYSTEM
                and build in named
                and isinstance(answer, Unnamed)
                and answer.reason.startswith("its source names no URL")
            ):
                found = named[build]
                out[i] = Upstream(
                    found.query,
                    f"{found.how}; {dependency.name} is another output of the same build "
                    f"({build[0]} at {build[1][:12]})",
                    found.inferred,
                    found.tag,
                )
                Fetch.resolved[
                    (
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version,
                        dependency.integrity,
                    )
                ] = out[i]
        return out


# Network answers, kept for one scan: a long-running process (the MCP server) asks again
# rather than keeping every answer it was ever given.
ScanCaches.register(CondaSiblings._built)


__all__ = ["CondaPackage", "CondaSiblings"]
