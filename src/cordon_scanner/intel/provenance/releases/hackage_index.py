"""Hackage's package index, kept in the scanner's state directory and checked whole against the signed snapshot.

Hackage's per-package targets (`<pkg>/<version>/package.json`) are not signed one by one: they live in `01-index.tar`, and the
snapshot (signed by Hackage's snapshot key) states that file's length and SHA-256. So a target is only as good as the whole file
it came from, and the file is checked whole every time it is used.

The index is append-only, with a 1024-byte zero trailer that each append overwrites. A refresh asks the repository for the bytes
from just before the cached end to the snapshot's length (an HTTP Range read: megabytes, not the whole gigabyte), appends them,
and checks the result against the snapshot's hash. A result that does not match puts the old bytes back; the cache is then
tried again from nothing in a separate file, which replaces the cache only if it matches."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, ClassVar, Protocol

from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.files.locks import FileLocks


class IndexProblem(ValueError):
    """The index could not be fetched, or is not the one the snapshot states."""


class Repository(Protocol):
    def index_range(self, start: int, length: int, sink: Callable[[bytes], None]) -> None:
        """Hand `sink` the bytes of `01-index.tar` from `start` to `length` (exclusive), in pieces; raise if the repository cannot."""


class IndexCache:
    TRAILER: ClassVar[int] = 1024
    MAX_BYTES: ClassVar[int] = 4 << 30
    CHUNK: ClassVar[int] = 1 << 20
    LOCK_WAIT: ClassVar[float] = 120.0

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / "01-index.tar"

    # -- the whole file, checked ----------------------------------------------------------------------------

    @classmethod
    def digest(cls, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(cls.CHUNK):
                digest.update(chunk)
        return digest.hexdigest()

    def ensure(self, repository: Repository, length: int, sha256: str) -> Path:
        """The cached index, brought to exactly `length` bytes of SHA-256 `sha256`; `IndexProblem` when it cannot be."""
        if not 0 < length <= self.MAX_BYTES:
            raise IndexProblem("the snapshot states an index size that is not accepted")
        self.directory.mkdir(parents=True, exist_ok=True)
        lock = os.open(
            self.directory / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600
        )
        try:
            self._take(lock)
            return self._ensure(repository, length, sha256)
        finally:
            FileLocks.release(lock)
            os.close(lock)

    def _take(self, lock: int) -> None:
        deadline = time.monotonic() + self.LOCK_WAIT
        while not FileLocks.take(lock):
            if time.monotonic() > deadline:
                raise IndexProblem("another scan is refreshing the index")
            time.sleep(0.25)

    def _ensure(self, repository: Repository, length: int, sha256: str) -> Path:
        have = self.path.stat().st_size if self.path.exists() else 0
        if have == length and self.digest(self.path) == sha256:
            return self.path
        if 0 < have <= length and self._extend(repository, have, length, sha256):
            return self.path
        self._replace(repository, length, sha256)
        return self.path

    def _extend(self, repository: Repository, have: int, length: int, sha256: str) -> bool:
        """Append the tail; on a result that is not the snapshot's, put the old bytes back and say so."""
        start = max(0, have - self.TRAILER)
        with self.path.open("r+b") as handle:
            handle.seek(start)
            kept = handle.read(have - start)
            handle.seek(start)
            handle.truncate()
            try:
                self._write(repository, handle, start, length)
            except (IndexProblem, OSError, ValueError):
                self._restore(handle, start, kept)
                return False
        if self.digest(self.path) == sha256:
            return True
        with self.path.open("r+b") as handle:
            self._restore(handle, start, kept)
        return False

    @staticmethod
    def _restore(handle: BinaryIO, start: int, kept: bytes) -> None:
        handle.seek(start)
        handle.truncate()
        handle.write(kept)
        handle.flush()

    def _replace(self, repository: Repository, length: int, sha256: str) -> None:
        part = self.directory / "01-index.tar.part"
        try:
            with part.open("wb") as handle:
                self._write(repository, handle, 0, length)
            if self.digest(part) != sha256:
                raise IndexProblem("the index is not the one the snapshot's hash names")
            part.replace(self.path)
        finally:
            part.unlink(missing_ok=True)

    def _write(self, repository: Repository, handle: BinaryIO, start: int, length: int) -> None:
        written = 0

        def sink(piece: bytes) -> None:
            nonlocal written
            written += len(piece)
            if written > length - start:
                raise IndexProblem("more bytes than the snapshot's length")
            handle.write(piece)

        repository.index_range(start, length, sink)
        if written != length - start:
            raise IndexProblem("the index came back short: a truncated tail")
        handle.flush()


class TarIndex:
    """The `package.json` entries of a tar file, found by walking its headers and seeking over the data."""

    BLOCK: ClassVar[int] = 512
    MAX_NAME: ClassVar[int] = 4096
    MAX_ENTRY: ClassVar[int] = 1 << 20
    _walked: ClassVar[dict[tuple[str, int, int], dict[str, tuple[int, int]]]] = {}

    @classmethod
    def entries(cls, path: Path) -> dict[str, tuple[int, int]]:
        """Each `<name>/<version>/package.json` of the file: (data offset, size). A later entry of the same name replaces an earlier."""
        stat = path.stat()
        key = (str(path), stat.st_size, stat.st_mtime_ns)
        found = cls._walked.get(key)
        if found is None:
            found = cls._walk(path)
            cls._walked.clear()
            cls._walked[key] = found
        return found

    @classmethod
    def _walk(cls, path: Path) -> dict[str, tuple[int, int]]:
        found: dict[str, tuple[int, int]] = {}
        size = path.stat().st_size
        with path.open("rb") as handle:
            at = 0
            long_name: str | None = None
            while at + cls.BLOCK <= size:
                handle.seek(at)
                header = handle.read(cls.BLOCK)
                if header == b"\0" * cls.BLOCK:
                    at += cls.BLOCK
                    continue
                data = at + cls.BLOCK
                length = cls._octal(header[124:136])
                kind = header[156:157]
                if kind in (b"L", b"x", b"g"):
                    if length > cls.MAX_NAME:
                        raise IndexProblem("a tar name record past any real size")
                    body = handle.read(length)
                    if kind == b"L":
                        long_name = body.split(b"\0", 1)[0].decode("utf-8", "replace")
                else:
                    name = long_name or cls._name(header)
                    long_name = None
                    if name.endswith("/package.json") and name.count("/") == 2:
                        found[name] = (data, length)
                at = data + (length + cls.BLOCK - 1) // cls.BLOCK * cls.BLOCK
        return found

    @staticmethod
    def _octal(field: bytes) -> int:
        text = field.split(b"\0", 1)[0].strip()
        try:
            return int(text or b"0", 8)
        except ValueError as exc:
            raise IndexProblem("a tar header with an unreadable size") from exc

    @staticmethod
    def _name(header: bytes) -> str:
        name = header[:100].split(b"\0", 1)[0].decode("utf-8", "replace")
        prefix = (
            header[345:500].split(b"\0", 1)[0].decode("utf-8", "replace")
            if header[257:262] == b"ustar"
            else ""
        )
        return f"{prefix}/{name}" if prefix else name

    @classmethod
    def read(cls, path: Path, name: str) -> bytes | None:
        located = cls.entries(path).get(name)
        if located is None:
            return None
        offset, size = located
        if size > cls.MAX_ENTRY:
            raise IndexProblem("a package entry past any real size")
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(size)


ScanCaches.register(TarIndex._walked)
