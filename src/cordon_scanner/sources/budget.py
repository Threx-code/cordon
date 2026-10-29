"""A compressed archive's decompressed bytes, metered as they are produced: the total budget, the
expansion cap and the deadline bind while tarfile reads, not after.
"""

from __future__ import annotations

import time
from typing import Any, cast

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import Limits

READ_CHUNK = 65536


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class BudgetExceeded(ArchiveError):
    """A decompressed budget was reached. `padded` when it was the expansion cap."""

    def __init__(self, message: str, *, hint: str = "", padded: bool = False) -> None:
        super().__init__(message, hint=hint)
        self.padded = padded


class _BudgetedStream:
    """A tar archive's DECOMPRESSED bytes, metered as they are produced.

    Every byte tarfile reads - a header, a member it hands back, or the data of a member it skips -
    passes through `read`, so three limits hold whatever tarfile does with the bytes:

    * the expansion cap, `ArchiveReader.expansion_cap`, judged from the whole archive's size;
    * a total decompressed budget, `Limits.max_uncompressed_bytes`;
    * the deadline.

    Each raises; the members read before it are kept (`ArchiveReader._extract_tar`), as a
    streaming installer would have written them.
    """

    def __init__(
        self,
        inner: Any,
        compressed: _BytesReader | None,
        limits: Limits,
        deadline: float | None,
        path: str,
        cap: int = 0,
    ) -> None:
        self.inner, self.compressed, self.limits, self.deadline, self.path = (
            inner,
            compressed,
            limits,
            deadline,
            path,
        )
        self.cap = cap
        self.produced = 0

    @classmethod
    def open(
        cls, data: bytes, *, limits: Limits, deadline: float | None, path: str, cap: int = 0
    ) -> _BudgetedStream:
        import bz2
        import gzip
        import lzma

        raw = _BytesReader(data)
        # Not context-managed: the decompressor is the stream tarfile reads for as long as the
        # archive is open, over bytes already in memory, so there is no descriptor to leak.
        if data[:2] == b"\x1f\x8b":
            inner: Any = gzip.GzipFile(fileobj=cast("Any", raw), mode="rb")
        elif data[:3] == b"BZh":
            inner = bz2.BZ2File(cast("Any", raw), mode="rb")
        elif data[:6] == b"\xfd7zXZ\x00":
            inner = lzma.LZMAFile(cast("Any", raw), mode="rb")  # noqa: SIM115
        elif data[:4] == ZSTD_MAGIC:
            # Past the budget by a read's worth, so `read` reports the budget, not the decoder.
            inner = _BudgetedStream._zstd(raw, limits.max_uncompressed_bytes + READ_CHUNK * 16)
        else:
            return cls(raw, None, limits, deadline, path, cap)
        return cls(inner, raw, limits, deadline, path, cap)

    @staticmethod
    def _zstd(raw: _BytesReader, limit: int) -> Any:
        """A zstd decompressing reader: the standard library's (3.14), else the core's own decoder
        (`intel/store/zstd`), so a `.conda` package is read with no third-party dependency
        (CONSTRAINT C1). The last fails past `limit` bytes."""
        try:
            from compression import zstd  # type: ignore[import-not-found]

            return zstd.ZstdFile(raw, mode="rb")
        except ImportError:
            from cordon_scanner.intel.store.zstd import Zstd

            return Zstd.Reader(raw, limit)

    def read(self, size: int = -1) -> bytes:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ArchiveError(f"{self.path}: the time budget ran out while reading the archive")
        if size is None or size < 0:
            size = READ_CHUNK
        chunk: bytes = self.inner.read(min(size, READ_CHUNK * 16))
        self.produced += len(chunk)
        if self.compressed is not None and 0 < self.cap < self.produced:
            raise BudgetExceeded(
                f"{self.path}: expanded past {self.cap} bytes, over {self.limits.max_archive_ratio} "
                f"times its size",
                hint="This is the shape of padding or a decompression bomb.",
                padded=True,
            )
        if self.produced > self.limits.max_uncompressed_bytes:
            raise BudgetExceeded(
                f"{self.path}: archive expands past the {self.limits.max_uncompressed_bytes}-byte budget",
                hint="This is the shape of a decompression bomb.",
            )
        return chunk


class _BytesReader:
    """Minimal seekable wrapper, so format sniffing needs no temporary file."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def getvalue(self) -> bytes:
        return self._data

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._data[self._pos :]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        else:
            self._pos = len(self._data) + offset
        self._pos = max(0, min(self._pos, len(self._data)))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return True


__all__ = ["READ_CHUNK", "ZSTD_MAGIC", "BudgetExceeded"]
