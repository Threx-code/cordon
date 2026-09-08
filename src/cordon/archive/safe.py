"""Hardened archive extraction.

This module is the only code permitted to expand an archive, and it exists
because archive formats were designed for convenience rather than for hostile
input. Every protection here maps to a documented attack:

**Decompression bombs.** A few kilobytes expanding to petabytes. The defence is
a compression-ratio ceiling checked *incrementally during the stream*, not
afterwards -- checking afterwards means the bomb has already gone off. The
declared size in a header is never trusted, because the attacker wrote it.

**Path traversal.** A member named ``../../etc/cron.d/x`` writing outside the
destination. Every member path is resolved and must land inside the destination
root; absolute paths and traversal segments are rejected outright.

**Link attacks.** A symlink member pointing at ``~/.ssh/id_rsa``, so the scanner
reads it and prints it as evidence. Links are never materialised at all.

**Nesting.** An archive inside an archive, repeated. Beyond a small depth the
nesting is itself the signal.

Nothing here is silent. A rejected archive produces a finding, because an
archive that was refused and an archive that was clean must never look alike.
"""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from cordon.core.errors import ArchiveError
from cordon.core.limits import DEFAULT_LIMITS, Limits

if TYPE_CHECKING:
    from collections.abc import Iterator

ARCHIVE_SUFFIXES = (
    ".zip", ".whl", ".jar", ".war", ".ear", ".nupkg", ".aar", ".apk", ".egg",
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".crate",
    ".gem",
)

READ_CHUNK = 65536


class Rejection:
    """Why a member or an archive was refused. Each becomes a finding."""

    RATIO = "compression_ratio"
    ENTRIES = "entry_count"
    SIZE = "uncompressed_size"
    DEPTH = "nesting_depth"
    TRAVERSAL = "path_traversal"
    ABSOLUTE = "absolute_path"
    LINK = "link_member"
    SPECIAL = "special_file"
    UNREADABLE = "unreadable"
    NAME = "unsafe_name"


@dataclass(frozen=True, slots=True)
class RejectedMember:
    name: str
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedMember:
    """One archive member, in memory.

    Members are returned as bytes rather than written to disk. Nothing that was
    never written can be executed, followed, or left behind by a crash, which
    removes an entire class of problem rather than mitigating it.
    """

    name: str
    data: bytes
    compressed_size: int
    uncompressed_size: int


@dataclass
class ExtractionResult:
    members: list[ExtractedMember] = field(default_factory=list)
    rejected: list[RejectedMember] = field(default_factory=list)
    total_uncompressed: int = 0
    total_compressed: int = 0
    truncated: bool = False
    """True when a limit stopped extraction early. The caller must report it:
    a partial extraction that looks complete is a false negative."""

    @property
    def ratio(self) -> float:
        if self.total_compressed <= 0:
            return 0.0
        return self.total_uncompressed / self.total_compressed


def is_archive(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def safe_member_name(name: str) -> str | None:
    """Normalise a member name, or return None if it is unsafe.

    Rejected: absolute paths, drive letters, any traversal segment, and names
    containing NUL. The check is on the *normalised* form, so ``a/../../b`` is
    caught even though no single component looks wrong.
    """
    if not name or "\x00" in name:
        return None

    cleaned = name.replace("\\", "/")

    if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
        return None

    parts = PurePosixPath(cleaned).parts
    if any(part == ".." for part in parts):
        return None

    normalised = PurePosixPath(*(p for p in parts if p not in {".", ""}))
    text = str(normalised)
    return None if text in {".", ""} else text


def extract(
    data: bytes,
    *,
    path: str,
    limits: Limits = DEFAULT_LIMITS,
    depth: int = 0,
) -> ExtractionResult:
    """Expand an archive held in memory, enforcing every limit.

    Raises :class:`ArchiveError` only when the archive as a whole is
    unprocessable. Individual bad members are recorded in ``rejected`` so one
    hostile entry does not discard an otherwise legitimate package.
    """
    result = ExtractionResult()

    if depth > limits.max_archive_depth:
        raise ArchiveError(
            f"{path}: archive nesting exceeds {limits.max_archive_depth} levels",
            hint=(
                "Nothing legitimate nests this deep. The nesting is itself the "
                "signal, which is why this is refused rather than skipped."
            ),
        )

    if zipfile.is_zipfile(_BytesReader(data)):
        _extract_zip(data, path, limits, result)
    else:
        _extract_tar(data, path, limits, result)

    return result


class _BytesReader:
    """Minimal seekable wrapper, so format sniffing needs no temporary file."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

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


def _extract_zip(
    data: bytes, path: str, limits: Limits, result: ExtractionResult
) -> None:
    try:
        archive = zipfile.ZipFile(_BytesReader(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveError(f"{path}: not a readable zip archive: {exc}") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_entries:
            raise ArchiveError(
                f"{path}: archive declares {len(infos)} entries, over the "
                f"{limits.max_archive_entries} limit"
            )

        for info in infos:
            if info.is_dir():
                continue

            safe = safe_member_name(info.filename)
            if safe is None:
                result.rejected.append(
                    RejectedMember(
                        info.filename,
                        Rejection.TRAVERSAL,
                        "member name escapes the destination directory",
                    )
                )
                continue

            # Zip stores unix mode in the top 16 bits of external_attr. A
            # symlink member is never materialised: following one is how an
            # extractor is made to write, or read, outside its own directory.
            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) == 0o120000:
                result.rejected.append(
                    RejectedMember(
                        safe, Rejection.LINK, "symbolic-link members are never extracted"
                    )
                )
                continue

            if _would_exceed(result, info.compress_size, info.file_size, limits, safe):
                continue

            try:
                with archive.open(info) as handle:
                    payload = _read_bounded(handle, limits, info.compress_size, result, safe)
            except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError) as exc:
                result.rejected.append(
                    RejectedMember(safe, Rejection.UNREADABLE, str(exc))
                )
                continue

            if payload is None:
                continue

            result.members.append(
                ExtractedMember(
                    name=safe,
                    data=payload,
                    compressed_size=info.compress_size,
                    uncompressed_size=len(payload),
                )
            )


def _extract_tar(
    data: bytes, path: str, limits: Limits, result: ExtractionResult
) -> None:
    try:
        # Opened outside a `with` so the failure can be converted into a typed
        # ArchiveError; the handle is closed by the `with` immediately below.
        archive = tarfile.open(  # noqa: SIM115
            fileobj=_BytesReader(data),  # type: ignore[arg-type]
            mode="r:*",
        )
    except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
        # EOFError specifically: a truncated gzip stream raises it rather than
        # OSError, and an uncaught exception here crashes the entire scan on a
        # single malformed archive.
        raise ArchiveError(f"{path}: not a readable archive: {exc}") from exc

    with archive:
        count = 0
        try:
            members = list(archive)
        except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
            raise ArchiveError(f"{path}: archive index is corrupt: {exc}") from exc

        for member in members:
            count += 1
            if count > limits.max_archive_entries:
                result.truncated = True
                result.rejected.append(
                    RejectedMember(
                        member.name,
                        Rejection.ENTRIES,
                        f"stopped after {limits.max_archive_entries} entries",
                    )
                )
                break

            if member.isdir():
                continue

            # Anything that is not a plain file: links, devices, FIFOs. A
            # device node or FIFO can block a reader indefinitely, and a link
            # can redirect it outside the archive entirely.
            if member.issym() or member.islnk():
                result.rejected.append(
                    RejectedMember(
                        member.name, Rejection.LINK, "link members are never extracted"
                    )
                )
                continue
            if not member.isfile():
                result.rejected.append(
                    RejectedMember(
                        member.name, Rejection.SPECIAL, "not a regular file"
                    )
                )
                continue

            safe = safe_member_name(member.name)
            if safe is None:
                result.rejected.append(
                    RejectedMember(
                        member.name,
                        Rejection.TRAVERSAL,
                        "member name escapes the destination directory",
                    )
                )
                continue

            # The declared size is the attacker's number. It is used only to
            # reject early; the real bound is enforced while reading.
            if _would_exceed(result, 0, member.size, limits, safe):
                continue

            try:
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                payload = _read_bounded(handle, limits, 0, result, safe)
            except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
                result.rejected.append(
                    RejectedMember(safe, Rejection.UNREADABLE, str(exc))
                )
                continue

            if payload is None:
                continue

            result.members.append(
                ExtractedMember(
                    name=safe,
                    data=payload,
                    compressed_size=0,
                    uncompressed_size=len(payload),
                )
            )

    result.total_compressed = max(result.total_compressed, len(data))
    _check_ratio(result, limits, path)


def _would_exceed(
    result: ExtractionResult,
    compressed: int,
    declared: int,
    limits: Limits,
    name: str,
) -> bool:
    """Reject a member before reading it, where the declared size allows."""
    if declared > limits.max_file_bytes:
        result.rejected.append(
            RejectedMember(
                name,
                Rejection.SIZE,
                f"declared {declared} bytes, over the {limits.max_file_bytes} limit",
            )
        )
        return True
    if result.total_uncompressed + declared > limits.max_uncompressed_bytes:
        result.truncated = True
        result.rejected.append(
            RejectedMember(
                name,
                Rejection.SIZE,
                "archive exceeds the total uncompressed budget",
            )
        )
        return True
    return False


def _read_bounded(
    handle,
    limits: Limits,
    compressed_size: int,
    result: ExtractionResult,
    name: str,
) -> bytes | None:
    """Read a member, enforcing the ratio ceiling as it streams.

    This is the control that actually stops a decompression bomb. Checking the
    ratio after extraction means the memory has already been allocated; the
    ceiling has to be enforced while the bytes are arriving, so the read aborts
    partway through rather than completing successfully into an out-of-memory
    failure.
    """
    chunks: list[bytes] = []
    read_total = 0

    while True:
        chunk = handle.read(READ_CHUNK)
        if not chunk:
            break
        read_total += len(chunk)

        if read_total > limits.max_file_bytes:
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.SIZE,
                    f"expanded past the {limits.max_file_bytes}-byte member limit",
                )
            )
            return None

        if compressed_size > 0:
            ratio = read_total / compressed_size
            if ratio > limits.max_archive_ratio:
                result.rejected.append(
                    RejectedMember(
                        name,
                        Rejection.RATIO,
                        f"expanded {ratio:.0f}:1, over the "
                        f"{limits.max_archive_ratio}:1 ceiling",
                    )
                )
                return None

        if result.total_uncompressed + read_total > limits.max_uncompressed_bytes:
            result.truncated = True
            result.rejected.append(
                RejectedMember(
                    name, Rejection.SIZE, "archive exceeds the total uncompressed budget"
                )
            )
            return None

        chunks.append(chunk)

    result.total_uncompressed += read_total
    result.total_compressed += compressed_size
    return b"".join(chunks)


def _check_ratio(result: ExtractionResult, limits: Limits, path: str) -> None:
    """Whole-archive ratio check, for formats with no per-member sizes.

    A compressed tar reports no per-member compressed size, so the per-member
    ceiling cannot apply. The aggregate ratio is checked once the whole archive
    has streamed, which still catches a bomb before anything is scanned.
    """
    if result.total_compressed <= 0:
        return
    if result.ratio > limits.max_archive_ratio:
        raise ArchiveError(
            f"{path}: archive expands {result.ratio:.0f}:1, over the "
            f"{limits.max_archive_ratio}:1 ceiling",
            hint="This is the shape of a decompression bomb.",
        )


def walk_archive(
    data: bytes,
    *,
    path: str,
    limits: Limits = DEFAULT_LIMITS,
    depth: int = 0,
) -> Iterator[tuple[str, bytes]]:
    """Yield every member, descending into nested archives.

    Nested archives are expanded up to the depth limit and their members are
    yielded with a path that records the nesting, so a finding inside a wheel
    inside a tarball still says exactly where it lives.
    """
    result = extract(data, path=path, limits=limits, depth=depth)

    for member in result.members:
        member_path = f"{path}!{member.name}"

        if is_archive(member.name) and depth < limits.max_archive_depth:
            try:
                yield from walk_archive(
                    member.data, path=member_path, limits=limits, depth=depth + 1
                )
                continue
            except ArchiveError:
                # A nested archive that will not open is still worth scanning as
                # bytes: a payload does not stop being a payload because its
                # container is malformed.
                pass

        yield member_path, member.data


__all__ = [
    "ARCHIVE_SUFFIXES",
    "ExtractedMember",
    "ExtractionResult",
    "RejectedMember",
    "Rejection",
    "extract",
    "is_archive",
    "safe_member_name",
    "walk_archive",
]
