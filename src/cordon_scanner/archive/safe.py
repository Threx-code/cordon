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

import struct
import tarfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, cast

from cordon_scanner.core.errors import ArchiveError
from cordon_scanner.core.limits import DEFAULT_LIMITS, Limits

if TYPE_CHECKING:
    from collections.abc import Iterator

ARCHIVE_SUFFIXES = (
    ".zip",
    ".whl",
    ".jar",
    ".war",
    ".ear",
    ".nupkg",
    # VS Code extensions: a zip whose `extension/` holds code that runs in the editor.
    ".vsix",
    ".aar",
    ".apk",
    ".egg",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".crate",
    ".gem",
    # conda's current format: a zip of `info-*.tar.zst` and `pkg-*.tar.zst`. 85.5% of conda-forge
    # noarch packages publish their newest build only this way (review 98, REC-8).
    ".conda",
    ".tar.zst",
    ".tzst",
)

READ_CHUNK = 65536
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_COMPRESSED_MAGIC = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", ZSTD_MAGIC)
"""gzip, bzip2, xz and zstd: the streams a tarball is compressed in."""


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
    POLYGLOT = "polyglot_archive"
    HIDDEN = "hidden_zip_member"
    PADDED = "padded_expansion"
    """A budget reached while the archive expanded past `max_archive_ratio`: what follows the
    padding was not read, and padding is how a payload is put out of a scanner's reach."""


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
    links: list[str] = field(default_factory=list)
    """Link members whose target is another member of the same archive: not followed, and not a
    coverage gap, because the content they name is read as that member (`link_stays_inside`)."""
    total_uncompressed: int = 0
    total_compressed: int = 0
    truncated: bool = False
    """True when a limit stopped extraction early. The caller must report it:
    a partial extraction that looks complete is a false negative."""
    expansion_cap: int = 0
    """How far this archive may expand: `max(max_member_bytes, its size x max_archive_ratio)`,
    from the WHOLE archive's size, known before a byte is decompressed. Past it the read stops and
    what was read is kept (`ArchiveReader.expansion_cap`)."""

    @property
    def ratio(self) -> float:
        if self.total_compressed <= 0:
            return 0.0
        return self.total_uncompressed / self.total_compressed


class ArchiveReader:
    """Reads archives entirely in memory, refusing hostile ones.

    Nothing is ever written to disk. An archive is untrusted input, and the
    classic attacks against extraction -- a member named `../../etc/passwd`, an
    absolute path, a symlink pointing out of the tree -- all depend on a write
    actually happening. Not writing removes the entire class rather than
    defending against each instance of it.

    What remains after that is resource exhaustion, which memory extraction does
    not solve: a few hundred kilobytes can expand to gigabytes. Those bounds --
    entry count, per-entry size, total size, compression ratio, nesting depth --
    are enforced during reading rather than after, because a bound checked after
    decompression has already been exceeded by the time it is consulted.

    Every refusal is recorded on the result. A member that is skipped and a
    member that contains nothing must never look alike.
    """

    @staticmethod
    def is_archive(path: str) -> bool:
        lowered = path.lower()
        return any(lowered.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)

    @staticmethod
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

    @staticmethod
    def link_stays_inside(member: str, target: str, *, hard: bool = False) -> bool:
        """Whether a link member points at another path inside the same archive.

        Such a link is never followed, and it carries no content of its own: what it names is a
        member read in its own right. Refused, it marked the scan incomplete -- 470 of 3,000 nix
        repositories and 504 of 3,000 bazel archives were scored "not fully examined" for symlinks
        such as `include/alsa -> ../alsa` (review 98). A target that is absolute or climbs out of
        the archive stays refused: that link is how an extractor is made to read or write outside.
        """
        if not target or "\x00" in target:
            return False
        cleaned = target.replace("\\", "/")
        if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
            return False
        # A hard link names an archive path; a symbolic link is relative to its own directory.
        base = () if hard else PurePosixPath(member.replace("\\", "/")).parent.parts
        depth: list[str] = [p for p in base if p not in {".", ""}]
        for part in PurePosixPath(cleaned).parts:
            if part in {".", ""}:
                continue
            if part == "..":
                if not depth:
                    return False
                depth.pop()
            else:
                depth.append(part)
        return bool(depth)

    @staticmethod
    def extract(
        data: bytes,
        *,
        path: str,
        limits: Limits = DEFAULT_LIMITS,
        depth: int = 0,
        deadline: float | None = None,
    ) -> ExtractionResult:
        """Expand an archive held in memory, enforcing every limit.

        Raises :class:`ArchiveError` only when the archive as a whole is
        unprocessable. Individual bad members are recorded in ``rejected`` so one
        hostile entry does not discard an otherwise legitimate package.
        """
        result = ExtractionResult(expansion_cap=ArchiveReader.expansion_cap(len(data), limits))

        if depth > limits.max_archive_depth:
            raise ArchiveError(
                f"{path}: archive nesting exceeds {limits.max_archive_depth} levels",
                hint=(
                    "Nothing legitimate nests this deep. The nesting is itself the "
                    "signal, which is why this is refused rather than skipped."
                ),
            )

        # The format is decided by the bytes at offset zero, which is how npm, pip and gem
        # decide it. `is_zipfile` looks for a zip directory at the END and tolerates anything
        # in front of it, so a tarball with a small zip appended was read as the zip alone --
        # while every package manager installed the tar, unexamined. A file that begins as one
        # format and ends as another is read as both, and reported.
        head = bytes(data[:512])
        zip_at_start = head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
        tar_at_start = head.startswith(_COMPRESSED_MAGIC) or head[257:262] == b"ustar"
        ends_as_zip = not zip_at_start and zipfile.is_zipfile(_BytesReader(data))
        if zip_at_start:
            ArchiveReader._extract_zip(data, path, limits, result, deadline)
        elif tar_at_start and ends_as_zip:
            result.rejected.append(
                RejectedMember(
                    path,
                    Rejection.POLYGLOT,
                    "begins as a tar or compressed stream and ends as a zip",
                )
            )
            ArchiveReader._extract_tar(data, path, limits, result, deadline)
            appended = ExtractionResult()
            ArchiveReader._extract_zip(data, path, limits, appended, deadline)
            for member in appended.members:
                result.members.append(replace(member, name=f"zip-appended/{member.name}"))
            result.rejected.extend(appended.rejected)
        elif ends_as_zip:
            # A zip with a stub in front (a self-extracting executable): the zip is what it holds.
            ArchiveReader._extract_zip(data, path, limits, result, deadline)
        else:
            ArchiveReader._extract_tar(data, path, limits, result, deadline)

        return result

    @staticmethod
    def _local_only_members(
        data: bytes,
        infos: list[zipfile.ZipInfo],
        path: str,
        limits: Limits,
        result: ExtractionResult,
    ) -> None:
        """Members a streaming unzip would install that the central directory does not list.

        `zipfile` reads the central directory at the end. Extractors that stream local headers from
        the front - several JavaScript unzip libraries, some Java tooling - read the other view, and
        a zip whose two views differ shows one file set to the scanner and another to the installer
        (`package.md` PK-07). The local headers are walked from offset 0; one the directory does not
        point at is refused as a finding of its own and, where it can be read, also extracted under
        `zip-local/` so the detectors see what it carries.

        The walk stops at a header whose size it cannot know (a data descriptor) or that does not
        parse: what was read before that is still compared, and nothing after is guessed at."""
        listed = {info.header_offset for info in infos}
        offset, header = 0, struct.Struct("<4s5H3L2H")
        seen = 0
        while offset + header.size <= len(data) and seen <= limits.max_archive_entries:
            fields = header.unpack_from(data, offset)
            if fields[0] != b"PK\x03\x04":
                break
            flags, method, compressed, name_len, extra_len = (
                fields[2],
                fields[3],
                fields[7],
                fields[9],
                fields[10],
            )
            start = offset + header.size + name_len + extra_len
            if flags & 0x08 or compressed == 0xFFFFFFFF or start + compressed > len(data):
                break
            seen += 1
            if offset not in listed:
                raw_name = bytes(data[offset + header.size : offset + header.size + name_len])
                name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", "replace")
                safe = ArchiveReader.safe_member_name(name) or "unnamed"
                result.rejected.append(
                    RejectedMember(
                        name,
                        Rejection.HIDDEN,
                        "a local header the central directory does not list: a streaming extractor "
                        "installs it, a directory-reading one never sees it",
                    )
                )
                body = bytes(data[start : start + compressed])
                payload: bytes | None = None
                try:
                    if method == 0:
                        payload = body[: ArchiveReader.member_limit(limits)]
                    elif method == 8:
                        inflater = zlib.decompressobj(-15)
                        payload = inflater.decompress(
                            body,
                            min(ArchiveReader.member_limit(limits), limits.max_uncompressed_bytes),
                        )
                except zlib.error:
                    payload = None
                if payload is not None and not ArchiveReader._would_exceed(
                    result, compressed, len(payload), limits, safe
                ):
                    result.members.append(
                        ExtractedMember(
                            name=f"zip-local/{safe}",
                            data=payload,
                            compressed_size=compressed,
                            uncompressed_size=len(payload),
                        )
                    )
            offset = start + compressed

    @staticmethod
    def _extract_zip(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None = None,
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
            ArchiveReader._local_only_members(data, infos, path, limits, result)

            for info in infos:
                if deadline is not None and time.monotonic() > deadline:
                    raise ArchiveError(f"{path}: the time budget ran out while reading the archive")
                if info.is_dir():
                    continue

                safe = ArchiveReader.safe_member_name(info.filename)
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
                    # A zip symlink's data is its target path: a few bytes, read only to place it.
                    target = ""
                    if info.file_size <= 4096:
                        try:
                            target = archive.read(info).decode("utf-8", "replace")
                        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
                            target = ""
                    if ArchiveReader.link_stays_inside(safe, target):
                        result.links.append(safe)
                        continue
                    result.rejected.append(
                        RejectedMember(
                            safe,
                            Rejection.LINK,
                            f"symbolic-link members are never extracted (-> {target[:200]})",
                        )
                    )
                    continue

                if ArchiveReader._would_exceed(
                    result, info.compress_size, info.file_size, limits, safe
                ):
                    continue

                try:
                    with archive.open(info) as handle:
                        payload = ArchiveReader._read_bounded(
                            handle, limits, info.compress_size, result, safe
                        )
                except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError) as exc:
                    result.rejected.append(RejectedMember(safe, Rejection.UNREADABLE, str(exc)))
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

        # The tar path called this and the zip path did not, so the compression
        # ratio ceiling -- the control the module documents first -- applied to
        # exactly one of the two archive formats.
        result.total_compressed = max(result.total_compressed, len(data))

    @staticmethod
    def _extract_tar(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None = None,
    ) -> None:
        try:
            # Decompressed HERE, and read by tarfile as a plain sequential stream (`r|`) through
            # `_BudgetedStream`, which sees every decompressed byte - including the data of members
            # this module refuses and tarfile skips over.
            #
            # `mode="r:*"` let tarfile decompress out of sight. Two consequences, both measured:
            # the whole-archive ratio could only be checked after every member was already in
            # memory, so a 2.15 MB tar.gz of zeros held 2.2 GB and OOM-killed a 1 GB scanner before
            # the 1000:1 ratio was ever compared (`package.md` PK-02); and a member refused on its
            # DECLARED size was still decompressed through to reach the next header, with the
            # deadline checked only between members, so a few-KB bz2 declaring 100 GB burned
            # minutes of CPU (PK-03). Now the ratio, a total budget and the deadline are enforced
            # on the bytes as they are produced.
            stream = _BudgetedStream.open(
                data, limits=limits, deadline=deadline, path=path, cap=result.expansion_cap
            )
            archive = tarfile.open(fileobj=stream, mode="r|")  # type: ignore[call-overload]  # noqa: SIM115
        except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
            # EOFError specifically: a truncated gzip stream raises it rather than
            # OSError, and an uncaught exception here crashes the entire scan on a
            # single malformed archive.
            raise ArchiveError(f"{path}: not a readable archive: {exc}") from exc

        with archive:
            count = 0
            # Iterated lazily. `list(archive)` walked every header first,
            # allocating a `TarInfo` per entry and decompressing the whole
            # stream to do it, before `max_archive_entries`,
            # `max_uncompressed_bytes` or the ratio ceiling had been consulted
            # once. An 18 MB tar.gz of three million empty entries -- tar
            # headers compress about 80:1, so that is a small file to ship --
            # took 45 seconds and 1.5 GB of resident memory before the
            # 50,000-entry limit bound. A 180 MB archive reaches roughly 15 GB
            # and OOM-kills the runner, taking co-tenant jobs with it.
            #
            # The limit has to bind before the allocation, which means checking
            # it inside the loop that produces the allocation.
            try:
                for member in archive:
                    if deadline is not None and time.monotonic() > deadline:
                        # Checked here rather than around the whole extraction. A
                        # three-million-entry tar spends all its time inside this
                        # loop and yields nothing until it finishes, so a budget
                        # applied outside never bound at all.
                        result.truncated = True
                        result.rejected.append(
                            RejectedMember(member.name, Rejection.ENTRIES, "scan budget exhausted")
                        )
                        break

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
                        if ArchiveReader.link_stays_inside(
                            member.name, member.linkname, hard=member.islnk()
                        ):
                            result.links.append(member.name)
                            continue
                        result.rejected.append(
                            RejectedMember(
                                member.name,
                                Rejection.LINK,
                                f"link members are never extracted (-> {member.linkname[:200]})",
                            )
                        )
                        continue
                    if not member.isfile():
                        result.rejected.append(
                            RejectedMember(member.name, Rejection.SPECIAL, "not a regular file")
                        )
                        continue

                    safe = ArchiveReader.safe_member_name(member.name)
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
                    if ArchiveReader._would_exceed(result, 0, member.size, limits, safe):
                        continue

                    try:
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        payload = ArchiveReader._read_bounded(handle, limits, 0, result, safe)
                    except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
                        result.rejected.append(RejectedMember(safe, Rejection.UNREADABLE, str(exc)))
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

            except BudgetExceeded as exc:
                # Stopped where the budget ran out. What was read is kept and scanned; past an
                # expansion this lopsided, what was not read is behind padding.
                result.truncated = True
                shape = Rejection.PADDED if exc.padded else Rejection.SIZE
                result.rejected.append(RejectedMember(path, shape, str(exc)))
            except ArchiveError as exc:
                result.truncated = True
                result.rejected.append(RejectedMember(path, Rejection.ENTRIES, str(exc)))
            except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
                # A corrupt index surfaces mid-iteration. The members before it are kept: npm and
                # pip extract a tarball as a stream, and install every file they read before the
                # damage. Refusing the whole archive passed `legoa-repodb` 66.0.0 and its kind --
                # internal names republished on npm, the dependency-confusion shape -- unread.
                if not result.members:
                    raise ArchiveError(f"{path}: archive index is corrupt: {exc}") from exc
                result.truncated = True
                result.rejected.append(
                    RejectedMember(
                        path,
                        Rejection.UNREADABLE,
                        f"damaged after {len(result.members)} member(s): {exc}",
                    )
                )

        result.total_compressed = max(result.total_compressed, len(data))

    @staticmethod
    def member_limit(limits: Limits) -> int:
        """The largest member extracted. Up to `max_member_bytes`, not `max_file_bytes`: a member
        over the latter is held whole so its windows can be read (`core/windows.py`), and every
        rule reads its first `max_file_bytes` (`FileContent.from_bytes`). The ratio and total
        budgets still bound what an archive can make this reader allocate."""
        return max(limits.max_file_bytes, limits.max_member_bytes)

    @staticmethod
    def expansion_cap(compressed: int, limits: Limits) -> int:
        """How far an archive of `compressed` bytes may expand before the read stops.

        An archive is held in memory once expanded, so a lopsided one must stop early: 600 KB of
        tar.gz held 600 MB of zeros without this (PK-02). It is judged against the whole archive's
        size, not the bytes consumed so far: that running ratio spikes at the start of honest
        archives and refused `ricklib` (23:1 overall), `compliance-checker` (120:1) and a Gradle
        repository (21:1) as bombs, unread (review 98). Every archive may reach
        `max_member_bytes`; past that, `max_archive_ratio` times its size."""
        return max(limits.max_member_bytes, compressed * limits.max_archive_ratio)

    @staticmethod
    def _would_exceed(
        result: ExtractionResult,
        compressed: int,
        declared: int,
        limits: Limits,
        name: str,
    ) -> bool:
        """Reject a member before reading it, where the declared size allows."""
        if declared > ArchiveReader.member_limit(limits):
            # A zip states each member's compressed size: sixty megabytes declared from sixty
            # kilobytes stored is padding, refused on its face before a byte is inflated.
            padded = compressed > 0 and declared > compressed * limits.max_archive_ratio
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.PADDED if padded else Rejection.SIZE,
                    f"declared {declared} bytes, over the {ArchiveReader.member_limit(limits)} limit",
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

    @staticmethod
    def _read_bounded(
        handle: Any,
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

            if read_total > ArchiveReader.member_limit(limits):
                result.rejected.append(
                    RejectedMember(
                        name,
                        Rejection.SIZE,
                        f"expanded past the {ArchiveReader.member_limit(limits)}-byte member limit",
                    )
                )
                return None

            if 0 < result.expansion_cap < result.total_uncompressed + read_total:
                result.truncated = True
                result.rejected.append(
                    RejectedMember(
                        name,
                        Rejection.PADDED,
                        f"the archive expanded past {result.expansion_cap} bytes, over "
                        f"{limits.max_archive_ratio} times its size",
                    )
                )
                return None

            if result.total_uncompressed + read_total > limits.max_uncompressed_bytes:
                result.truncated = True
                result.rejected.append(
                    RejectedMember(
                        name,
                        Rejection.SIZE,
                        "archive exceeds the total uncompressed budget",
                    )
                )
                return None

            chunks.append(chunk)

        result.total_uncompressed += read_total
        result.total_compressed += compressed_size
        return b"".join(chunks)

    @staticmethod
    def walk_archive(
        data: bytes,
        *,
        path: str,
        limits: Limits = DEFAULT_LIMITS,
        depth: int = 0,
        rejected: list[tuple[str, str, str]] | None = None,
        deadline: float | None = None,
    ) -> Iterator[tuple[str, bytes]]:
        """Yield every member, descending into nested archives.

        Nested archives are expanded up to the depth limit and their members are
        yielded with a path that records the nesting, so a finding inside a wheel
        inside a tarball still says exactly where it lives.

        Rejections are reported through `rejected`, which the caller must pass
        if it wants them. This module's own docstring says "a rejected archive
        produces a finding, because an archive that was refused and an archive
        that was clean must never look alike" -- and `extract` recorded every
        refusal faithfully while this function threw the list away. A package
        shipping a payload member that was oversize, a symlink, a traversal name
        or the 50,001st entry was scanned, said nothing about that member, and
        returned complete.
        """
        result = ArchiveReader.extract(
            data, path=path, limits=limits, depth=depth, deadline=deadline
        )

        if rejected is not None:
            for refused in result.rejected:
                rejected.append((f"{path}!{refused.name}", refused.reason, refused.detail))
            if result.truncated:
                rejected.append((path, Rejection.ENTRIES, "extraction stopped early at a limit"))

        for member in result.members:
            member_path = f"{path}!{member.name}"

            too_deep = ArchiveReader.is_archive(member.name) and depth >= limits.max_archive_depth
            if too_deep and rejected is not None:
                # Past the depth limit. Reported, then yielded as opaque bytes.
                #
                # It used to fall straight through to the yield, so a nested
                # archive one layer past the limit was handed to the detectors
                # as compressed bytes, its contents never examined, and nothing
                # appended to `rejected`. The limits module states the governing
                # invariant -- "reaching a limit produces an OPERATIONAL
                # finding, it is never a silent skip" -- and the threat model
                # says of nesting specifically that "a nested archive beyond the
                # limit is a finding, not a silent skip".
                #
                # Measured: a payload survived three layers of wrapping and
                # disappeared at the fourth, with the scan still reporting
                # complete. One extra layer of zip hid it, and the output was
                # identical to a clean archive.
                rejected.append(
                    (
                        member_path,
                        Rejection.DEPTH,
                        f"nested deeper than {limits.max_archive_depth} levels; "
                        f"its contents were not examined",
                    )
                )

            if ArchiveReader.is_archive(member.name) and depth < limits.max_archive_depth:
                try:
                    yield from ArchiveReader.walk_archive(
                        member.data,
                        path=member_path,
                        limits=limits,
                        depth=depth + 1,
                        rejected=rejected,
                        deadline=deadline,
                    )
                    continue
                except ArchiveError as exc:
                    # A nested archive that will not open is still worth scanning as
                    # bytes: a payload does not stop being a payload because its
                    # container is malformed. zstd is also reported unread: the core's
                    # decoder refuses dictionaries, which libzstd and so the installer read,
                    # so a stream it fails on may hold a payload it never saw.
                    if member.data[:4] == ZSTD_MAGIC and rejected is not None:
                        rejected.append((member_path, Rejection.UNREADABLE, str(exc)))

            yield member_path, member.data


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
            inner: Any = gzip.GzipFile(fileobj=cast(Any, raw), mode="rb")
        elif data[:3] == b"BZh":
            inner = bz2.BZ2File(cast(Any, raw), mode="rb")
        elif data[:6] == b"\xfd7zXZ\x00":
            inner = lzma.LZMAFile(cast(Any, raw), mode="rb")  # noqa: SIM115
        elif data[:4] == ZSTD_MAGIC:
            # Past the budget by a read's worth, so `read` reports the budget, not the decoder.
            inner = _BudgetedStream._zstd(raw, limits.max_uncompressed_bytes + READ_CHUNK * 16)
        else:
            return cls(raw, None, limits, deadline, path, cap)
        return cls(inner, raw, limits, deadline, path, cap)

    @staticmethod
    def _zstd(raw: _BytesReader, limit: int) -> Any:
        """A zstd decompressing reader: the standard library's (3.14), `zstandard` where installed,
        else the core's own decoder (`intel/zstd`), so a `.conda` package is read with no
        third-party dependency (CONSTRAINT C1). The last fails past `limit` bytes."""
        try:
            from compression import zstd  # type: ignore[import-not-found]

            return zstd.ZstdFile(raw, mode="rb")
        except ImportError:
            pass
        try:
            import zstandard  # type: ignore[import-not-found]

            return zstandard.ZstdDecompressor().stream_reader(raw)
        except ImportError:
            from cordon_scanner.intel.zstd import Zstd

            return Zstd.Reader(raw.getvalue(), limit)

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


__all__ = [
    "ARCHIVE_SUFFIXES",
    "ArchiveReader",
    "ExtractedMember",
    "ExtractionResult",
    "RejectedMember",
    "Rejection",
]
