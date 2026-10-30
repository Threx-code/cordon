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

import hashlib
import struct
import tarfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.files.spill import Spill, SpilledBytes
from cordon_scanner.foundation.limits import DEFAULT_LIMITS, Limits
from cordon_scanner.sources.base import RejectedMember, Rejection
from cordon_scanner.sources.budget import (
    READ_CHUNK,
    ZSTD_MAGIC,
    BudgetExceeded,
    _BudgetedStream,
    _BytesReader,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

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

_COMPRESSED_MAGIC = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", ZSTD_MAGIC)
"""gzip, bzip2, xz and zstd: the streams a tarball is compressed in."""


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
class NestedWalk:
    """What one `walk_archive` has opened, and what it met past the depth limit.

    A package that ships its own earlier `npm pack` tarballs carries each one at several depths;
    the copy past the limit holds the same bytes as one opened higher up, so its contents were
    examined. Only an archive no copy of which was opened is reported as unexamined."""

    opened: set[bytes] = field(default_factory=set)
    """sha256 of every nested archive opened and walked."""
    too_deep: list[tuple[bytes, tuple[str, str, str]]] = field(default_factory=list)
    """(sha256, rejection) for every nested archive met past the limit."""


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
    def safe_member_name(name: str, *, collapse: bool = False) -> str | None:
        """Normalise a member name, or return None if it is unsafe.

        Rejected: absolute paths, drive letters, any traversal segment, and names
        containing NUL. The check is on the *normalised* form, so ``a/../../b`` is
        caught even though no single component looks wrong.

        With `collapse`, a `..` that stays inside the archive is resolved instead
        (`pkg-0.3.1/../README.md` is `README.md`, which some sdist builders write);
        one that climbs above the archive's root is still refused. Callers pass it
        only while no link member has come before this one: an extractor writes
        `a/../x` through `a` once `a` is a symlink, so then the name is refused.
        """
        if not name or "\x00" in name:
            return None

        cleaned = name.replace("\\", "/")

        if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
            return None

        parts = PurePosixPath(cleaned).parts
        if any(part == ".." for part in parts):
            if not collapse:
                return None
            kept: list[str] = []
            for part in parts:
                if part == "..":
                    if not kept:
                        return None
                    kept.pop()
                elif part not in {".", ""}:
                    kept.append(part)
            parts = tuple(kept)

        normalised = PurePosixPath(*(p for p in parts if p not in {".", ""}))
        text = str(normalised)
        return None if text in {".", ""} else text

    @staticmethod
    def _links_seen(result: ExtractionResult) -> bool:
        """Whether a link member has been met yet, kept or refused (`safe_member_name`)."""
        return bool(result.links) or any(r.reason == Rejection.LINK for r in result.rejected)

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
            # A nameless entry or an empty directory installs no file, whichever view is read: an
            # APK's leading stub, a directory entry whose offset a writer recorded shifted.
            name_end = offset + header.size + name_len
            empty = not name_len or (compressed == 0 and data[name_end - 1 : name_end] == b"/")
            if offset not in listed and not empty:
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
                payload = ArchiveReader._hidden_payload(
                    data[start : start + compressed], method, name, limits, result
                )
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
    def _hidden_payload(
        body: bytes, method: int, name: str, limits: Limits, result: ExtractionResult
    ) -> bytes | None:
        """A hidden member's bytes, read from its local header within the member limit. Each way
        one goes unread is a refusal of its own, so the scan says so: the hidden refusal alone
        means it was read (as `zip-local/`), as a link's means nothing was there to read."""
        limit = min(ArchiveReader.member_limit(limits), limits.max_uncompressed_bytes)
        payload: bytes | None = None
        cut = False
        try:
            if method == 0:
                payload, cut = bytes(body[:limit]), len(body) > limit
            elif method == 8:
                inflater = zlib.decompressobj(-15)
                payload = inflater.decompress(bytes(body), limit)
                cut = bool(inflater.unconsumed_tail)
        except zlib.error:
            payload = None
        if payload is None:
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.UNREADABLE,
                    f"a hidden member (method {method}) could not be read",
                )
            )
        elif cut:
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.SIZE,
                    f"a hidden member past the {limit}-byte limit: read in part",
                )
            )
        return payload

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
                ArchiveReader._zip_member(archive, info, limits, result)

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

                    ArchiveReader._tar_member(archive, member, limits, result)

            except (ArchiveError, tarfile.TarError, OSError, ValueError, EOFError) as exc:
                ArchiveReader._tar_stopped(exc, path, result)

        result.total_compressed = max(result.total_compressed, len(data))

    @staticmethod
    def _zip_member(
        archive: zipfile.ZipFile, info: zipfile.ZipInfo, limits: Limits, result: ExtractionResult
    ) -> None:
        """One member of a zip: kept, recorded as a link inside the archive, or rejected with its
        reason. A directory is skipped; the deadline is `_extract_zip`'s."""
        if info.is_dir():
            return

        safe = ArchiveReader.safe_member_name(
            info.filename, collapse=not ArchiveReader._links_seen(result)
        )
        if safe is None:
            result.rejected.append(
                RejectedMember(
                    info.filename,
                    Rejection.TRAVERSAL,
                    "member name escapes the destination directory",
                )
            )
            return

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
                return
            result.rejected.append(
                RejectedMember(
                    safe,
                    Rejection.LINK,
                    f"symbolic-link members are never extracted (-> {target[:200]})",
                )
            )
            return

        if ArchiveReader._would_exceed(
            result, info.compress_size, info.file_size, limits, safe
        ) and not ArchiveReader._spilled_instead(result, safe):
            return

        try:
            with archive.open(info) as handle:
                payload = ArchiveReader._read_bounded(
                    handle, limits, info.compress_size, result, safe
                )
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError) as exc:
            result.rejected.append(RejectedMember(safe, Rejection.UNREADABLE, str(exc)))
            return

        if payload is None:
            return

        result.members.append(
            ExtractedMember(
                name=safe,
                data=payload,
                compressed_size=info.compress_size,
                uncompressed_size=len(payload),
            )
        )

    @staticmethod
    def _tar_stopped(exc: Exception, path: str, result: ExtractionResult) -> None:
        """A tar stream that stopped part way: what was read is kept, and why it stopped recorded.
        Raises `ArchiveError` only for a damaged index with nothing read before it."""
        if isinstance(exc, BudgetExceeded):
            # Stopped where the budget ran out. What was read is kept and scanned; past an
            # expansion this lopsided, what was not read is behind padding.
            result.truncated = True
            shape = Rejection.PADDED if exc.padded else Rejection.SIZE
            result.rejected.append(RejectedMember(path, shape, str(exc)))
            return
        if isinstance(exc, ArchiveError):
            result.truncated = True
            result.rejected.append(RejectedMember(path, Rejection.ENTRIES, str(exc)))
            return
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

    @staticmethod
    def _tar_member(
        archive: tarfile.TarFile, member: tarfile.TarInfo, limits: Limits, result: ExtractionResult
    ) -> None:
        """One member of a tar stream: kept, recorded as a link inside the archive, or rejected with
        its reason. A directory is skipped; nothing here stops the stream (`_extract_tar` does)."""
        if member.isdir():
            return

        # Anything that is not a plain file: links, devices, FIFOs. A
        # device node or FIFO can block a reader indefinitely, and a link
        # can redirect it outside the archive entirely.
        if member.issym() or member.islnk():
            if ArchiveReader.link_stays_inside(member.name, member.linkname, hard=member.islnk()):
                result.links.append(member.name)
                return
            result.rejected.append(
                RejectedMember(
                    member.name,
                    Rejection.LINK,
                    f"link members are never extracted (-> {member.linkname[:200]})",
                )
            )
            return
        if not member.isfile():
            result.rejected.append(
                RejectedMember(member.name, Rejection.SPECIAL, "not a regular file")
            )
            return

        safe = ArchiveReader.safe_member_name(
            member.name, collapse=not ArchiveReader._links_seen(result)
        )
        if safe is None:
            result.rejected.append(
                RejectedMember(
                    member.name,
                    Rejection.TRAVERSAL,
                    "member name escapes the destination directory",
                )
            )
            return

        # The declared size is the attacker's number. It is used only to
        # reject early; the real bound is enforced while reading.
        if ArchiveReader._would_exceed(
            result, 0, member.size, limits, safe
        ) and not ArchiveReader._spilled_instead(result, safe):
            return

        try:
            handle = archive.extractfile(member)
            if handle is None:
                return
            payload = ArchiveReader._read_bounded(handle, limits, 0, result, safe)
        except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
            result.rejected.append(RejectedMember(safe, Rejection.UNREADABLE, str(exc)))
            return

        if payload is None:
            return

        result.members.append(
            ExtractedMember(
                name=safe,
                data=payload,
                compressed_size=0,
                uncompressed_size=len(payload),
            )
        )

    @staticmethod
    def member_limit(limits: Limits) -> int:
        """The largest member a declared size may be refused at, and the largest nested archive
        opened in memory. A member past it is not refused for its size: past `max_file_bytes` every
        member is kept on disk as it is read (`foundation/files/spill.py`), and only the ratio and total
        budgets stop one."""
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
    def _spilled_instead(result: ExtractionResult, name: str) -> bool:
        """Whether `_would_exceed` just refused `name` for its own declared size alone -- not as
        padding, and not for the archive's total budget -- and so it is read after all, spilled to
        disk as it arrives (`_read_bounded`), its refusal withdrawn.

        A member over the size limit used to be refused unread, a compiled program's first 64 MB
        excepted: a Go or Rust launcher runs past that, and a payload padded past any limit is
        exactly what the limit hides (review 98: 207 of the npm work set's malware refused so).
        Read whole from disk, only the decompression-bomb ceilings stop it."""
        last = result.rejected[-1] if result.rejected else None
        if (
            last is None
            or last.name != name
            or last.reason != Rejection.SIZE
            or not last.detail.startswith("declared ")
        ):
            return False
        result.rejected.pop()
        return True

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
        # Past `max_file_bytes` the member is written to disk as it arrives and read from there
        # (`foundation/files/spill.py`): memory holds its prefix, and no size of member is refused.
        spill: BinaryIO | None = None
        spill_path, prefix = "", b""
        try:
            while True:
                chunk = handle.read(READ_CHUNK)
                if not chunk:
                    break
                read_total += len(chunk)
                if ArchiveReader._over_budget(result, limits, name, read_total):
                    return None
                if spill is None and read_total > limits.max_file_bytes:
                    chunks.append(chunk)
                    held = b"".join(chunks)
                    prefix, chunks = held[: limits.max_file_bytes], []
                    spill, spill_path = Spill.writer()
                    spill.write(held)
                elif spill is None:
                    chunks.append(chunk)
                else:
                    spill.write(chunk)
            if spill is not None:
                spill.close()
                spill = None
                kept_member: bytes = SpilledBytes(prefix, spill_path, read_total)
                spill_path = ""
            else:
                kept_member = b"".join(chunks)
        finally:
            if spill is not None:
                spill.close()
            if spill_path:  # stopped at a budget or an error: nothing of it is kept
                Spill.remove(spill_path)

        result.total_uncompressed += read_total
        result.total_compressed += compressed_size
        return kept_member

    @staticmethod
    def _over_budget(result: ExtractionResult, limits: Limits, name: str, read_total: int) -> bool:
        """Whether reading `read_total` bytes of `name` passes the archive's expansion cap or its
        total budget -- the decompression-bomb ceilings, which no member is read past."""
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
            return True
        if result.total_uncompressed + read_total > limits.max_uncompressed_bytes:
            result.truncated = True
            result.rejected.append(
                RejectedMember(
                    name, Rejection.SIZE, "archive exceeds the total uncompressed budget"
                )
            )
            return True
        return False

    @staticmethod
    def walk_archive(
        data: bytes,
        *,
        path: str,
        limits: Limits = DEFAULT_LIMITS,
        depth: int = 0,
        rejected: list[tuple[str, str, str]] | None = None,
        deadline: float | None = None,
        walk: NestedWalk | None = None,
    ) -> Iterator[tuple[str, bytes]]:
        """Yield every member, descending into nested archives.

        A nested archive met past the depth limit whose exact bytes this walk also opened at a
        shallower depth has had its contents examined, so it is not reported as unexamined
        (`NestedWalk`).

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

        root = walk is None
        walk = NestedWalk() if walk is None else walk
        try:
            yield from ArchiveReader._walk_members(
                result, path, limits, depth, rejected, deadline, walk
            )
        finally:
            if root and rejected is not None:
                # Settled once the whole walk has run (or stopped): an archive is unexamined
                # only if no copy of it was opened anywhere in this walk.
                rejected.extend(r for digest, r in walk.too_deep if digest not in walk.opened)

    @staticmethod
    def _walk_members(
        result: ExtractionResult,
        path: str,
        limits: Limits,
        depth: int,
        rejected: list[tuple[str, str, str]] | None,
        deadline: float | None,
        walk: NestedWalk,
    ) -> Iterator[tuple[str, bytes]]:
        for member in result.members:
            member_path = f"{path}!{member.name}"

            nested = ArchiveReader.is_archive(member.name)
            # A nested archive is opened in memory. One kept on disk is read back within the size a
            # member could always be held at; past it, its contents are reported unexamined.
            inner = member.data
            if nested and isinstance(inner, SpilledBytes):
                if inner.size <= ArchiveReader.member_limit(limits):
                    inner = inner.read_whole()
                else:
                    nested = False
                    if rejected is not None:
                        rejected.append(
                            (
                                member_path,
                                Rejection.SIZE,
                                f"a nested archive of {inner.size} bytes, past the "
                                f"{ArchiveReader.member_limit(limits)} bytes one is opened at; "
                                "its contents were not examined",
                            )
                        )
            digest = hashlib.sha256(inner).digest() if nested else b""
            too_deep = nested and depth >= limits.max_archive_depth
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
                walk.too_deep.append(
                    (
                        digest,
                        (
                            member_path,
                            Rejection.DEPTH,
                            f"nested deeper than {limits.max_archive_depth} levels; "
                            f"its contents were not examined",
                        ),
                    )
                )

            if nested and depth < limits.max_archive_depth:
                try:
                    yield from ArchiveReader.walk_archive(
                        inner,
                        path=member_path,
                        limits=limits,
                        depth=depth + 1,
                        rejected=rejected,
                        deadline=deadline,
                        walk=walk,
                    )
                    walk.opened.add(digest)
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


__all__ = ["ARCHIVE_SUFFIXES", "ArchiveReader", "ExtractedMember", "ExtractionResult"]
