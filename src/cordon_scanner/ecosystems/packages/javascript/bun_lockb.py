"""bun.lockb: Bun's binary lockfile, read into the dependency graph.

The format is in reviews/review-98/28-BUN-LOCKB-FORMAT.md, measured from Bun's source: a
header, a table of fixed-width package columns, six arrays (the dependency records, the
resolutions, the string bytes every name points into), an end marker. This reader is our own
design from that note; it reads the bytes once, checks every offset and count against them,
and emits the `LockGraph` the text `bun.lock` reader emits.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.base import LockEntry, LockGraph
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class Malformed(ValueError):
    """The file is not a bun.lockb this reader can follow; the message says where it stopped."""


@dataclass(frozen=True)
class Widths:
    """The record widths that differ between format 2 (u32 version numbers) and format 3."""

    version: int
    resolution: int
    number: str
    """The struct code of one version number."""
    pre: int
    """Offset of the pre-release tag's STRING inside a VERSION; `build` the build tag's."""
    build: int


class Stream:
    """Bounded little-endian reads over the file's bytes."""

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.view = memoryview(raw)
        self.pos = 0

    def take(self, size: int, what: str) -> bytes:
        end = self.pos + size
        if end > len(self.raw):
            raise Malformed(f"{what}: the file ends first")
        out = self.raw[self.pos : end]
        self.pos = end
        return out

    def u32(self, what: str) -> int:
        return int(struct.unpack("<I", self.take(4, what))[0])

    def u64(self, what: str) -> int:
        return int(struct.unpack("<Q", self.take(8, what))[0])

    def array(self, width: int, what: str) -> memoryview:
        """One ARRAY: its payload as a view of `width`-byte records; the stream moves past it."""
        start = self.u64(f"{what} start")
        end = self.u64(f"{what} end")
        if start == 0 or end == 0 or start > end or end > len(self.raw) or start < self.pos - 16:
            raise Malformed(f"{what}: positions {start}..{end} do not fit the file")
        if (end - start) % width:
            raise Malformed(f"{what}: {end - start} bytes is not a whole number of records")
        self.pos = end
        return self.view[start:end]


class Strings:
    """The 8-byte STRING: inline text, or a pointer into the string bytes by its top bit."""

    def __init__(self, string_bytes: memoryview) -> None:
        self.bytes = string_bytes

    def text(self, raw: memoryview, what: str) -> str:
        head = bytes(raw[:8])
        if len(head) < 8:
            raise Malformed(f"{what}: a string cut short")
        if head[7] & 0x80:
            off, length = struct.unpack("<II", head)
            length &= 0x7FFFFFFF
            if off + length > len(self.bytes):
                raise Malformed(f"{what}: a string pointer past the string bytes")
            return bytes(self.bytes[off : off + length]).decode("utf-8", "replace")
        end = head.find(b"\0")
        return head[: end if end >= 0 else 8].decode("utf-8", "replace")


@dataclass(frozen=True)
class Resolution:
    version: str
    resolved_from: str | None
    local: bool
    workspace_path: str | None


@dataclass(frozen=True)
class Dependency:
    name: str
    behavior: int
    package: int
    """The resolved package's id, or `BunLockb.INVALID` where Bun left it unresolved."""


class Records:
    """Each record kind decoded from its column bytes."""

    #: RESOLUTION tags that may appear in a lockfile.
    ROOT: ClassVar[int] = 1
    NPM: ClassVar[int] = 2
    GITHUB: ClassVar[int] = 16
    GIT: ClassVar[int] = 32
    WORKSPACE: ClassVar[int] = 72
    REMOTE_TARBALL: ClassVar[int] = 80
    TAGS: ClassVar[frozenset[int]] = frozenset({1, 2, 4, 8, 16, 32, 64, 72, 80})

    #: META: the integrity digest lengths by tag, and the platform bits by name.
    DIGEST: ClassVar[dict[int, tuple[str, int]]] = {
        1: ("sha1", 20),
        2: ("sha256", 32),
        3: ("sha384", 48),
        4: ("sha512", 64),
    }
    OS: ClassVar[tuple[tuple[str, int], ...]] = (
        ("aix", 1 << 1),
        ("darwin", 1 << 2),
        ("freebsd", 1 << 3),
        ("linux", 1 << 4),
        ("openbsd", 1 << 5),
        ("sunos", 1 << 6),
        ("win32", 1 << 7),
        ("android", 1 << 8),
    )
    CPU: ClassVar[tuple[tuple[str, int], ...]] = (
        ("arm", 1 << 1),
        ("arm64", 1 << 2),
        ("ia32", 1 << 3),
        ("mips", 1 << 4),
        ("mipsel", 1 << 5),
        ("ppc", 1 << 6),
        ("ppc64", 1 << 7),
        ("s390", 1 << 8),
        ("s390x", 1 << 9),
        ("x32", 1 << 10),
        ("x64", 1 << 11),
    )
    LIBC: ClassVar[tuple[tuple[str, int], ...]] = (("glibc", 1 << 1), ("musl", 1 << 2))

    def __init__(self, strings: Strings, widths: Widths) -> None:
        self.strings = strings
        self.widths = widths

    def version(self, raw: memoryview, what: str) -> str:
        """VERSION: `major.minor.patch`, then `-pre` and `+build` where they are not empty."""
        w = self.widths
        major, minor, patch = struct.unpack_from("<3" + w.number, raw)
        text = f"{major}.{minor}.{patch}"
        pre = self.strings.text(raw[w.pre : w.pre + 8], f"{what} pre")
        build = self.strings.text(raw[w.build : w.build + 8], f"{what} build")
        if pre:
            text += f"-{pre}"
        if build:
            text += f"+{build}"
        return text

    def resolution(self, raw: memoryview, what: str) -> Resolution:
        tag = raw[0]
        if tag not in self.TAGS:
            raise Malformed(f"{what}: resolution tag {tag}")
        value = raw[8:]
        if tag == self.NPM:
            url = self.strings.text(value[:8], f"{what} url")
            return Resolution(self.version(value[8:], what), url or None, False, None)
        if tag in (self.GIT, self.GITHUB):
            owner, repo, committish, resolved = (
                self.strings.text(value[i : i + 8], what) for i in (0, 8, 16, 24)
            )
            scheme = "github:" if tag == self.GITHUB else "git+"
            return Resolution("", f"{scheme}{owner}/{repo}#{resolved or committish}", False, None)
        if tag == self.ROOT:
            return Resolution("", None, True, None)
        path = self.strings.text(value[:8], what)
        if tag == self.WORKSPACE:
            return Resolution("", None, True, path)
        if tag == self.REMOTE_TARBALL:
            return Resolution("", path or None, False, None)
        return Resolution("", None, True, None)  # a folder, a local tarball, a symlink

    def integrity(self, meta: memoryview) -> str | None:
        """META's digest as `<algorithm>-<base64>`, the form the text lockfiles carry."""
        known = self.DIGEST.get(meta[20])
        if known is None:
            return None
        name, length = known
        return f"{name}-{base64.b64encode(bytes(meta[21 : 21 + length])).decode('ascii')}"

    def platform(self, meta: memoryview) -> tuple[str, ...]:
        """`os`, `cpu` and `libc` conditions where the package is not for every platform."""
        arch, os_bits = struct.unpack_from("<HH", meta, 2)
        libc = meta[6]
        out: list[str] = []
        for field, bits, names in (("os", os_bits, self.OS), ("cpu", arch, self.CPU)):
            every = sum(bit for _, bit in names)
            if bits & every != every:
                # A mask naming nothing: the manifest named a platform Bun has no bit for
                # (npm's `wasm32`), so the package is constrained to one Bun does not record.
                allowed = ", ".join(n for n, bit in names if bits & bit) or "unknown"
                out.append(f"{field}: {allowed}")
        every_libc = sum(bit for _, bit in self.LIBC)
        if libc and libc & every_libc != every_libc:
            out.append(f"libc: {', '.join(n for n, bit in self.LIBC if libc & bit)}")
        return tuple(out)


@dataclass
class Table:
    """The package table's columns, each a view of `count` records."""

    count: int
    columns: dict[str, memoryview]

    def record(self, column: str, index: int, width: int) -> memoryview:
        return self.columns[column][index * width : (index + 1) * width]


class BunLockb:
    """`BunLockb.parse(content, ecosystem)`: the lockfile as a `LockGraph`, or one with a
    `parse_error` naming where the bytes stopped making sense."""

    HEADER: ClassVar[bytes] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n"
    WIDTHS: ClassVar[dict[int, Widths]] = {
        2: Widths(version=48, resolution=64, number="I", pre=16, build=32),
        3: Widths(version=56, resolution=72, number="Q", pre=24, build=40),
    }
    #: The package table's columns, by name and width (the resolution's is per format).
    COLUMNS: ClassVar[tuple[tuple[str, int], ...]] = (
        ("name", 8),
        ("name_hash", 8),
        ("resolution", 0),
        ("dependencies", 8),
        ("resolutions", 8),
        ("meta", 88),
        ("bin", 20),
        ("scripts", 49),
    )
    INVALID: ClassVar[int] = 0xFFFFFFFF

    #: DEPENDENCY behaviour bits.
    PROD: ClassVar[int] = 1 << 1
    OPTIONAL: ClassVar[int] = 1 << 2
    DEV: ClassVar[int] = 1 << 3
    PEER: ClassVar[int] = 1 << 4

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        try:
            entries, workspaces = cls._read(content.raw)
        except (Malformed, struct.error) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid bun.lockb: {exc}"
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            workspaces=tuple(sorted(workspaces)),
        )

    @classmethod
    def _read(cls, raw: bytes) -> tuple[list[LockEntry], list[str]]:
        stream = Stream(raw)
        if stream.take(len(cls.HEADER), "header") != cls.HEADER:
            raise Malformed("not Bun's binary lockfile header")
        fmt = stream.u32("format")
        widths = cls.WIDTHS.get(fmt)
        if widths is None:
            raise Malformed(f"format {fmt}; formats 2 and 3 are read")
        stream.take(32, "meta hash")
        if stream.u64("total size") > len(raw):
            raise Malformed("total size past the file's end")
        table = cls._table(stream, widths)
        stream.array(20, "trees")
        stream.array(4, "hoisted dependencies")
        resolutions = stream.array(4, "resolutions")
        dependencies = stream.array(26, "dependencies")
        stream.array(16, "extern strings")
        strings = Strings(stream.array(1, "string bytes"))
        if stream.u64("end marker") != 0:
            raise Malformed("the end marker is not 0")
        if len(resolutions) // 4 != len(dependencies) // 26:
            raise Malformed("resolutions and dependencies differ in length")
        records = Records(strings, widths)
        return cls._entries(table, records, strings, dependencies, resolutions)

    @classmethod
    def _table(cls, stream: Stream, widths: Widths) -> Table:
        """The package table: its header checked, each column as a view of its records."""
        count = stream.u64("package count")
        if stream.u64("alignment") != 8:
            raise Malformed("package table alignment is not 8")
        fields = stream.u64("field count")
        if fields not in (len(cls.COLUMNS), len(cls.COLUMNS) - 1):
            raise Malformed(f"{fields} package columns")
        begin = stream.u64("columns begin")
        end = stream.u64("columns end")
        if begin > end or end > len(stream.raw) or begin < stream.pos:
            raise Malformed(f"package columns {begin}..{end} do not fit the file")
        names = [(n, widths.resolution if w == 0 else w) for n, w in cls.COLUMNS[: int(fields)]]
        if count == 0 or count * sum(w for _, w in names) > end - begin:
            raise Malformed(f"{count} packages do not fit {end - begin} column bytes")
        columns: dict[str, memoryview] = {}
        at = begin
        for name, width in names:
            columns[name] = stream.view[at : at + width * count]
            at += width * count
        stream.pos = end
        return Table(int(count), columns)

    @classmethod
    def _dependencies(
        cls,
        table: Table,
        index: int,
        strings: Strings,
        dependencies: memoryview,
        resolutions: memoryview,
    ) -> list[Dependency]:
        """Package `index`'s declared dependencies, each with the package it resolved to."""
        off, length = struct.unpack("<II", table.record("dependencies", index, 8))
        if (off + length) * 26 > len(dependencies):
            raise Malformed(f"package {index}: a dependency slice past the buffer")
        out: list[Dependency] = []
        for k in range(off, off + length):
            record = dependencies[k * 26 : (k + 1) * 26]
            name = strings.text(record[:8], f"dependency {k} name")
            package = struct.unpack("<I", resolutions[k * 4 : (k + 1) * 4])[0]
            out.append(Dependency(name, record[16], package))
        return out

    @classmethod
    def _entries(
        cls,
        table: Table,
        records: Records,
        strings: Strings,
        dependencies: memoryview,
        resolutions: memoryview,
    ) -> tuple[list[LockEntry], list[str]]:
        width = records.widths.resolution
        names = [
            strings.text(table.record("name", i, 8), f"package {i} name")
            for i in range(table.count)
        ]
        resolved = [
            records.resolution(table.record("resolution", i, width), f"package {i}")
            for i in range(table.count)
        ]
        if resolved[0].workspace_path is not None or not resolved[0].local:
            raise Malformed("package 0 is not the root")
        declared: dict[str, int] = {}
        direct: set[int] = set()
        workspaces: list[str] = []
        for i, res in enumerate(resolved):
            if i and res.workspace_path is None:
                continue
            if res.workspace_path:
                workspaces.append(res.workspace_path)
            for dep in cls._dependencies(table, i, strings, dependencies, resolutions):
                declared[dep.name] = declared.get(dep.name, 0) | dep.behavior
                direct.add(dep.package)
        entries: list[LockEntry] = []
        for i in range(1, table.count):
            meta = table.record("meta", i, 88)
            requires = cls._dependencies(table, i, strings, dependencies, resolutions)
            is_direct = i in direct and names[i] in declared
            entries.append(
                LockEntry(
                    name=names[i],
                    version=resolved[i].version,
                    integrity=None if resolved[i].local else records.integrity(meta),
                    resolved_from=resolved[i].resolved_from,
                    scope=cls._scope(declared.get(names[i], 0)) if is_direct else Scope.RUNTIME,
                    dependencies=tuple(sorted({d.name for d in requires})),
                    direct=is_direct,
                    local=resolved[i].local,
                    platform=records.platform(meta),
                )
            )
        return entries, workspaces

    @classmethod
    def _scope(cls, behavior: int) -> Scope:
        """Dev only when nothing asks for it at runtime; optional only likewise (as bun.lock)."""
        if behavior & cls.DEV and not behavior & (cls.PROD | cls.OPTIONAL | cls.PEER):
            return Scope.DEV
        if behavior & cls.OPTIONAL and not behavior & (cls.PROD | cls.DEV | cls.PEER):
            return Scope.OPTIONAL
        return Scope.RUNTIME


__all__ = ["BunLockb"]
