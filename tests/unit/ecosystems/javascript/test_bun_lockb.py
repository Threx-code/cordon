"""Bun's binary lockfile (`bun.lockb`) is read into the same graph as the text `bun.lock`.

The fixtures are built here, byte by byte, from the format note (reviews/review-98/28), by a
writer that follows the note and nothing else: there is no licensed `bun.lockb` in the
repository and nothing from the corpus is ever a fixture. The negative tests cut and bend
those bytes; every one must come back as a `parse_error`, never an exception.
"""

from __future__ import annotations

import struct

import pytest

from cordon_scanner.ecosystems.packages.javascript.bun_lockb import BunLockb
from cordon_scanner.ecosystems.packages.npm import NpmEcosystem
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope

PROD, OPTIONAL, DEV, PEER = 1 << 1, 1 << 2, 1 << 3, 1 << 4
ALL_OS = sum(1 << b for b in range(1, 9))
ALL_CPU = sum(1 << b for b in range(1, 12))


class Writer:
    """A `bun.lockb` from a description, laid out as the note says."""

    HEADER = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n"

    def __init__(self, fmt: int = 3, columns: int = 8) -> None:
        self.fmt = fmt
        self.columns = columns
        self.strings = bytearray()
        self.deps = bytearray()
        self.resolutions = bytearray()
        self.packages: list[dict[str, bytes]] = []

    # -- records -----------------------------------------------------------------------------

    def s(self, text: str) -> bytes:
        raw = text.encode()
        if len(raw) < 8 or (len(raw) == 8 and raw[7] < 0x80):
            return raw.ljust(8, b"\0")
        off = len(self.strings)
        self.strings += raw
        return struct.pack("<II", off, len(raw) | 0x80000000)

    def version(self, major: int, minor: int, patch: int, pre: str = "", build: str = "") -> bytes:
        numbers = (
            struct.pack("<3Q", major, minor, patch)
            if self.fmt == 3
            else struct.pack("<3I", major, minor, patch) + bytes(4)
        )
        return numbers + self.s(pre) + bytes(8) + self.s(build) + bytes(8)

    def resolution(self, tag: int, *values: bytes) -> bytes:
        width = 72 if self.fmt == 3 else 64
        return (bytes([tag]) + bytes(7) + b"".join(values)).ljust(width, b"\0")

    def npm(self, url: str, *version: int, pre: str = "", build: str = "") -> bytes:
        return self.resolution(2, self.s(url), self.version(*version, pre=pre, build=build))

    def meta(self, integrity: bytes | None = None, os: int = ALL_OS, cpu: int = ALL_CPU) -> bytes:
        tag = 4 if integrity else 0
        digest = (integrity or b"").ljust(64, b"\0")
        return (
            bytes([1, 0])
            + struct.pack("<HH", cpu, os)
            + bytes([0, 0])
            + struct.pack("<I", len(self.packages))
            + bytes(8)
            + bytes([tag])
            + digest
            + bytes([1, 0, 0])
        )

    def package(
        self,
        name: str,
        resolution: bytes,
        deps: list[tuple[str, int, int]] = (),
        meta: bytes | None = None,
    ) -> int:
        """Appends a package; `deps` are (name, behaviour, resolved package id). Its id."""
        off = len(self.deps) // 26
        for dep_name, behavior, package in deps:
            self.deps += self.s(dep_name) + bytes(8) + bytes([behavior, 1]) + self.s("*")
            self.resolutions += struct.pack("<I", package)
        record = {
            "name": self.s(name),
            "name_hash": bytes(8),
            "resolution": resolution,
            "dependencies": struct.pack("<II", off, len(deps)),
            "resolutions": struct.pack("<II", off, len(deps)),
            "meta": meta if meta is not None else self.meta(),
            "bin": bytes(20),
            "scripts": bytes(49),
        }
        self.packages.append(record)
        return len(self.packages) - 1

    # -- the file ------------------------------------------------------------------------------

    @staticmethod
    def array(
        out: bytearray, payload: bytes, label: bytes = b"\n<u8> 1 sizeof, 1 alignof\n"
    ) -> None:
        at = len(out)
        out += struct.pack("<QQ", 0xDEADBEEF, 0xDEADBEEF) + label
        if payload:
            out += bytes(-len(out) % 8)
        start = len(out)
        out += payload
        out[at : at + 16] = struct.pack("<QQ", start, len(out))

    def build(self) -> bytes:
        out = bytearray(self.HEADER + struct.pack("<I", self.fmt) + bytes(32))
        total_at = len(out)
        out += bytes(8)
        names = [
            "name",
            "name_hash",
            "resolution",
            "dependencies",
            "resolutions",
            "meta",
            "bin",
            "scripts",
        ]
        out += struct.pack("<QQQ", len(self.packages), 8, self.columns)
        range_at = len(out)
        out += bytes(16)
        out += bytes(-len(out) % 8)
        begin = len(out)
        for column in names[: self.columns]:
            for record in self.packages:
                out += record[column]
        out[range_at : range_at + 16] = struct.pack("<QQ", begin, len(out))
        self.array(out, b"")  # trees
        self.array(out, b"")  # hoisted dependencies
        self.array(out, bytes(self.resolutions))
        self.array(out, bytes(self.deps))
        self.array(out, b"")  # extern strings
        self.array(out, bytes(self.strings))
        out += bytes(8)  # the end marker
        out[total_at : total_at + 8] = struct.pack("<Q", len(out))
        return bytes(out) + bytes(16)


class Project:
    """A root with four kinds of dependency, a workspace, a transitive package."""

    @staticmethod
    def build(fmt: int = 3, columns: int = 8) -> Writer:
        w = Writer(fmt, columns)
        w.package(
            "app",
            w.resolution(1),
            [
                ("alpha", PROD, 1),
                ("beta-tools", DEV, 2),
                ("gamma", OPTIONAL, 3),
                ("delta", PEER, 4),
                ("@acme/ui", PROD, 5),
            ],
        )
        w.package(
            "alpha",
            w.npm("https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz", 1, 2, 3),
            [("@scope/long-name", PROD, 6)],
            w.meta(integrity=bytes(range(64))),
        )
        w.package("beta-tools", w.npm("", 2, 0, 0, pre="beta.1", build="7"))
        w.package("gamma", w.npm("", 0, 1, 0), meta=w.meta(os=1 << 2))
        w.package("delta", w.resolution(16, w.s("octo"), w.s("delta"), w.s("main"), w.s("abc123")))
        w.package("@acme/ui", w.resolution(72, w.s("packages/ui")), [("@scope/long-name", PROD, 6)])
        w.package("@scope/long-name", w.npm("", 9, 9, 9))
        return w

    @staticmethod
    def parse(raw: bytes) -> object:
        return BunLockb.parse(FileContent(path="bun.lockb", raw=raw, size=len(raw)), "npm")


class TestAProjectIsRead:
    @pytest.mark.parametrize("fmt", [3, 2])
    def test_every_package_with_its_version_scope_and_edges(self, fmt: int) -> None:
        graph = Project.parse(Project.build(fmt).build())
        assert graph.parse_error is None, graph.parse_error
        by_name = {e.name: e for e in graph.entries}
        assert sorted(by_name) == [
            "@acme/ui",
            "@scope/long-name",
            "alpha",
            "beta-tools",
            "delta",
            "gamma",
        ]
        alpha = by_name["alpha"]
        assert (alpha.version, alpha.scope, alpha.direct) == ("1.2.3", Scope.RUNTIME, True)
        assert alpha.resolved_from == "https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz"
        assert alpha.integrity is not None and alpha.integrity.startswith("sha512-AAECAwQF")
        assert alpha.dependencies == ("@scope/long-name",)
        assert by_name["beta-tools"].version == "2.0.0-beta.1+7"
        assert by_name["beta-tools"].scope is Scope.DEV
        assert by_name["gamma"].scope is Scope.OPTIONAL
        assert by_name["gamma"].platform == ("os: darwin",)
        assert by_name["alpha"].platform == ()
        delta = by_name["delta"]
        assert (delta.version, delta.resolved_from, delta.scope) == (
            "",
            "github:octo/delta#abc123",
            Scope.RUNTIME,
        )
        ui = by_name["@acme/ui"]
        assert (ui.local, ui.version, ui.integrity, ui.direct) == (True, "", None, True)
        long = by_name["@scope/long-name"]
        assert (long.version, long.direct, long.scope) == ("9.9.9", True, Scope.RUNTIME)
        assert graph.workspaces == ("packages/ui",)

    def test_a_transitive_package_is_not_direct(self) -> None:
        w = Writer()
        w.package("app", w.resolution(1), [("a", PROD, 1)])
        w.package("a", w.npm("", 1, 0, 0), [("b", PROD, 2)])
        w.package("b", w.npm("", 2, 0, 0))
        graph = Project.parse(w.build())
        assert [(e.name, e.direct, e.scope) for e in graph.entries] == [
            ("a", True, Scope.RUNTIME),
            ("b", False, Scope.RUNTIME),
        ]

    def test_seven_columns_from_before_bun_0_6_8_read(self) -> None:
        graph = Project.parse(Project.build(columns=7).build())
        assert graph.parse_error is None and len(graph.entries) == 6

    def test_the_read_is_the_same_twice(self) -> None:
        raw = Project.build().build()
        assert Project.parse(raw) == Project.parse(raw)


class Bent:
    """Ways to spoil the project's bytes; each must be one parse error."""

    @staticmethod
    def cases() -> list[tuple[str, bytes]]:
        good = Project.build().build()
        at = lambda marker: good.index(marker)  # noqa: E731
        out = [
            ("header", b"#!/usr/bin/env bun\nbun-lockfile-format-v9\n" + good[42:]),
            ("format 1", good[:42] + struct.pack("<I", 1) + good[46:]),
            ("format 4", good[:42] + struct.pack("<I", 4) + good[46:]),
            ("total size past the end", good[:78] + struct.pack("<Q", len(good) * 2) + good[86:]),
            ("end marker", good[: len(good) - 24] + b"\7" + good[len(good) - 23 :]),
            ("empty", b""),
            ("header only", good[:42]),
        ]
        # The name column holds 7 records of 8 bytes and the hash column 7 more; "alpha" is the
        # name column's second record, so the resolution column (its root record's tag byte)
        # starts 8 + 112 bytes before it... that is, 104 bytes after it.
        resolution_at = at(b"alpha\0\0\0") + 104
        out.append(("resolution tag 3", good[:resolution_at] + b"\3" + good[resolution_at + 1 :]))
        pointer_at = at(Writer().s("beta-tools"))  # the fixture's first pointer string
        out.append(
            (
                "string pointer past the bytes",
                good[:pointer_at]
                + struct.pack("<II", 0, 4096 | 0x80000000)
                + good[pointer_at + 8 :],
            )
        )
        for cut in range(43, len(good), 61):
            out.append((f"cut at {cut}", good[:cut]))
        return out


class TestSpoiledBytesAreOneRefusal:
    @pytest.mark.parametrize(("why", "raw"), Bent.cases(), ids=[c[0] for c in Bent.cases()])
    def test_a_parse_error_never_an_exception(self, why: str, raw: bytes) -> None:
        graph = Project.parse(raw)
        assert graph.parse_error is not None and graph.parse_error.startswith(
            "invalid bun.lockb"
        ), why
        assert graph.entries == ()

    def test_a_dependency_slice_past_the_buffer(self) -> None:
        w = Writer()
        w.package("app", w.resolution(1), [("a", PROD, 1)])
        w.package("a", w.npm("", 1, 0, 0))
        w.packages[1]["dependencies"] = struct.pack("<II", 0, 40)
        assert "slice" in (Project.parse(w.build()).parse_error or "")


class TestTheEcosystemDispatchesToIt:
    def test_npm_reads_a_bun_lockb_like_any_lockfile(self) -> None:
        raw = Project.build().build()
        graph = NpmEcosystem().parse_lockfile(FileContent.from_bytes("a/bun.lockb", raw, Limits()))
        assert graph.parse_error is None and len(graph.entries) == 6
        assert "**/bun.lockb" in NpmEcosystem.lockfile_globs
