"""bun.lockb files whose bytes do not fit the format, and the resolution kinds that carry no registry version: each is a refusal or a local package, never an exception (`ecosystems/packages/javascript/bun_lockb.py`)."""

from __future__ import annotations

import struct
from typing import Any

import pytest
from test_bun_lockb import PROD, Project, Writer

COUNT = len(Writer.HEADER) + 4 + 32 + 8
"""Where the package count sits: after the header, the format, the meta hash and the total size."""


class Skewed(Writer):
    """A writer whose `nth` array gets positions that do not fit."""

    nth = -1
    mode = ""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.seen = 0

    def array(
        self, out: bytearray, payload: bytes, label: bytes = b"\n<u8> 1 sizeof, 1 alignof\n"
    ) -> None:  # type: ignore[override]
        at = len(out)
        Writer.array(out, payload, label)
        if self.seen == self.nth:
            start, end = struct.unpack_from("<QQ", out, at)
            if self.mode == "zero":
                start = 0
            elif self.mode == "ragged":
                end = start + 5
            struct.pack_into("<QQ", out, at, start, end)
        self.seen += 1


class _Kit:
    @staticmethod
    def parse(raw: bytes) -> Any:
        return Project.parse(raw)

    @staticmethod
    def patched(offset: int, value: int) -> bytes:
        raw = bytearray(Project.build().build())
        struct.pack_into("<Q", raw, offset, value)
        return bytes(raw)


class TestTheTableHeader:
    @pytest.mark.parametrize(
        ("offset", "value", "why"),
        [
            (COUNT + 8, 9, "alignment is not 8"),
            (COUNT + 16, 3, "3 package columns"),
            (COUNT + 24, 1 << 40, "do not fit the file"),
            (COUNT, 1 << 30, "packages do not fit"),
        ],
    )
    def test_a_header_field_that_does_not_fit_is_a_named_refusal(
        self, offset: int, value: int, why: str
    ) -> None:
        graph = _Kit.parse(_Kit.patched(offset, value))
        assert why in graph.parse_error


class TestArrays:
    def build(self, mode: str, nth: int, **kwargs: Any) -> bytes:
        writer = Skewed(**kwargs)
        writer.nth, writer.mode = nth, mode
        return writer.build()

    def test_an_array_whose_start_is_zero_does_not_fit(self) -> None:
        writer = Skewed()
        writer.nth, writer.mode = 0, "zero"
        writer.package("app", writer.resolution(1))
        assert "do not fit the file" in _Kit.parse(writer.build()).parse_error

    def test_an_array_that_is_not_a_whole_number_of_records_is_refused(self) -> None:
        writer = Skewed()
        writer.nth, writer.mode = 0, "ragged"
        writer.package("app", writer.resolution(1))
        assert "not a whole number of records" in _Kit.parse(writer.build()).parse_error

    def test_resolutions_and_dependencies_of_different_lengths_are_refused(self) -> None:
        writer = Writer()
        writer.package("app", writer.resolution(1))
        writer.resolutions += struct.pack("<I", 0)
        assert "differ in length" in _Kit.parse(writer.build()).parse_error


class TestResolutions:
    def test_a_first_package_that_is_not_the_root_is_refused(self) -> None:
        writer = Writer()
        writer.package("alpha", writer.npm("", 1, 0, 0))
        assert "package 0 is not the root" in _Kit.parse(writer.build()).parse_error

    def test_a_remote_tarball_a_folder_and_a_workspace_are_read_as_they_are_declared(self) -> None:
        writer = Writer()
        writer.package(
            "app",
            writer.resolution(1),
            [("tarball", PROD, 1), ("folder", PROD, 2), ("ws", PROD, 3)],
        )
        writer.package("tarball", writer.resolution(80, writer.s("https://example.invalid/t.tgz")))
        writer.package("folder", writer.resolution(8, writer.s("../folder")))
        writer.package("ws", writer.resolution(72, writer.s("packages/ws")))
        graph = _Kit.parse(writer.build())
        assert graph.parse_error is None, graph.parse_error
        by_name = {e.name: e for e in graph.entries}
        assert by_name["tarball"].resolved_from == "https://example.invalid/t.tgz"
        assert by_name["folder"].local is True
