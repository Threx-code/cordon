"""The `lnk` module (modules.lnk): a shortcut built field by field here is read back value by value,
through the reader and through rules, and a damaged one keeps what came before the damage, as the
reference (YARA-X's lnk module) does. The real-file differential against the reference lives in the
review harness."""

from __future__ import annotations

import random
import struct
import uuid

import pytest

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.lnk import Lnk
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import Rules

GUID = uuid.UUID("20d04fe0-3aea-1069-a2d8-08002b30309d")  # My Computer, a root folder item
FILETIME_2020 = (1_577_836_800 + Lnk.UNIX_FROM_FILETIME) * 10_000_000


class Shortcut:
    """MS-SHLLINK, written out."""

    @staticmethod
    def header(
        flags: int, *, attributes: int = 0x20, show: int = 1, created: int = FILETIME_2020
    ) -> bytes:
        return (
            struct.pack("<I", 0x4C)
            + Lnk.CLSID
            + struct.pack("<II", flags, attributes)
            + struct.pack("<QQQ", created, 0, created)
            + struct.pack("<III", 1234, 7, show)
            + b"\x00" * 12
        )

    @staticmethod
    def item(data: bytes) -> bytes:
        return struct.pack("<H", len(data) + 2) + data

    @staticmethod
    def id_list(*items: bytes) -> bytes:
        body = b"".join(Shortcut.item(i) for i in items) + b"\x00\x00"
        return struct.pack("<H", len(body)) + body

    @staticmethod
    def link_info(base_path: bytes, label: bytes) -> bytes:
        volume = struct.pack("<IIII", 16 + len(label) + 1, 3, 0xCAFEBABE, 16) + label + b"\x00"
        head = 28
        base_at = head + len(volume)
        body = volume + base_path + b"\x00"
        size = head + len(body)
        return struct.pack("<IIIIIII", size, 0x1C, 0x1, head, base_at, 0, 0) + body

    @staticmethod
    def utf16(text: str, *, count: int | None = None) -> bytes:
        data = text.encode("utf-16-le")
        return struct.pack("<H", len(text) if count is None else count) + data

    @staticmethod
    def tracker() -> bytes:
        ids = b"".join(uuid.UUID(int=i + 1).bytes_le for i in range(4))
        body = (
            struct.pack("<I", Lnk.TRACKER)
            + struct.pack("<II", 0x58, 0)
            + b"host-01".ljust(16, b"\x00")
            + ids
        )
        return struct.pack("<I", len(body) + 4) + body

    @staticmethod
    def full(overlay: bytes = b"") -> bytes:
        flags = Lnk.ID_LIST | Lnk.LINK_INFO | Lnk.NAME | Lnk.ARGUMENTS | Lnk.UNICODE
        return (
            Shortcut.header(flags)
            + Shortcut.id_list(
                b"\x1f\x50" + GUID.bytes_le,
                b"\x2f" + b"C:\\".ljust(20, b"\x00"),
                b"\x32\x00" + b"\x00" * 10 + b"evil.exe\x00",
            )
            + Shortcut.link_info(b"C:\\Windows\\System32\\cmd.exe", b"OS")
            + Shortcut.utf16("Open the report")
            + Shortcut.utf16("/c powershell -enc AAAA")
            + Shortcut.tracker()
            + struct.pack("<I", 0)
            + overlay
        )


class TestReader:
    def test_every_value_of_a_full_shortcut(self) -> None:
        file = Shortcut.full(overlay=b"PK\x03\x04tail")
        out = Lnk.data(file)
        assert out["is_lnk"] is True
        assert (
            out["file_attributes"],
            out["file_size"],
            out["icon_index"],
            out["show_command"],
        ) == (0x20, 1234, 7, 1)
        assert out["creation_time"] == out["write_time"] == 1_577_836_800
        assert "access_time" not in out  # FILETIME zero is undefined
        assert out["name"] == b"Open the report"
        assert out["cmd_line_args"] == b"/c powershell -enc AAAA"
        assert out["local_base_path"] == b"C:\\Windows\\System32\\cmd.exe"
        assert (out["drive_type"], out["drive_serial_number"], out["volume_label"]) == (
            3,
            0xCAFEBABE,
            b"OS",
        )
        assert out["overlay_size"] == 8
        assert out["overlay_offset"] == len(file) - 8
        tracker = out["tracker_data"]
        assert tracker["machine_id"] == b"host-01"
        assert tracker["droid_volume_id"] == str(uuid.UUID(int=1)).encode()
        items = out["target_id_list"]
        assert [items[i]["item_type"] for i in range(3)] == [0x1F, 0x20, 0x30]
        assert items[0]["root_folder_id"] == str(GUID).encode()
        assert items[1]["volume_name"] == b"C:\\"
        assert items[2]["file_entry_name"] == b"evil.exe"
        assert Data.conforms(Lnk.SCHEMA, out) == []

    def test_no_overlay_is_size_zero_and_no_offset(self) -> None:
        out = Lnk.data(Shortcut.full())
        assert out["overlay_size"] == 0
        assert "overlay_offset" not in out

    @pytest.mark.parametrize(
        "file",
        [b"", b"not a shortcut", b"\x4c\x00\x00\x00" + b"\x00" * 72, Shortcut.header(0)[:75]],
    )
    def test_anything_else_is_not_a_shortcut(self, file: bytes) -> None:
        out = Lnk.data(file)
        assert out["is_lnk"] is False
        assert "file_size" not in out
        assert out["FILE_ATTRIBUTE_HIDDEN"] == 2  # the constants are there for every file

    def test_a_size_past_the_end_keeps_what_came_before(self) -> None:
        # CVE-2010-2568's shape: an ID list declaring more than the file holds, then nothing.
        flags = Lnk.ID_LIST | Lnk.NAME
        file = (
            Shortcut.header(flags)
            + struct.pack("<H", 0xFFFF)
            + Shortcut.item(b"\x00" + b"\x00" * 9 + b"x.cpl\x00")
        )
        out = Lnk.data(file)
        assert out["is_lnk"] is True and out["file_size"] == 1234
        assert out["target_id_list"][0]["item_type"] == 0x00
        assert out["target_id_list"][0]["cpl_file_path"] == b"x.cpl"
        assert "name" not in out  # the string data was never reached

    def test_a_shell_string_is_cut_at_260_characters(self) -> None:
        file = (
            Shortcut.header(Lnk.NAME | Lnk.UNICODE)
            + Shortcut.utf16("n" * 300)
            + struct.pack("<I", 0)
        )
        assert Lnk.data(file)["name"] == b"n" * 260

    def test_arguments_are_not_cut(self) -> None:
        file = (
            Shortcut.header(Lnk.ARGUMENTS | Lnk.UNICODE)
            + Shortcut.utf16("a" * 300)
            + struct.pack("<I", 0)
        )
        out = Lnk.data(file)
        assert out["cmd_line_args"] == b"a" * 300
        assert out["overlay_size"] == 0

    def test_ansi_text_is_utf8_with_bad_bytes_replaced(self) -> None:
        file = Shortcut.header(Lnk.NAME) + struct.pack("<H", 3) + b"a\xffb" + struct.pack("<I", 0)
        assert Lnk.data(file)["name"] == "a\ufffdb".encode()

    def test_an_unknown_item_type_is_its_own_byte(self) -> None:
        file = Shortcut.header(Lnk.ID_LIST) + Shortcut.id_list(b"\x99abc") + struct.pack("<I", 0)
        item = Lnk.data(file)["target_id_list"][0]
        assert (item["item_type"], item["data"]) == (0x99, b"abc")

    def test_random_bytes_after_a_header_never_raise(self) -> None:
        rng = random.Random(20261031)  # noqa: S311 -- fuzz input, not key material
        head = Shortcut.header(0xFF)
        for _ in range(2000):
            tail = bytes(rng.randrange(256) for _ in range(rng.randrange(200)))
            out = Lnk.data(head + tail)
            assert out["is_lnk"] is True
            assert Data.conforms(Lnk.SCHEMA, out) == []


class TestRules:
    def test_the_module_is_built_in(self) -> None:
        assert "lnk" in Builtin.modules()

    @pytest.mark.parametrize(
        "condition",
        [
            "lnk.is_lnk",
            'lnk.cmd_line_args contains "powershell"',
            "lnk.file_attributes & lnk.FILE_ATTRIBUTE_ARCHIVE != 0",
            "lnk.show_command == lnk.ShowCommand.NORMAL",
            "lnk.drive_type == lnk.DriveType.FIXED",
            'lnk.tracker_data.machine_id == "host-01"',
            "lnk.target_id_list[2].item_type == lnk.ShellItemType.FILE_ENTRY",
            'for any item in lnk.target_id_list : (item.file_entry_name == "evil.exe")',
            "lnk.overlay_size == 0",
        ],
    )
    def test_a_condition_reads_each_value(self, condition: str) -> None:
        assert Rules.compile(f'import "lnk" rule r {{ condition: {condition} }}').match(
            Shortcut.full()
        )

    def test_a_file_that_is_not_a_shortcut(self) -> None:
        rules = Rules.compile(
            'import "lnk" rule r { condition: not lnk.is_lnk and not defined lnk.name }'
        )
        assert rules.match(b"MZ plain")
