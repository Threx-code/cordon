"""The Windows shortcut (LNK) reader for cordon-rule: the `lnk` module's values as a condition sees them.

YARA has no `lnk` module; YARA-X has one, and rule collections written for it read these names. The schema
is YARA-X's (`lnk.proto` at v1.21.0) name for name, and what each value holds follows its reader, so a rule
answers the same here as there. The format is Microsoft's [MS-SHLLINK]; the shell items inside the target
ID list follow the reverse-engineered shell item format (libfwsi), decoded on a best-effort basis as the
reference does.

    SHELL_LINK = HEADER [LINKTARGET_IDLIST] [LINKINFO] [STRING_DATA] *EXTRA_DATA

A file whose 76-byte header is not a shortcut's answers `is_lnk` false and nothing else. A shortcut whose
body is damaged past the header keeps every value read before the damage, as the reference does: a
CVE-2010-2568 exploit declares sizes past the end of the file, and its header and shell items are still the
evidence. Text is UTF-8: an ANSI string decoded as UTF-8 with invalid bytes replaced, a UTF-16 string
decoded to its first NUL with unpaired surrogates replaced. Times are Unix seconds from FILETIME, undefined
for zero or before 1970.
"""

from __future__ import annotations

import contextlib
import uuid
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class Short(Exception):
    """A read past the end of the part being read: the reference stops there."""


class Stream:
    """A little-endian sequential read of `data[at:end]` through the file's Cursor."""

    __slots__ = ("at", "cur", "end")

    def __init__(self, cur: Cursor, at: int, end: int) -> None:
        self.cur, self.at, self.end = cur, at, end

    def uint(self, width: int) -> int:
        if self.at + width > self.end:
            raise Short
        value = self.cur.uint(self.at, width, "little")
        if value is ABSENT:
            raise Short
        self.at += width
        return int(value)

    def take(self, n: int) -> Stream:
        """The next `n` bytes as their own stream; this one moves past them."""
        if n < 0 or self.at + n > self.end:
            raise Short
        part = Stream(self.cur, self.at, self.at + n)
        self.at += n
        return part

    def rest(self, offset: int) -> Stream | None:
        """The part from `offset` to the end, or None when `offset` is past the end."""
        start = self.at + offset
        return Stream(self.cur, start, self.end) if start <= self.end else None

    def left(self) -> int:
        return self.end - self.at

    def raw(self) -> bytes:
        return self.cur.data[self.at : self.end]


class Text:
    """The two string forms a shortcut stores."""

    @staticmethod
    def ansi(s: Stream) -> bytes:
        """To the first NUL (or the end), invalid UTF-8 replaced."""
        data = s.raw()
        cut = data.find(b"\x00")
        return Text.utf8(data if cut < 0 else data[:cut])

    @staticmethod
    def utf16(s: Stream) -> bytes:
        """UTF-16LE to the first NUL code unit (or the last whole one), unpaired surrogates replaced."""
        data = s.raw()
        end = len(data) - len(data) % 2
        for i in range(0, end, 2):
            if data[i] == 0 and data[i + 1] == 0:
                end = i
                break
        return data[:end].decode("utf-16-le", "replace").encode("utf-8")

    @staticmethod
    def utf8(data: bytes) -> bytes:
        return data.decode("utf-8", "replace").encode("utf-8")

    @staticmethod
    def guid(s: Stream | None) -> bytes | None:
        """A GUID stored little-endian in its first three fields, as lowercase hyphenated text."""
        if s is None or s.left() < 16:
            return None
        return str(uuid.UUID(bytes_le=s.raw()[:16])).encode()


class Lnk:
    """The `lnk` module reader."""

    FILE_ATTRIBUTES: ClassVar[dict[str, int]] = {
        "FILE_ATTRIBUTE_READONLY": 0x1, "FILE_ATTRIBUTE_HIDDEN": 0x2, "FILE_ATTRIBUTE_SYSTEM": 0x4,
        "RESERVED_1": 0x8, "FILE_ATTRIBUTE_DIRECTORY": 0x10, "FILE_ATTRIBUTE_ARCHIVE": 0x20,
        "RESERVED_2": 0x40, "FILE_ATTRIBUTE_NORMAL": 0x80, "FILE_ATTRIBUTE_TEMPORARY": 0x100,
        "FILE_ATTRIBUTE_SPARSE_FILE": 0x200, "FILE_ATTRIBUTE_REPARSE_POINT": 0x400,
        "FILE_ATTRIBUTE_COMPRESSED": 0x800, "FILE_ATTRIBUTE_OFFLINE": 0x1000,
        "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED": 0x2000, "FILE_ATTRIBUTE_ENCRYPTED": 0x4000,
    }  # fmt: skip
    ENUMS: ClassVar[dict[str, dict[str, int]]] = {
        "ShowCommand": {"NORMAL": 1, "MAXIMIZED": 3, "MIN_NO_ACTIVE": 7},
        "DriveType": {
            "UNKNOWN": 0, "NO_ROOT_DIR": 1, "REMOVABLE": 2, "FIXED": 3, "REMOTE": 4, "CDROM": 5,
            "RAMDISK": 6,
        },
        "ShellItemType": {
            "CONTROL_PANEL_CPL": 0x00, "CONTROL_PANEL_CATEGORY": 0x01, "ROOT_FOLDER": 0x1F,
            "VOLUME": 0x20, "FILE_ENTRY": 0x30, "NETWORK_LOCATION": 0x40, "COMPRESSED_FOLDER": 0x52,
            "URI": 0x61, "CONTROL_PANEL": 0x71, "PRINTERS": 0x72, "COMMON_PLACES_FOLDER": 0x73,
            "USERS_FILES_FOLDER": 0x74,
        },
    }  # fmt: skip

    _tracker = Record(
        {"version": INT, **dict.fromkeys(
            ("machine_id", "droid_volume_id", "droid_file_id", "droid_birth_volume_id",
             "droid_birth_file_id"), TEXT,
        )}
    )  # fmt: skip
    _item = Record({
        "item_type": INT, "data": TEXT,
        **dict.fromkeys(
            ("cpl_file_path", "root_folder_id", "volume_name", "volume_id", "file_entry_name",
             "network_location"), TEXT,
        ),
    })  # fmt: skip
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(FILE_ATTRIBUTES, INT),
        **{name: Record(dict.fromkeys(values, INT)) for name, values in ENUMS.items()},
        "is_lnk": BOOL,
        **dict.fromkeys(
            ("name", "icon_location", "volume_label", "local_base_path", "common_path_suffix",
             "relative_path", "working_dir", "cmd_line_args"), TEXT,
        ),
        **dict.fromkeys(
            ("creation_time", "access_time", "write_time", "file_size", "file_attributes",
             "icon_index", "show_command", "drive_type", "drive_serial_number", "overlay_size",
             "overlay_offset"), INT,
        ),
        "tracker_data": _tracker,
        "target_id_list": Seq(_item),
    })  # fmt: skip

    HEADER_SIZE: ClassVar[int] = 0x4C
    CLSID: ClassVar[bytes] = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
    #: The LinkFlags bits the reader looks at (MS-SHLLINK 2.1.1).
    ID_LIST, LINK_INFO, NAME, RELATIVE, WORKING, ARGUMENTS, ICON, UNICODE = (
        1 << i for i in range(8)
    )
    #: Strings the shell itself cuts at 260 characters (yara-x issue 379); arguments are not cut.
    SHELL_LIMIT: ClassVar[int] = 260
    TRACKER: ClassVar[int] = 0xA0000003
    UNIX_FROM_FILETIME: ClassVar[int] = 11644473600

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = dict(Lnk.FILE_ATTRIBUTES)  # the constants are there for every file
        out.update({name: dict(values) for name, values in Lnk.ENUMS.items()})
        out["target_id_list"] = {}
        cur = Cursor(file)
        if len(file) < Lnk.HEADER_SIZE or cur.uint(0, 4, "little") != Lnk.HEADER_SIZE:
            out["is_lnk"] = False
            return out
        if file[4:20] != Lnk.CLSID:
            out["is_lnk"] = False
            return out
        s = Stream(cur, 20, len(file))
        flags, attributes = s.uint(4), s.uint(4)
        times = [s.uint(8) for _ in range(3)]
        file_size, icon_index, show = s.uint(4), s.uint(4), s.uint(4)
        s.uint(2 + 2 + 4 + 4)  # hot key and the reserved fields
        out.update(
            is_lnk=True, file_attributes=attributes, file_size=file_size, icon_index=icon_index
        )
        for name, value in zip(("creation_time", "access_time", "write_time"), times, strict=True):
            seconds = value // 10_000_000 - Lnk.UNIX_FROM_FILETIME
            if seconds >= 0:
                out[name] = seconds
        if show < 1 << 31:
            out["show_command"] = show
        with contextlib.suppress(Short):  # what was read before the damage stands
            Lnk._body(out, s, flags, len(file))
        return out

    @staticmethod
    def _body(out: dict[str, Any], s: Stream, flags: int, total: int) -> None:
        if flags & Lnk.ID_LIST:
            Lnk._id_list(out, s)
        if flags & Lnk.LINK_INFO:
            Lnk._link_info(out, s)
        unicode = bool(flags & Lnk.UNICODE)
        for bit, name, limit in (
            (Lnk.NAME, "name", Lnk.SHELL_LIMIT),
            (Lnk.RELATIVE, "relative_path", Lnk.SHELL_LIMIT),
            (Lnk.WORKING, "working_dir", Lnk.SHELL_LIMIT),
            (Lnk.ARGUMENTS, "cmd_line_args", None),
            (Lnk.ICON, "icon_location", Lnk.SHELL_LIMIT),
        ):
            if flags & bit:
                length = s.uint(2)
                if limit is not None:
                    length = min(length, limit)
                part = s.take(length * 2 if unicode else length)
                out[name] = Text.utf16(part) if unicode else Text.utf8(part.raw())
        Lnk._extra_data(out, s, total)

    @staticmethod
    def _id_list(out: dict[str, Any], s: Stream) -> None:
        """The shell items; a declared size past the end is cut to what is there."""
        size = s.uint(2)
        items = s.take(min(size, s.left()))
        seq = out["target_id_list"]
        while items.left() >= 2:
            item_size = items.uint(2)
            if item_size == 0:
                break
            item = items.take(min(max(item_size - 2, 0), items.left()))
            parsed = Lnk._shell_item(item)
            if parsed is not None:
                seq[len(seq)] = parsed

    @staticmethod
    def _shell_item(item: Stream) -> dict[str, Any] | None:
        data = item.raw()
        if not data:
            return None
        cls = data[0]
        out: dict[str, Any] = {"data": data[1:], "item_type": Lnk._item_type(cls)}
        if cls == 0x00:
            if len(data) > 10:
                if data[10] == 0:
                    if len(data) >= 22:
                        out["cpl_file_path"] = Text.utf16(item.rest(22) or item)
                else:
                    out["cpl_file_path"] = Text.ansi(item.rest(10) or item)
        elif cls in (0x1E, 0x1F):
            Lnk._put(out, "root_folder_id", Text.guid(item.rest(2)))
        elif cls & 0x70 == 0x20:
            if cls & 0x01:
                if len(data) >= 21:
                    out["volume_name"] = Text.ansi(Stream(item.cur, item.at + 1, item.at + 21))
            else:
                Lnk._put(out, "volume_id", Text.guid(item.rest(2)))
        elif cls & 0x70 == 0x30:
            if len(data) >= 12:
                rest = item.rest(12) or item
                out["file_entry_name"] = Text.utf16(rest) if cls & 0x04 else Text.ansi(rest)
        elif cls & 0x70 == 0x40 and len(data) >= 3:
            out["network_location"] = Text.ansi(item.rest(3) or item)
        return out

    @staticmethod
    def _item_type(cls: int) -> int:
        """The category a class type indicator names, or the indicator itself when it names none."""
        masked = cls & 0x70
        if masked in (0x20, 0x30, 0x40):
            return masked
        known = {0x00: 0x00, 0x01: 0x01, 0x1E: 0x1F, 0x1F: 0x1F, 0x52: 0x52, 0x61: 0x61,
                 0x70: 0x71, 0x71: 0x71, 0x72: 0x72, 0x73: 0x73, 0x74: 0x74}  # fmt: skip
        return known.get(cls, cls)

    @staticmethod
    def _link_info(out: dict[str, Any], s: Stream) -> None:
        start = Stream(s.cur, s.at, s.end)
        size, header, flags, volume_at, base_at, _network_at, suffix_at = (
            start.uint(4) for _ in range(7)
        )
        base_unicode = start.uint(4) if header >= 0x24 else None
        suffix_unicode = start.uint(4) if header >= 0x24 else None
        info = s.take(size)
        if flags & 0x1:
            volume = info.rest(volume_at)
            if volume is not None:
                with contextlib.suppress(Short):  # what was read before the damage stands
                    Lnk._volume(out, volume)
            Lnk._path(out, "local_base_path", info, base_unicode, base_at)
        if flags & 0x2:
            Lnk._path(out, "common_path_suffix", info, suffix_unicode, suffix_at)

    @staticmethod
    def _path(
        out: dict[str, Any], name: str, info: Stream, unicode_at: int | None, at: int
    ) -> None:
        if unicode_at is not None and unicode_at > 0:
            part = info.rest(unicode_at)
            if part is not None:
                out[name] = Text.utf16(part)
        else:
            part = info.rest(at)
            if part is not None:
                out[name] = Text.ansi(part)

    @staticmethod
    def _volume(out: dict[str, Any], s: Stream) -> None:
        start = Stream(s.cur, s.at, s.end)
        size, drive, serial, label_at = (start.uint(4) for _ in range(4))
        if drive < 1 << 31:
            out["drive_type"] = drive
        out["drive_serial_number"] = serial
        volume = s.take(size)
        if label_at == 0x14:
            label_at = start.uint(4)
            part = volume.rest(label_at)
            if part is not None:
                out["volume_label"] = Text.utf16(part)
        else:
            part = volume.rest(label_at)
            if part is not None:
                out["volume_label"] = Text.ansi(part)

    @staticmethod
    def _extra_data(out: dict[str, Any], s: Stream, total: int) -> None:
        """Blocks until the terminal one (a size under 4); what follows it is the overlay. Without a
        terminal block, or with a block past the end, there is no overlay value."""
        while True:
            if s.left() < 4:
                return
            size = s.cur.uint(s.at, 4, "little")
            if size < 4:
                s.uint(4)
                break
            if size > s.left():
                return
            block = s.take(size)
            block.uint(4)
            if block.left() >= 4 and block.cur.uint(block.at, 4, "little") == Lnk.TRACKER:
                block.uint(4)
                with contextlib.suppress(Short):  # what was read before the damage stands
                    Lnk._tracker_data(out, block)
        overlay = s.left()
        out["overlay_size"] = overlay
        if overlay:
            out["overlay_offset"] = total - overlay

    @staticmethod
    def _tracker_data(out: dict[str, Any], s: Stream) -> None:
        s.uint(4)  # length
        version = s.uint(4)
        machine = Text.ansi(s.take(16))
        ids = [Text.guid(s.take(16)) for _ in range(4)]
        out["tracker_data"] = {
            "version": version,
            "machine_id": machine,
            **dict(
                zip(
                    (
                        "droid_volume_id",
                        "droid_file_id",
                        "droid_birth_volume_id",
                        "droid_birth_file_id",
                    ),
                    ids,
                    strict=True,
                )
            ),
        }

    @staticmethod
    def _put(out: dict[str, Any], name: str, value: bytes | None) -> None:
        if value is not None:
            out[name] = value


__all__ = ["Lnk"]
