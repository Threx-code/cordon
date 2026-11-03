"""Inert MSVC import libraries, laid out as the linker writes them (notes/75 fix 2).

An import library (`.lib`) is an `ar` archive: two linker members (`/`), three COFF descriptor objects
and one short import stub per function, every member named for the DLL it imports from. Measured on
sharp's libvips.lib, npcap's Packet.lib and tree-sitter's parser.lib. These carry names and fixed-size
tables only: no code section and nothing that runs.
"""

from __future__ import annotations

import struct

I386, AMD64 = 0x14C, 0x8664
DEBUG, IDATA, IDATA6 = 0x42100040, 0xC0300040, 0xC0200040
TEXT = 0x60000020
"""A code section's flags (code, execute, read): what no descriptor object has."""


class ImportLibKit:
    """Builders for import-library members and archives."""

    @staticmethod
    def stub(symbol: str, dll: str, machine: int = I386, *, tail: bytes = b"") -> bytes:
        """A short import object: the 20-byte header, then the symbol and DLL names."""
        data = symbol.encode() + b"\x00" + dll.encode() + b"\x00"
        header = struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, machine, 0, len(data), 0, 0x0004)
        return header + data + tail

    @staticmethod
    def coff(
        machine: int,
        sections: list[tuple[str, bytes, int, int]],
        symbols: list[tuple[str, int, int]],
        *,
        tail: bytes = b"",
    ) -> bytes:
        """A COFF object: (name, data, relocations, flags) sections and (name, section, class)
        symbols, laid out header, section table, raw data, relocations, symbols, strings."""
        table = 20 + 40 * len(sections)
        raw, relocs, at = b"", b"", table
        heads = []
        for name, data, nrel, flags in sections:
            heads.append([name, len(data), at if data else 0, nrel, flags])
            raw += data
            at += len(data)
        for head in heads:
            head.append(at + len(relocs) if head[3] else 0)
            relocs += b"".join(struct.pack("<IIH", 0, 1, 7) for _ in range(head[3]))
        strings, entries = b"", b""
        for name, section, storage in symbols:
            encoded = name.encode("latin-1")
            if len(encoded) <= 8:
                field = encoded.ljust(8, b"\x00")
            else:
                field = struct.pack("<II", 0, 4 + len(strings))
                strings += encoded + b"\x00"
            entries += field + struct.pack("<IhHBB", 0, section, 0, storage, 0)
        symtab = table + len(raw) + len(relocs)
        header = struct.pack("<HHIIIHH", machine, len(sections), 0, symtab, len(symbols), 0, 0)
        section_table = b"".join(
            name.encode().ljust(8, b"\x00")
            + struct.pack("<IIIIIIHHI", 0, 0, size, ptr, rel_ptr, 0, nrel, 0, flags)
            for name, size, ptr, nrel, flags, rel_ptr in heads
        )
        body = header + section_table + raw + relocs + entries
        return body + struct.pack("<I", 4 + len(strings)) + strings + tail

    @staticmethod
    def debug() -> bytes:
        """A `.debug$S` as the linker writes one: CodeView signature 2, then a short record."""
        return struct.pack("<I", 2) + b"\x00" * 56

    @staticmethod
    def descriptors(dll: str, machine: int = I386) -> list[bytes]:
        """The three descriptor objects: the import descriptor, the null descriptor, the null thunk."""
        base = dll.rsplit(".", 1)[0]
        word = 8 if machine == AMD64 else 4
        name = dll.encode() + b"\x00"
        name += b"\x00" * (len(name) & 1)
        flags = 0xC0400040 if word == 8 else IDATA
        return [
            ImportLibKit.coff(
                machine,
                [
                    (".debug$S", ImportLibKit.debug(), 0, DEBUG),
                    (".idata$2", b"\x00" * 20, 3, IDATA),
                    (".idata$6", name, 0, IDATA6),
                ],
                [
                    ("@comp.id", -1, 3),
                    (f"__IMPORT_DESCRIPTOR_{base}", 2, 2),
                    (".idata$2", 2, 104),
                    (".idata$6", 3, 3),
                    (".idata$4", 0, 104),
                    (".idata$5", 0, 104),
                    ("__NULL_IMPORT_DESCRIPTOR", 0, 2),
                    (f"\x7f{base}_NULL_THUNK_DATA", 0, 2),
                ],
            ),
            ImportLibKit.coff(
                machine,
                [
                    (".debug$S", ImportLibKit.debug(), 0, DEBUG),
                    (".idata$3", b"\x00" * 20, 0, IDATA),
                ],
                [("@comp.id", -1, 3), ("__NULL_IMPORT_DESCRIPTOR", 2, 2)],
            ),
            ImportLibKit.coff(
                machine,
                [
                    (".debug$S", ImportLibKit.debug(), 0, DEBUG),
                    (".idata$5", b"\x00" * word, 0, flags),
                    (".idata$4", b"\x00" * word, 0, flags),
                ],
                [("@comp.id", -1, 3), (f"\x7f{base}_NULL_THUNK_DATA", 2, 2)],
            ),
        ]

    @staticmethod
    def header(name: bytes, size: int) -> bytes:
        return (
            name.ljust(16)
            + b"0".ljust(12)
            + b"".ljust(6)
            + b"".ljust(6)
            + b"0".ljust(8)
            + str(size).encode().ljust(10)
            + b"`\n"
        )

    @staticmethod
    def archive(
        members: list[tuple[bytes, bytes]], *, linkers: int = 2, tail: bytes = b""
    ) -> bytes:
        """An ar archive: the linker members (one symbol per member, pointing at it), then
        `members` as (ar name, body)."""
        table = b""
        named = []
        for name, body in members:
            if len(name) > 16:  # a GNU long name, `/offset` into the `//` member
                at = table.find(name + b"\n")
                if at < 0:
                    at, table = len(table), table + name + b"\n"
                name = b"/%d" % at
            named.append((name, body))
        members = named
        symbols = [b"sym%d" % i for i in range(len(members))]
        names = b"".join(s + b"\x00" for s in symbols)
        first_size = 4 + 4 * len(members) + len(names)
        second_size = 4 + 4 * len(members) + 4 + 2 * len(members) + len(names)
        sizes = [first_size, second_size][:linkers] + ([len(table)] if table else [])
        at = 8 + sum(60 + s + (s & 1) for s in sizes)
        offsets = []
        for _name, body in members:
            offsets.append(at)
            at += 60 + len(body) + (len(body) & 1)
        first = struct.pack(f">I{len(offsets)}I", len(offsets), *offsets) + names
        second = (
            struct.pack(f"<I{len(offsets)}I", len(offsets), *offsets)
            + struct.pack(f"<I{len(offsets)}H", len(offsets), *range(1, len(offsets) + 1))
            + names
        )
        out = b"!<arch>\n"
        for body in [first, second][:linkers]:
            out += ImportLibKit.header(b"/", len(body)) + body + b"\n" * (len(body) & 1)
        if table:
            out += ImportLibKit.header(b"//", len(table)) + table + b"\n" * (len(table) & 1)
        for name, body in members:
            out += ImportLibKit.header(name, len(body)) + body + b"\n" * (len(body) & 1)
        return out + tail

    @staticmethod
    def library(
        dll: str = "jc.dll",
        functions: tuple[str, ...] = ("jc_open", "jc_close"),
        machine: int = I386,
    ) -> bytes:
        """A whole import library for `dll`, as the linker lays one out."""
        name = dll.encode() + b"/"
        members = [(name, body) for body in ImportLibKit.descriptors(dll, machine)]
        members += [(name, ImportLibKit.stub(f, dll, machine)) for f in functions]
        return ImportLibKit.archive(members)


__all__ = ["AMD64", "I386", "TEXT", "ImportLibKit"]
