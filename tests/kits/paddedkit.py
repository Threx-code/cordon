"""Inert binaries whose telling part sits past a padding (note 74's killer probe).

A binary padded past `limits.max_file_bytes` hid from every binary reader, which read only its first
10 MiB. These are structurally valid PE and ELF files built in memory: headers, a section table, zero
padding, then the section the readers need (an import table naming the process-injection calls, or a
marker string). No code, nothing that runs: a loader would find no entry point to call.
"""

from __future__ import annotations

import struct

PAD: int = 11 * 1024 * 1024
"""Past the default limits.max_file_bytes (10 MiB)."""
INJECTION: dict[str, list[str]] = {
    "kernel32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
}


class PaddedKit:
    """Builders for padded, inert binaries."""

    @staticmethod
    def pe(
        imports: dict[str, list[str]] | None = None, *, pad: int = PAD, marker: bytes = b""
    ) -> bytes:
        """A PE32 whose one section (.idata, the imports) starts at file offset `pad` + 0x200."""
        imports = imports if imports is not None else INJECTION
        section_rva, section_raw = 0x1000, 0x200 + pad
        descriptor_count = len(imports) + 1
        desc_size = descriptor_count * 20
        layout = bytearray(desc_size)
        thunks_start = desc_size
        cursor = thunks_start + sum((len(f) + 1) * 4 for f in imports.values())
        thunk_cursor, thunk_blobs, name_blobs, descriptors = thunks_start, [], [], []
        for dll, functions in imports.items():
            thunk = b""
            for function in functions:
                entry = struct.pack("<H", 0) + function.encode() + b"\x00"
                thunk += struct.pack("<I", section_rva + cursor)
                name_blobs.append(entry)
                cursor += len(entry)
            thunk += struct.pack("<I", 0)
            dll_rva = section_rva + cursor
            dll_blob = dll.encode() + b"\x00"
            name_blobs.append(dll_blob)
            cursor += len(dll_blob)
            descriptors.append((section_rva + thunk_cursor, dll_rva))
            thunk_blobs.append(thunk)
            thunk_cursor += len(thunk)
        for i, (thunk_rva, dll_rva) in enumerate(descriptors):
            layout[i * 20 : i * 20 + 20] = struct.pack(
                "<IIIII", thunk_rva, 0, 0, dll_rva, thunk_rva
            )
        section = bytes(layout) + b"".join(thunk_blobs) + b"".join(name_blobs) + marker
        dos = (b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)).ljust(0x80, b"\x00")
        coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional = bytearray(224)
        struct.pack_into("<H", optional, 0, 0x10B)
        struct.pack_into("<II", optional, 96 + 8, section_rva, desc_size)
        header = b".idata\x00\x00" + struct.pack(
            "<IIIIIIHHI", len(section), section_rva, len(section), section_raw, 0, 0, 0, 0, 0
        )
        head = (dos + coff + bytes(optional) + header).ljust(0x200, b"\x00")
        return head + b"\x00" * pad + section

    @staticmethod
    def elf(symbols: list[str], needed: list[str], *, pad: int = PAD) -> bytes:
        """An ELF64 whose dynamic string, symbol and dynamic sections start past `pad` bytes of zeros."""
        dynstr, offsets = b"\x00", {}
        for name in [*needed, *symbols]:
            offsets[name] = len(dynstr)
            dynstr += name.encode() + b"\x00"
        dynsym = b"\x00" * 24 + b"".join(
            struct.pack("<IBBHQQ", offsets[s], 0x12, 0, 0, 0, 0) for s in symbols
        )
        dynamic = b"".join(struct.pack("<qQ", 1, offsets[n]) for n in needed) + struct.pack(
            "<qQ", 0, 0
        )
        header_size = 64
        str_off = header_size + pad
        sym_off = str_off + len(dynstr)
        dyn_off = sym_off + len(dynsym)
        shoff = dyn_off + len(dynamic)
        sections = [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(dynstr), 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", 0, 11, 0, 0, sym_off, len(dynsym), 1, 1, 8, 24),
            struct.pack("<IIQQQQIIQQ", 0, 6, 0, 0, dyn_off, len(dynamic), 1, 0, 8, 16),
        ]
        ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), 0
        )
        return header + b"\x00" * pad + dynstr + dynsym + dynamic + b"".join(sections)


__all__ = ["INJECTION", "PAD", "PaddedKit"]
