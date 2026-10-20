"""What a compiled .NET assembly calls and the literals it carries, read from its metadata.

NuGet packages ship compiled assemblies. The malicious ones of 2023-2025 (review 98: 22 of 23
real releases still served by NuGet) carry their payload in a DLL: the source the C# rules read
is not in the package at all, so the scan saw nothing but a binary. Yet a .NET assembly keeps a
readable record of exactly what the rules look for -- every type and member it references
(`System.Net.WebClient::DownloadString`, `System.Diagnostics.Process::Start`,
`System.Reflection.Assembly::Load`) and every string literal its code uses (the URL, the command,
the path), in the metadata tables and the user-string heap ECMA-335 defines.

```
  PE headers ──► CLI header (data directory 14) ──► metadata root ──► streams
                                                                      ├── #~        tables: TypeRef, MemberRef
                                                                      ├── #Strings  their names
                                                                      └── #US       the code's string literals
                                         │
                                         ▼
  a C#-shaped view:   Process.Start(   new WebClient(   WebClient.DownloadString(   "https://..."
                      read by the same `capabilities-dotnet` rules that read C# source
```

Read only; nothing is loaded or run. Bounded: tables and heaps past their declared sizes are not
read, and any inconsistency returns no view rather than a guess.
"""

from __future__ import annotations

import struct
from typing import Final

MAX_STRINGS: Final = 20_000
MAX_MEMBERS: Final = 50_000
MAX_LITERAL: Final = 2_000

# Table numbers (ECMA-335 II.22) and the columns of each table before MemberRef.
MODULE, TYPEREF, TYPEDEF, FIELDPTR, FIELD, METHODPTR, METHODDEF = (
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
)
PARAMPTR, PARAM, INTERFACEIMPL, MEMBERREF, MODULEREF, TYPESPEC = 0x07, 0x08, 0x09, 0x0A, 0x1A, 0x1B


class _Bytes:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]


class DotNetMetadata:
    @staticmethod
    def is_assembly(data: bytes) -> bool:
        return DotNetMetadata._metadata_offset(data) is not None

    @staticmethod
    def _metadata_offset(data: bytes) -> tuple[int, int, list[tuple[int, int, int]]] | None:
        """(file offset of the metadata root, its size, sections) or None for anything else."""
        if len(data) < 0x100 or data[:2] != b"MZ":
            return None
        b = _Bytes(data)
        pe = b.u32(0x3C)
        if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
            return None
        sections_count = b.u16(pe + 6)
        optional_size = b.u16(pe + 20)
        optional = pe + 24
        magic = b.u16(optional)
        directories = optional + (96 if magic == 0x10B else 112 if magic == 0x20B else 0)
        if not directories or directories + 15 * 8 > len(data):
            return None
        cli_rva, cli_size = b.u32(directories + 14 * 8), b.u32(directories + 14 * 8 + 4)
        if not cli_rva or not cli_size:
            return None
        sections: list[tuple[int, int, int]] = []
        table = optional + optional_size
        for index in range(min(sections_count, 96)):
            entry = table + index * 40
            if entry + 40 > len(data):
                return None
            virtual_size, virtual_address = b.u32(entry + 8), b.u32(entry + 12)
            raw_size, raw_pointer = b.u32(entry + 16), b.u32(entry + 20)
            sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

        def offset_of(rva: int) -> int | None:
            for start, size, raw in sections:
                if start <= rva < start + size:
                    return rva - start + raw
            return None

        cli = offset_of(cli_rva)
        if cli is None or cli + 16 > len(data):
            return None
        meta_rva, meta_size = b.u32(cli + 8), b.u32(cli + 12)
        root = offset_of(meta_rva)
        if root is None or root + meta_size > len(data) or b.u32(root) != 0x424A5342:
            return None
        return root, meta_size, sections

    @staticmethod
    def _streams(data: bytes, root: int, size: int) -> dict[str, tuple[int, int]]:
        b = _Bytes(data)
        version_length = b.u32(root + 12)
        cursor = root + 16 + version_length
        count = b.u16(cursor + 2)
        cursor += 4
        streams: dict[str, tuple[int, int]] = {}
        for _ in range(min(count, 16)):
            offset, length = b.u32(cursor), b.u32(cursor + 4)
            end = data.index(b"\0", cursor + 8, cursor + 8 + 40)
            name = data[cursor + 8 : end].decode("ascii", "replace")
            cursor = (end + 4) & ~3
            if offset + length <= size:
                streams[name] = (root + offset, length)
        return streams

    @staticmethod
    def _string(data: bytes, heap: tuple[int, int], index: int) -> str:
        start, length = heap
        if index >= length:
            return ""
        end = data.find(b"\0", start + index, start + length)
        return data[start + index : end if end >= 0 else start + length].decode("utf-8", "replace")

    @staticmethod
    def _user_strings(data: bytes, heap: tuple[int, int]) -> list[str]:
        start, length = heap
        out: list[str] = []
        cursor = start + 1
        end = start + length
        while cursor < end and len(out) < MAX_STRINGS:
            first = data[cursor]
            if first & 0x80 == 0:
                size, cursor = first, cursor + 1
            elif first & 0xC0 == 0x80:
                size, cursor = ((first & 0x3F) << 8) | data[cursor + 1], cursor + 2
            else:
                size = ((first & 0x1F) << 24) | (data[cursor + 1] << 16)
                size |= (data[cursor + 2] << 8) | data[cursor + 3]
                cursor += 4
            if size == 0:
                continue
            text = data[cursor : cursor + size - 1].decode("utf-16-le", "replace")
            cursor += size
            if text.strip():
                out.append(text[:MAX_LITERAL])
        return out

    @classmethod
    def references(cls, data: bytes) -> tuple[list[tuple[str, str, str]], list[str]] | None:
        """([(namespace, type, member)], [string literals]) or None when not an assembly."""
        located = cls._metadata_offset(data)
        if located is None:
            return None
        root, size, _ = located
        try:
            streams = cls._streams(data, root, size)
            tables = streams.get("#~") or streams.get("#-")
            strings = streams.get("#Strings")
            if tables is None or strings is None:
                return None
            members = cls._member_refs(data, tables, strings)
            literals = cls._user_strings(data, streams["#US"]) if "#US" in streams else []
        except (struct.error, IndexError, ValueError):
            return None
        return members, literals

    @classmethod
    def _member_refs(
        cls, data: bytes, tables: tuple[int, int], strings: tuple[int, int]
    ) -> list[tuple[str, str, str]]:
        b = _Bytes(data)
        start, _ = tables
        heap_sizes = data[start + 6]
        valid = struct.unpack_from("<Q", data, start + 8)[0]
        cursor = start + 24
        rows = [0] * 64
        for number in range(64):
            if valid >> number & 1:
                rows[number] = b.u32(cursor)
                cursor += 4
        string_index = 4 if heap_sizes & 1 else 2
        guid_index = 4 if heap_sizes & 2 else 2
        blob_index = 4 if heap_sizes & 4 else 2

        def index(table: int) -> int:
            return 4 if rows[table] >= 1 << 16 else 2

        def coded(bits: int, *targets: int) -> int:
            return 4 if max(rows[t] for t in targets) >= 1 << (16 - bits) else 2

        resolution_scope = coded(2, MODULE, MODULEREF, 0x23, TYPEREF)  # 0x23 AssemblyRef
        type_def_or_ref = coded(2, TYPEDEF, TYPEREF, TYPESPEC)
        member_ref_parent = coded(3, TYPEDEF, TYPEREF, MODULEREF, METHODDEF, TYPESPEC)
        widths = {
            MODULE: 2 + string_index + 3 * guid_index,
            TYPEREF: resolution_scope + 2 * string_index,
            TYPEDEF: 4 + 2 * string_index + type_def_or_ref + index(FIELD) + index(METHODDEF),
            FIELDPTR: index(FIELD),
            FIELD: 2 + string_index + blob_index,
            METHODPTR: index(METHODDEF),
            METHODDEF: 4 + 2 + 2 + string_index + blob_index + index(PARAM),
            PARAMPTR: index(PARAM),
            PARAM: 2 + 2 + string_index,
            INTERFACEIMPL: index(TYPEDEF) + type_def_or_ref,
            MEMBERREF: member_ref_parent + string_index + blob_index,
        }
        offsets: dict[int, int] = {}
        for number in range(MEMBERREF + 1):
            offsets[number] = cursor
            cursor += rows[number] * widths[number]

        def read(offset: int, width: int) -> int:
            return b.u16(offset) if width == 2 else b.u32(offset)

        type_refs: list[tuple[str, str]] = []
        for row in range(min(rows[TYPEREF], MAX_MEMBERS)):
            at = offsets[TYPEREF] + row * widths[TYPEREF] + resolution_scope
            name = cls._string(data, strings, read(at, string_index))
            space = cls._string(data, strings, read(at + string_index, string_index))
            type_refs.append((space, name))
        type_defs: list[tuple[str, str]] = []
        for row in range(min(rows[TYPEDEF], MAX_MEMBERS)):
            at = offsets[TYPEDEF] + row * widths[TYPEDEF] + 4
            name = cls._string(data, strings, read(at, string_index))
            space = cls._string(data, strings, read(at + string_index, string_index))
            type_defs.append((space, name))
        members: list[tuple[str, str, str]] = []
        for row in range(min(rows[MEMBERREF], MAX_MEMBERS)):
            at = offsets[MEMBERREF] + row * widths[MEMBERREF]
            parent = read(at, member_ref_parent)
            name = cls._string(data, strings, read(at + member_ref_parent, string_index))
            tag, target = parent & 7, (parent >> 3) - 1
            owner = (
                type_refs[target]
                if tag == 1 and 0 <= target < len(type_refs)
                else type_defs[target]
                if tag == 0 and 0 <= target < len(type_defs)
                else ("", "")
            )
            members.append((owner[0], owner[1], name))
        return members

    @classmethod
    def view(cls, data: bytes) -> str | None:
        """The assembly as the C# rules read it: one referenced member per line, as a call, then
        each string literal its code uses, quoted. None for anything that is not an assembly."""
        found = cls.references(data)
        if found is None:
            return None
        members, literals = found
        lines = ["// .NET metadata: the members this assembly calls, then its string literals"]
        seen: set[str] = set()
        for space, owner, member in members:
            if not owner or not member:
                continue
            short = owner.split("`", 1)[0]
            qualified = f"{space}.{short}" if space else short
            call = f"new {short}(" if member == ".ctor" else f"{short}.{member}("
            line = f"{call}  // {qualified}"
            if line not in seen:
                seen.add(line)
                lines.append(line)
        for literal in literals:
            escaped = literal.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'"{escaped}"')
        return "\n".join(lines) + "\n"


__all__ = ["DotNetMetadata"]
