"""A compiled .NET assembly read through its metadata (`detect/dotnet_meta.py`, review 98).

The streams are built byte by byte as ECMA-335 II.24 lays them out: what is tested is that the
reader finds a referenced member by its owner and name, and a string literal from the user-string
heap -- the two things the C# rules read.
"""

from __future__ import annotations

import struct

from cordon_scanner.analysis.dotnet.dotnet_meta import DotNetMetadata


class Streams:
    @staticmethod
    def strings(*names: str) -> tuple[bytes, dict[str, int]]:
        heap = bytearray(b"\0")
        index: dict[str, int] = {}
        for name in names:
            index[name] = len(heap)
            heap += name.encode() + b"\0"
        return bytes(heap), index

    @staticmethod
    def tables(index: dict[str, int]) -> bytes:
        """`#~` with one TypeRef (System.Diagnostics.Process) and one MemberRef (Start) on it."""
        valid = (1 << 0x01) | (1 << 0x0A)
        header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
        rows = struct.pack("<II", 1, 1)
        # TypeRef: ResolutionScope (2), TypeName (2), TypeNamespace (2).
        type_ref = struct.pack("<HHH", 0, index["Process"], index["System.Diagnostics"])
        # MemberRef: Class = coded MemberRefParent (TypeRef is tag 1, row 1), Name, Signature.
        member_ref = struct.pack("<HHH", (1 << 3) | 1, index["Start"], 0)
        return header + rows + type_ref + member_ref

    @staticmethod
    def user_strings(*literals: str) -> bytes:
        heap = bytearray(b"\0")
        for literal in literals:
            body = literal.encode("utf-16-le") + b"\0"
            heap += bytes([len(body)]) + body
        return bytes(heap)


class TestTheReader:
    def test_a_referenced_member_is_found_by_owner_and_name(self):
        strings, index = Streams.strings("Process", "System.Diagnostics", "Start")
        tables = Streams.tables(index)
        data = tables + strings
        members = DotNetMetadata._member_refs(data, (0, len(tables)), (len(tables), len(strings)))
        assert members == [("System.Diagnostics", "Process", "Start")]

    def test_a_string_literal_is_read_from_the_user_string_heap(self):
        heap = Streams.user_strings("cmd /c echo hi", "https://example.invalid/x")
        assert DotNetMetadata._user_strings(heap, (0, len(heap))) == [
            "cmd /c echo hi",
            "https://example.invalid/x",
        ]

    def test_anything_that_is_not_an_assembly_has_no_view(self):
        assert DotNetMetadata.view(b"MZ" + b"\0" * 300) is None
        assert DotNetMetadata.view(b"\x7fELF" + b"\0" * 300) is None
        assert DotNetMetadata.view(b"") is None
