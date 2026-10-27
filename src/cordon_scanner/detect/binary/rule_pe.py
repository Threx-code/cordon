"""The PE reader for cordon-rule: the `pe` module's values as a condition sees them.

A Portable Executable is read from the MS-DOS stub (the `e_lfanew` pointer at 0x3C) to the PE signature,
the COFF file header, the optional header (PE32 or PE32+), the data directories, and the section table;
from there the import, delayed-import and export tables, resources and their version information, the Rich
stub, the debug directory's CodeView path, and the certificate table. Every read is bounded against the
file: a table is walked only where its directory points and only as far as the file actually reaches, and a
field that cannot be read is left undefined. Addresses are virtual (RVAs); `Image.rva_to_offset` maps them
to file offsets through the section table, and an address outside every section has no offset.

Values follow the published PE/COFF layout. Named constants and the import-ordinal tables come from
``rule_tables``; the signature values from the certificate parser; the ELF import digest is in ``rule_elf``.
Shapes a rule can read (the schema) are declared up front, all undefined, so a file that is not a PE, or one
whose later structures do not fit, still answers every field.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import struct
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_tables import Tables
from cordon_scanner.detect.binary.rule_values import (
    UNDEF_INT,
    UNDEF_STR,
    Array,
    Dictionary,
    Struct,
    Values,
)
from cordon_scanner.detect.binary.yara_authenticode import Authenticode


class Reader:
    """A bounded view over the file bytes: a read that would fall outside returns None."""

    @staticmethod
    def or_undefined(value: Any, undef: Any = UNDEF_INT) -> Any:
        return undef if value is None else value

    def __init__(self, data: bytes) -> None:
        self.data = data

    def at(self, fmt: str, where: int) -> tuple[Any, ...] | None:
        size = struct.calcsize(fmt)
        if where < 0 or where + size > len(self.data):
            return None
        return struct.unpack_from(fmt, self.data, where)

    def one(self, fmt: str, where: int) -> Any:
        got = self.at(fmt, where)
        return None if got is None else got[0]

    def cstring(self, where: int, limit: int = 4096) -> bytes | None:
        if where < 0 or where >= len(self.data):
            return None
        end = self.data.find(b"\x00", where, where + limit)
        return self.data[where : end if end >= 0 else min(len(self.data), where + limit)]


class Image:
    """An accepted PE header and the section table under it, enough to map an RVA to a file offset."""

    MAX_SECTIONS: ClassVar[int] = 96

    def __init__(self, data: bytes, e_lfanew: int, is64: bool) -> None:
        self.data, self.n, self.e_lfanew, self.is64 = data, len(data), e_lfanew, is64
        self.opt = e_lfanew + 24

    @staticmethod
    def header(data: bytes) -> Image | None:
        """Accept a file as a PE: an MZ stub, an `e_lfanew` to a `PE\\0\\0` signature, a COFF header and
        an optional header of the magic's width all present in the file."""
        n = len(data)
        if n < 64 or data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<i", data, 0x3C)[0]
        if e_lfanew < 0:
            return None
        size = e_lfanew + 4 + 20
        if n < size or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        if n < size + 224:
            return None
        is64 = struct.unpack_from("<H", data, e_lfanew + 24)[0] == 0x20B
        if n < size + (240 if is64 else 224):
            return None
        return Image(data, e_lfanew, is64)

    def fits(self, where: int, size: int) -> bool:
        size &= 0xFFFFFFFFFFFFFFFF
        return size <= self.n and 0 <= where <= self.n - size

    def u16(self, where: int) -> int:
        if where < 0 or where + 2 > self.n:
            raise IndexError(where)
        return int.from_bytes(self.data[where : where + 2], "little")

    def u32(self, where: int) -> int:
        if where < 0 or where + 4 > self.n:
            raise IndexError(where)
        return int.from_bytes(self.data[where : where + 4], "little")

    def directory(self, entry: int) -> tuple[int, int] | None:
        where = self.opt + (112 if self.is64 else 96) + 8 * entry
        if not self.fits(where, 8):
            return None
        return self.u32(where), self.u32(where + 4)

    def number_of_rva_and_sizes(self) -> int:
        return self.u32(self.opt + (108 if self.is64 else 92))

    def rva_to_offset(self, rva: int) -> int:
        """Map a virtual address to a file offset through the section with the highest base that still
        contains it, aligning the raw pointer as the loader does; -1 when no section holds it or the
        offset falls past the file."""
        count = struct.unpack_from("<H", self.data, self.e_lfanew + 6)[0]
        first = self.opt + struct.unpack_from("<H", self.data, self.e_lfanew + 20)[0]
        file_alignment = self.u32(self.opt + 36)
        section_alignment = self.u32(self.opt + 32)
        lowest = 0xFFFFFFFF
        hit_rva = hit_off = hit_raw = 0
        for i in range(min(count, Image.MAX_SECTIONS)):
            where = first + 40 * i
            if not self.fits(where, 40):
                return -1
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", self.data, where + 8)
            lowest = min(lowest, vaddr)
            if vaddr <= rva and rva - vaddr < max(vsize, rsize) and hit_rva <= vaddr:
                alignment = min(file_alignment, 0x200)
                hit_rva, hit_off, hit_raw = vaddr, roff, rsize
                if alignment and hit_off % alignment:
                    hit_off -= hit_off % alignment
                if section_alignment >= 0x1000:
                    hit_off &= ~0x1FF
        if rva < lowest:
            hit_rva, hit_off, hit_raw = 0, 0, self.n
        if rva < hit_rva or rva - hit_rva >= hit_raw:
            return -1
        result = hit_off + (rva - hit_rva)
        return result if result < self.n else -1


class Pe:
    """The `pe` module reader."""

    #: Each function's overloads (argument kinds, result kind). "r" is a regular expression argument.
    SIGNATURES: ClassVar[dict[str, tuple[tuple[tuple[str, ...], str], ...]]] = {
        "calculate_checksum": (((), "int"),),
        "imphash": (((), "str"),),
        "section_index": ((("str",), "int"), (("int",), "int")),
        "exports": ((("str",), "int"), (("r",), "int"), (("int",), "int")),
        "exports_index": ((("str",), "int"), (("int",), "int"), (("r",), "int")),
        "imports": ((("str", "str"), "int"), (("str", "int"), "int"), (("str",), "int"), (("r", "r"), "int"),
                    (("int", "str", "str"), "int"), (("int", "str", "int"), "int"), (("int", "str"), "int"),
                    (("int", "r", "r"), "int")),
        "import_rva": ((("str", "str"), "int"), (("str", "int"), "int")),
        "delayed_import_rva": ((("str", "str"), "int"), (("str", "int"), "int")),
        "locale": ((("int",), "int"),),
        "language": ((("int",), "int"),),
        "is_dll": (((), "int"),),
        "is_32bit": (((), "int"),),
        "is_64bit": (((), "int"),),
        "rva_to_offset": ((("int",), "int"),),
    }  # fmt: skip

    UNDEFINED_VALUE: ClassVar[int] = 0xFFFABADAFABADAFF
    MAX_IMPORTS: ClassVar[int] = 16384
    MAX_EXPORTS: ClassVar[int] = 16384
    MAX_RESOURCES: ClassVar[int] = 65536
    FUNCTION_NAME: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9._?@$()<>]+")

    @staticmethod
    def schema() -> Struct:
        """Every field the module declares, undefined: the shape a non-PE file still answers."""
        u, s = UNDEF_INT, UNDEF_STR
        section = Struct(dict.fromkeys(("characteristics", "virtual_address", "virtual_size", "raw_data_offset", "raw_data_size", "pointer_to_relocations", "pointer_to_line_numbers", "number_of_relocations", "number_of_line_numbers"), u) | {"name": s, "full_name": s})  # fmt: skip
        directory = Struct({"virtual_address": u, "size": u})
        resource = Struct({"rva": u, "offset": u, "length": u, "type": u, "id": u, "language": u, "type_string": s, "name_string": s, "language_string": s})  # fmt: skip
        function = Struct({"name": s, "ordinal": u, "rva": u})
        import_detail = Struct(
            {"library_name": s, "number_of_functions": u, "functions": Array(function)}
        )
        export_detail = Struct({"name": s, "ordinal": u, "rva": u, "offset": u, "forward_name": s})
        signature = Authenticode.proto()
        version = Struct({"major": u, "minor": u})
        fields: dict[str, Any] = dict(Tables.PE)
        fields |= dict.fromkeys(("is_pe", "machine", "number_of_sections", "timestamp", "pointer_to_symbol_table", "number_of_symbols", "size_of_optional_header", "characteristics", "entry_point", "entry_point_raw", "image_base", "number_of_rva_and_sizes", "number_of_version_infos", "opthdr_magic", "size_of_code", "size_of_initialized_data", "size_of_uninitialized_data", "base_of_code", "base_of_data", "section_alignment", "file_alignment", "win32_version_value", "size_of_image", "size_of_headers", "checksum", "subsystem", "dll_characteristics", "size_of_stack_reserve", "size_of_stack_commit", "size_of_heap_reserve", "size_of_heap_commit", "loader_flags", "number_of_resources", "resource_timestamp", "number_of_imports", "number_of_imported_functions", "number_of_delayed_imports", "number_of_delayed_imported_functions", "number_of_exports", "export_timestamp", "number_of_signatures", "is_signed"), u)  # fmt: skip
        fields |= {"dll_name": s, "pdb_path": s}
        for name in (
            "linker_version",
            "os_version",
            "image_version",
            "subsystem_version",
            "resource_version",
        ):
            fields[name] = Values.undefined_like(version)
        fields["overlay"] = Struct({"offset": u, "size": u})
        fields["rich_signature"] = Struct({"offset": u, "length": u, "key": u, "raw_data": s, "clear_data": s, "version_data": s,
                                           "version": Values.fn((("int",), lambda *_: u, "int"), (("int", "int"), lambda *_: u, "int")),
                                           "toolid": Values.fn((("int",), lambda *_: u, "int"), (("int", "int"), lambda *_: u, "int"))})  # fmt: skip
        fields["sections"] = Array(section)
        fields["data_directories"] = Array(directory)
        fields["resources"] = Array(resource)
        fields["import_details"] = Array(import_detail)
        fields["delayed_import_details"] = Array(import_detail)
        fields["export_details"] = Array(export_detail)
        fields["signatures"] = Array(signature)
        fields["version_info"] = Dictionary(s)
        fields["version_info_list"] = Array(Struct({"key": s, "value": s}))
        fields |= Pe._functions_undefined()
        fields["is_pe"] = 0  # set for every file scanned, before a header is looked for
        return Struct(fields)

    @staticmethod
    def _undefined_of(kind: str) -> Any:
        undefined = UNDEF_STR if kind == "str" else UNDEF_INT
        return lambda *_: undefined

    @staticmethod
    def _functions_undefined() -> dict[str, Any]:
        out = {}
        for name, overloads in Pe.SIGNATURES.items():
            out[name] = Values.fn(
                *((args, Pe._undefined_of(kind), kind) for args, kind in overloads)
            )
        return out

    @staticmethod
    def module(data: bytes) -> Struct:
        root = Pe.schema()
        with contextlib.suppress(IndexError, ValueError, struct.error):
            Pe._parse(root, data)  # a PE whose later structures do not fit keeps what was read
        return root

    @staticmethod
    def _parse(root: Struct, data: bytes) -> None:
        img = Image.header(data)
        if img is None:
            return
        b = Reader(data)
        f = root.fields
        e_lfanew = img.e_lfanew
        coff = e_lfanew + 4
        machine, nsec, ts, symptr, nsym, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, coff
        )
        opt = img.opt
        is64 = img.is64
        magic = img.u16(opt)
        f.update(is_pe=1, machine=machine, number_of_sections=nsec, timestamp=ts, pointer_to_symbol_table=symptr,
                 number_of_symbols=nsym, size_of_optional_header=opt_size, characteristics=chars)  # fmt: skip
        f.update(
            number_of_resources=0, number_of_version_infos=0, number_of_signatures=0, is_signed=0
        )
        entry = img.u32(opt + 16)
        f["entry_point"] = img.rva_to_offset(entry)
        f["entry_point_raw"] = entry
        image_base = struct.unpack_from("<Q", data, opt + 24)[0] if is64 else img.u32(opt + 28)
        f["image_base"] = image_base
        f["number_of_rva_and_sizes"] = img.number_of_rva_and_sizes()
        f["opthdr_magic"] = magic
        f["linker_version"] = Struct({"major": data[opt + 2], "minor": data[opt + 3]})
        size_code, size_init, size_uninit, _, base_code = struct.unpack_from(
            "<IIIII", data, opt + 4
        )
        f.update(size_of_code=size_code, size_of_initialized_data=size_init,
                 size_of_uninitialized_data=size_uninit, base_of_code=base_code)  # fmt: skip
        if not is64:
            f["base_of_data"] = img.u32(opt + 24)
        sa, fa, osmaj, osmin, imaj, imin, smaj, smin, w32, soi, soh, csum, subsys, dllc = (
            struct.unpack_from("<IIHHHHHHIIIIHH", data, opt + 32)
        )
        f.update(section_alignment=sa, file_alignment=fa, win32_version_value=w32, size_of_image=soi,
                 size_of_headers=soh, checksum=csum, subsystem=subsys, dll_characteristics=dllc)  # fmt: skip
        f["os_version"] = Struct({"major": osmaj, "minor": osmin})
        f["image_version"] = Struct({"major": imaj, "minor": imin})
        f["subsystem_version"] = Struct({"major": smaj, "minor": smin})
        r = struct.unpack_from("<QQQQI" if is64 else "<IIIII", data, opt + 72)
        f.update(size_of_stack_reserve=r[0], size_of_stack_commit=r[1], size_of_heap_reserve=r[2],
                 size_of_heap_commit=r[3], loader_flags=r[4])  # fmt: skip
        dd_at = opt + (112 if is64 else 96)
        for i in range(min(img.number_of_rva_and_sizes(), 16)):
            if not img.fits(dd_at + 8 * i, 8):
                break
            va, size = struct.unpack_from("<II", data, dd_at + 8 * i)
            f["data_directories"].items[i] = Struct({"virtual_address": va, "size": size})

        def rva_to_offset(rva: int) -> int | None:
            offset = img.rva_to_offset(rva)
            return None if offset < 0 else offset

        Pe._resources(f, img)
        f["number_of_version_infos"] = len(f["version_info_list"].items)
        sec_at = opt + opt_size
        sections: list[tuple[bytes, int, int, int, int, int]] = []
        highest_ofs = highest_size = 0
        for i in range(min(nsec, Image.MAX_SECTIONS)):
            where = sec_at + 40 * i
            if not img.fits(where, 40):
                break
            sfields = struct.unpack_from("<8sIIIIIIHHI", data, where)
            name = sfields[0].rstrip(b"\x00")
            full = Pe._full_section_name(img, symptr, nsym, name)
            sections.append((name, sfields[1], sfields[2], sfields[3], sfields[4], sfields[9]))
            f["sections"].items[i] = Struct({
                "name": name, "full_name": UNDEF_STR if full is None else full, "virtual_size": sfields[1],
                "virtual_address": sfields[2], "raw_data_size": sfields[3], "raw_data_offset": sfields[4],
                "pointer_to_relocations": sfields[5], "pointer_to_line_numbers": sfields[6],
                "number_of_relocations": sfields[7], "number_of_line_numbers": sfields[8],
                "characteristics": sfields[9],
            })  # fmt: skip
            if sfields[4] + sfields[3] > highest_ofs + highest_size:
                highest_ofs, highest_size = sfields[4], sfields[3]
        last = highest_ofs + highest_size
        if last and len(data) > last:
            f["overlay"] = Struct({"offset": last, "size": len(data) - last})
        else:
            f["overlay"] = Struct({"offset": 0, "size": 0})
        Pe._rich(f, data)
        Pe._pdb(f, img)
        Pe._signatures(f, data, e_lfanew, is64)
        imports: list[tuple[bytes, list[tuple[bytes | None, int | None, int]]]] = []
        f.update(number_of_imports=0, number_of_imported_functions=0)
        f.update(number_of_delayed_imports=0, number_of_delayed_imported_functions=0)
        directory = img.directory(1)
        if directory is not None and directory[0]:
            Pe._imports(b, directory[0], rva_to_offset, is64, imports)
        f["number_of_imports"] = len(imports)
        f["number_of_imported_functions"] = sum(len(fs) for _, fs in imports)
        Pe._details(f["import_details"], imports)
        delayed: list[tuple[bytes, list[tuple[bytes | None, int | None, int]]]] = []
        directory = img.directory(13)
        if directory is not None and directory[0]:
            Pe._delayed(b, directory[0], rva_to_offset, is64, image_base, soi, delayed)
        f["number_of_delayed_imports"] = len(delayed)
        f["number_of_delayed_imported_functions"] = sum(len(fs) for _, fs in delayed)
        Pe._details(f["delayed_import_details"], delayed)
        exports: list[tuple[bytes | None, int, int]] = []
        f["number_of_exports"] = 0
        directory = img.directory(0)
        if directory is not None and directory[0]:
            Pe._exports(f, b, directory, rva_to_offset, exports)
        Pe._functions(f, img, sections, imports, delayed, exports, chars)

    @staticmethod
    def _full_section_name(img: Image, symptr: int, nsym: int, name: bytes) -> bytes | None:
        """A `/<n>` section name resolved through the COFF string table to its long name, kept only when
        printable and terminated inside the file; the short name when it is not a `/<n>` form."""
        if symptr == 0 or not name.startswith(b"/"):
            return name
        index = 0
        for c in name[1:8]:
            if not 0x30 <= c <= 0x39:
                break
            index = index * 10 + c - 0x30
        where = symptr + nsym * 18 + index
        length = 0
        while img.fits(where, length + 1):
            c = img.data[where + length]
            if c == 0:
                return img.data[where : where + length]
            if not 0x20 <= c <= 0x7E:
                return None
            length += 1
        return None

    @staticmethod
    def _valid_dll(b: Reader, where: int) -> bytes | None:
        """A library name: printable, free of `"*<>?|`, and terminated by a NUL within the file (a name
        that runs to the end of the file without one is rejected), shorter than 256 bytes."""
        name = b.data[where : where + 256].split(b"\x00", 1)
        if (
            len(name) < 2
        ):  # no terminator within the window (truncated or over-long): not a valid name
            return None
        text = name[0]
        if not text or any(c < 0x20 or c > 0x7E or c in b'"*<>?|' for c in text):
            return None
        return text

    @staticmethod
    def _imports(b: Reader, rva: int, rva_to_offset: Any, is64: bool, out: list[Any]) -> None:
        """The import table: each library with at least one function, each function `(name, ordinal, rva)`
        — named, or named by ordinal — its rva the import-address-table slot; a rejected name is skipped."""
        where = rva_to_offset(rva)
        if where is None:
            return
        size = 8 if is64 else 4
        flag = 1 << (63 if is64 else 31)
        parsed, total = 0, 0
        while parsed < Pe.MAX_IMPORTS:
            d = b.at("<IIIII", where)
            if d is None or d[3] == 0:
                return
            parsed += 1
            original, _, _, name_rva, first = d
            where += 20
            name_off = rva_to_offset(name_rva)
            dll = Pe._valid_dll(b, name_off) if name_off is not None else None
            if dll is None:
                continue
            thunk = rva_to_offset(original)
            if thunk is None or thunk <= 0:
                thunk = rva_to_offset(first)
            if thunk is None:
                continue
            funcs: list[tuple[bytes | None, int | None, int]] = []
            index = 0
            while total < Pe.MAX_IMPORTS:
                entry = b.one("<Q" if is64 else "<I", thunk + size * index)
                if not entry:
                    break
                name: bytes | None = None
                ordinal: int | None = None
                if not entry & flag:
                    hint_at = rva_to_offset(entry)
                    if hint_at is not None and hint_at + 2 < len(b.data):
                        name = b.data[hint_at + 2 : hint_at + 2 + 512].split(b"\x00", 1)[0]
                elif entry <= (0x800000000000FFFF if is64 else 0x8000FFFF):
                    # a by-ordinal import: the flag bit plus an ordinal in the low 16 bits and nothing
                    # between; a value with other bits set is not an ordinal and is left out
                    ordinal = entry & 0xFFFF
                    name = Tables.ordinal_name(dll, ordinal)
                slot = first + size * index
                index += 1
                if name is not None and not Pe.FUNCTION_NAME.fullmatch(name):
                    continue
                if name is not None or ordinal is not None:
                    funcs.append((name, ordinal, slot))
                    total += 1
            if funcs:
                out.append((dll, funcs))

    @staticmethod
    def _delayed(b: Reader, rva: int, rva_to_offset: Any, is64: bool, image_base: int,
                 size_of_image: int, out: list[Any]) -> None:  # fmt: skip
        """The delay-load import table, its addresses taken as RVAs or, for an old 32-bit descriptor, as
        virtual addresses relative to the image base."""
        where = rva_to_offset(rva)
        if where is None:
            return
        size = 8 if is64 else 4
        flag = 1 << (63 if is64 else 31)

        def normal(value: int) -> int:
            return value - image_base if value >= image_base else value

        while True:
            d = b.at("<IIIIIIII", where)
            if d is None or not any(d):
                return
            where += 32
            attrs, name_rva, _, iat, int_, _, _, _ = d
            if attrs > 1:
                return
            if not is64 and not attrs:
                name_rva, iat, int_ = normal(name_rva), normal(iat), normal(int_)
            if int_ >= size_of_image or iat >= size_of_image or name_rva < 64 or int_ < 64:
                return
            name_off = rva_to_offset(name_rva)
            dll = Pe._valid_dll(b, name_off) if name_off is not None else None
            if dll is None:
                continue
            funcs: list[tuple[bytes | None, int | None, int]] = []
            name_at, func_at = int_, iat
            while True:
                no, fo = rva_to_offset(name_at), rva_to_offset(func_at)
                if no is None or fo is None:
                    break
                name_address = b.one("<Q" if is64 else "<I", no)
                func_address = b.one("<Q" if is64 else "<I", fo)
                if not name_address or not func_address:
                    break
                if not name_address & flag:
                    if not attrs:
                        name_address = normal(name_address)
                    off = rva_to_offset(name_address + 2)
                    if off is None:
                        name_at += size
                        func_at += size
                        continue
                    funcs.append((b.data[off : off + 512].split(b"\x00", 1)[0], None, func_at))
                else:
                    ordinal = name_address & 0xFFFF
                    funcs.append((Tables.ordinal_name(dll, ordinal), ordinal, func_at))
                name_at += size
                func_at += size
            out.append((dll, funcs))

    @staticmethod
    def _details(target: Array, libraries: list[Any]) -> None:
        proto = Struct({"name": UNDEF_STR, "ordinal": UNDEF_INT, "rva": UNDEF_INT})
        for i, (dll, funcs) in enumerate(libraries):
            target.items[i] = Struct({
                "library_name": dll, "number_of_functions": len(funcs),
                "functions": Array(proto, {
                    j: Struct({"name": Reader.or_undefined(n, UNDEF_STR), "ordinal": Reader.or_undefined(o), "rva": slot})
                    for j, (n, o, slot) in enumerate(funcs)
                }),
            })  # fmt: skip

    @staticmethod
    def _exports(
        f: dict[str, Any], b: Reader, directory: tuple[int, int], rva_to_offset: Any, out: list[Any]
    ) -> None:
        """The export table, each entry `(name, ordinal, rva)` — forwarded names noted, the rest by offset;
        the address, name and ordinal arrays read only where they fit the file."""
        where = rva_to_offset(directory[0])
        if where is None:
            return
        e = b.at("<IIHHIIIIIII", where)
        if e is None:
            return
        _, ts, _, _, name_rva, base, nfuncs, nnames, funcs_rva, names_rva, ords_rva = e
        count = min(nfuncs, Pe.MAX_EXPORTS)
        f["export_timestamp"] = ts
        name_off = rva_to_offset(name_rva)
        if name_off is not None and name_off > 0:
            f["dll_name"] = b.data[name_off:].split(b"\x00", 1)[0]
        # the function count must leave room past the name offset, or the table is not walked
        if count * 4 > len(b.data) - (name_off if name_off is not None else -1):
            return
        names_off = rva_to_offset(names_rva) if nnames else None
        if nnames and (names_off is None or nnames * 4 > len(b.data) - names_off):
            return
        ords_off, funcs_off = rva_to_offset(ords_rva), rva_to_offset(funcs_rva)
        if ords_off is None or funcs_off is None:
            return
        if len(b.data) - ords_off < 2 * count or len(b.data) - funcs_off < 4 * count:
            return
        named = min(nnames, count)
        ordinals = [b.one("<H", ords_off + 2 * j) for j in range(count)]
        start, end = where, where + directory[1]
        for i in range(count):
            frva = b.one("<I", funcs_off + 4 * i)
            entry: dict[str, Any] = {"ordinal": base + i, "rva": frva, "name": UNDEF_STR, "offset": UNDEF_INT, "forward_name": UNDEF_STR}  # fmt: skip
            offset = rva_to_offset(frva)
            if offset is not None and start < offset < end:
                entry["forward_name"] = b.data[offset : offset + 512].split(b"\x00", 1)[0]
            else:
                entry["offset"] = Pe._or(offset)
            if names_off is not None:
                for j in range(count):
                    if ordinals[j] == i and j < named:
                        nrva = b.one("<I", names_off + 4 * j)
                        noff = rva_to_offset(nrva) if nrva is not None else None
                        if noff is not None and noff > 0:
                            entry["name"] = b.data[noff : noff + 512].split(b"\x00", 1)[0]
                        break
            out.append(
                (entry["name"] if isinstance(entry["name"], bytes) else None, base + i, frva)
            )
            f["export_details"].items[i] = Struct(entry)
        f["number_of_exports"] = len(out)

    @staticmethod
    def _or(value: Any) -> Any:
        return UNDEF_INT if value is None else value

    @staticmethod
    def _resources(f: dict[str, Any], img: Image) -> None:
        """The resource directory walked at its three levels (type, name, language); the last identifier
        seen at a level is the one a leaf carries, and a zero child ends a directory."""
        directory = img.directory(2)
        if directory is None or directory[0] == 0:
            return
        base = img.rva_to_offset(directory[0])
        if base < 0 or not img.fits(base, 16):
            return
        data = img.data
        _, ts, major, minor = struct.unpack_from("<IIHH", data, base)
        f["resource_timestamp"] = ts
        f["resource_version"] = Struct({"major": major, "minor": minor})
        state = {"type": -1, "id": -1, "language": -1}
        found: Array = f["resources"]

        def name_string(name: int) -> bytes | None:
            if not name & 0x80000000:
                return None
            where = base + (name & 0x7FFFFFFF)
            if not img.fits(where, 2) or not img.fits(where, 2 + img.u16(where) * 2):
                return None
            return data[where : where + 2 + img.u16(where) * 2]

        def collect(
            entry_at: int, strings: tuple[bytes | None, bytes | None, bytes | None]
        ) -> None:
            index = len(found.items)
            if index >= Pe.MAX_RESOURCES:
                return
            rva, size = struct.unpack_from("<II", data, entry_at)
            offset = img.rva_to_offset(rva)
            fields: dict[str, Any] = dict(found.proto.fields)
            fields.update(rva=rva, offset=UNDEF_INT if offset < 0 else offset, length=size)
            for (key, num), string in zip((("type_string", "type"), ("name_string", "id"), ("language_string", "language")), strings, strict=True):  # fmt: skip
                value = state[num]
                if string is not None:
                    fields[key] = string[2:]
                elif value != -1:
                    fields[num] = value
            found.items[index] = Struct(fields)
            if state["type"] == 16 and offset >= 0:
                Pe._version_info(f, data, offset)

        def walk(where: int, level: int, strings: list[bytes | None]) -> None:
            characteristics, _, _, _, named, ids = struct.unpack_from("<IIHHHH", data, where)
            if characteristics != 0 or named > 32768 or ids > 32768:
                return
            total = named + ids
            entry = where + 16
            if not img.fits(entry, total * 8):
                return
            for _ in range(total):
                name, child = struct.unpack_from("<II", data, entry)
                if child == 0:
                    return  # a zero child ends this directory
                if level < 3:
                    state[("type", "id", "language")[level]] = (
                        name - (1 << 32) if name & 0x80000000 else name
                    )
                    strings = [*strings]
                    strings[level] = name_string(name)
                target = base + (child & 0x7FFFFFFF)
                if child & 0x80000000 and level < 2:
                    if img.fits(target, 16):
                        walk(target, level + 1, strings)
                elif img.fits(target, 16):
                    size = img.u32(target + 4)
                    if 0 < size < img.n:
                        collect(target, (strings[0], strings[1], strings[2]))
                entry += 8

        walk(base, 0, [None, None, None])
        f["number_of_resources"] = len(found.items)

    @staticmethod
    def _version_info(f: dict[str, Any], data: bytes, offset: int) -> None:
        """The VS_VERSION_INFO block's StringFileInfo entries, walked through the file; each key kept to
        63 bytes and value to 255, each UTF-16 unit taken as its low byte and cut at the first zero."""
        n = len(data)

        def fits(where: int, size: int) -> bool:
            return size <= n and 0 <= where <= n - size

        def u16(where: int) -> int:
            return data[where] | (data[where + 1] << 8)

        def align(where: int, add: int) -> int:
            return where + ((add + 3) & ~3)

        def wide_fits(where: int) -> bool:
            if not 0 <= where < n:
                return False
            i = where
            while n - i >= 2:
                if data[i] == 0 and data[i + 1] == 0:
                    return True
                i += 2
            return False

        def wide_len(where: int) -> int:
            i = where
            while data[i] or data[i + 1]:
                i += 2
            return (i - where) // 2

        def same(where: int, text: bytes) -> bool:
            i = 0
            while i < len(text) and data[where + 2 * i] == text[i] and data[where + 2 * i + 1] == 0:
                i += 1
            return i == len(text) and data[where + 2 * i + 1] == 0 and data[where + 2 * i] == 0

        def narrow(where: int, size: int) -> bytes:
            out = bytearray()
            while size > 1 and where < n and data[where] != 0:
                out.append(data[where])
                where += 2
                size -= 1
            return bytes(out)

        if (
            not fits(offset, 6)
            or not fits(offset + 6, 32)
            or not same(offset + 6, b"VS_VERSION_INFO")
        ):
            return
        info = align(offset, 6 + 86)
        while fits(info + 6, 24) and same(info + 6, b"VarFileInfo") and u16(info) != 0:
            info = align(info, u16(info))
        while fits(info + 6, 30) and same(info + 6, b"StringFileInfo") and u16(info) != 0:
            table = align(info, 6 + 30)
            info = align(info, u16(info))
            while fits(table, 6) and wide_fits(table + 6) and u16(table) != 0 and table < info:
                string = align(table, 6 + 2 * (wide_len(table + 6) + 1))
                table = align(table, u16(table))
                while (
                    fits(string, 6)
                    and wide_fits(string + 6)
                    and u16(string) != 0
                    and string < table
                ):
                    value_at = align(string, 6 + 2 * (wide_len(string + 6) + 1))
                    if wide_fits(value_at):
                        key = narrow(string + 6, 64)
                        value = b"" if u16(string + 2) == 0 else narrow(value_at, 256)
                        f["version_info"].items[key] = value
                        index = len(f["version_info_list"].items)
                        f["version_info_list"].items[index] = Struct({"key": key, "value": value})
                    string = align(string, u16(string))

    @staticmethod
    def _pdb(f: dict[str, Any], img: Image) -> None:
        """The first CodeView debug entry (NB10, RSDS or MTOC) whose path ends within 260 bytes, found
        through its RVA and else its file pointer."""
        directory = img.directory(6)
        if directory is None or directory[1] == 0 or directory[0] == 0:
            return
        base = img.rva_to_offset(directory[0])
        if base < 0:
            return
        data = img.data
        for i in range(directory[1] // 28):
            where = base + 28 * i
            if not img.fits(where, 28):
                break
            kind, _, address, pointer = struct.unpack_from("<IIII", data, where + 12)
            if kind != 2:
                continue
            header = 0
            if address != 0:
                header = img.rva_to_offset(address)
            if header <= 0 and pointer != 0:
                header = pointer
            if header <= 0 or not img.fits(header, 8):
                continue
            signature = img.u32(header)
            path_at = None
            if signature == 0x3031424E and img.fits(header, 17):
                path_at = header + 16
            elif signature == 0x53445352 and img.fits(header, 25):
                path_at = header + 24
            elif signature == 0x434F544D and img.fits(header, 21):
                path_at = header + 20
            if path_at is not None:
                limit = min(max(img.n - path_at, 0), 260)
                end = data.find(b"\x00", path_at, path_at + limit)
                length = (end - path_at) if end >= 0 else limit
                if length < 260:
                    f["pdb_path"] = data[path_at : path_at + length]
                    return

    @staticmethod
    def _rich(f: dict[str, Any], data: bytes) -> None:
        """The Rich stub: "Rich" sought back from the PE header a dword at a time, then "DanS" (unmasked by
        the key that follows "Rich") sought back from there; neither below the DOS header."""
        n = len(data)
        if n < 64 or data[:2] != b"MZ":
            return
        nt = int.from_bytes(data[0x3C:0x40], "little")
        if nt > n + 4 or nt < 4:
            return

        def dword(where: int) -> int:
            return int.from_bytes(data[where : where + 4].ljust(4, b"\x00"), "little")

        p = nt - 4
        key = 0
        rich = -1
        while p >= 64:
            if dword(p) == 0x68636952:
                key = dword(p + 4)
                rich = p
                p -= 4
                break
            p -= 4
        if key == 0:
            return
        start = -1
        while p >= 64:
            if dword(p) ^ key == 0x536E6144:
                start = p
                break
            p -= 4
        if start < 0:
            return
        raw = data[start:rich]
        clear = b"".join(
            (int.from_bytes(raw[i : i + 4], "little") ^ key).to_bytes(4, "little")
            for i in range(0, len(raw), 4)
        )
        count = (len(raw) - 16) // 8 if len(raw) >= 16 else 0
        entries = [struct.unpack_from("<II", clear, 16 + 8 * i) for i in range(count)]

        def tally(version: int | None, toolid: int | None) -> int:
            if version is None and toolid is None:
                return 0
            return sum(times for id_version, times in entries
                       if (version is None or id_version & 0xFFFF == version) and (toolid is None or id_version >> 16 == toolid))  # fmt: skip

        rich_fields: dict[str, Any] = {
            "offset": start, "length": len(raw), "key": key, "raw_data": raw, "clear_data": clear,
            "version_data": b"".join(clear[16 + 8 * i : 20 + 8 * i] for i in range(count)) if len(raw) >= 16 else UNDEF_STR,
            "version": Values.fn((("int",), lambda v: tally(v, None), "int"), (("int", "int"), lambda v, t: tally(v, t), "int")),
            "toolid": Values.fn((("int",), lambda t: tally(None, t), "int"), (("int", "int"), lambda t, v: tally(v, t), "int")),
        }  # fmt: skip
        f["rich_signature"] = Struct(rich_fields)

    @staticmethod
    def _signatures(f: dict[str, Any], data: bytes, pe_off: int, is64: bool) -> None:
        """The certificate table, read where the optional header's security directory points and checked
        to lie within the file."""
        where = pe_off + 24 + (0x70 if is64 else 0x60) + 4 * 8
        if where + 8 > len(data):
            return
        va, size = struct.unpack_from("<II", data, where)
        if va == 0 or va > len(data) or size > len(data) or va + size > len(data):
            return
        found, signed = Authenticode.module_values(data)
        f["number_of_signatures"] = len(found)
        f["is_signed"] = int(signed)
        for i, sig in enumerate(found):
            f["signatures"].items[i] = sig

    @staticmethod
    def _c(text: bytes) -> bytes:
        return text.split(b"\x00", 1)[0]

    @staticmethod
    def _lower(text: bytes) -> bytes:
        return bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in text)

    @staticmethod
    def _search(pattern: Any, text: bytes) -> int:
        """A regular expression run over a C string: where its match ends, or -1."""
        return int(pattern.run(text.split(b"\x00", 1)[0]))

    @staticmethod
    def _signed64(value: int) -> int:
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value & (1 << 63) else value

    @staticmethod
    def _functions(f: dict[str, Any], img: Image, sections: list[Any], imports: list[Any], delayed: list[Any],
                   exports: list[Any], chars: int) -> None:  # fmt: skip
        """The `pe` functions, each resolved against what the file provided."""
        data = img.data
        low, c, search = Pe._lower, Pe._c, Pe._search

        def table_count(table: list[Any], dll: bytes) -> int:
            return sum(len(fs) for name, fs in table if low(name) == low(c(dll)))

        def table_has(table: list[Any], dll: bytes, fn: bytes) -> int:
            return int(
                any(
                    low(n or b"") == low(c(fn))
                    for name, fs in table
                    if low(name) == low(c(dll))
                    for n, _, _ in fs
                )
            )

        def table_ordinal(table: list[Any], dll: bytes, ordinal: int) -> int:
            return int(
                any(
                    o is not None and o == ordinal
                    for name, fs in table
                    if low(name) == low(c(dll))
                    for _, o, _ in fs
                )
            )

        def table_regex(table: list[Any], dll_re: Any, fn_re: Any) -> int:
            return sum(
                1
                for name, fs in table
                if search(dll_re, name) > 0
                for n, _, _ in fs
                if search(fn_re, n or b"") > 0
            )

        def flagged(flags: int, one: Any, *args: Any, total: bool = False) -> int:
            standard = one(imports, *args) if flags & 1 else 0
            if not total and standard:
                return 1
            later = one(delayed, *args) if flags & 2 else 0
            return standard + later if total else int(bool(later))

        n_exports = len(exports)

        def export_name(q: bytes) -> Any:
            return int(any(n is not None and low(n) == low(q) for n, _, _ in exports))

        def export_regex(q: Any) -> Any:
            return int(any(n is not None and search(q, n) != -1 for n, _, _ in exports))

        def export_ordinal(q: int) -> Any:
            if n_exports == 0 or q == 0 or q > n_exports:
                return 0
            return int(any(o == q for _, o, _ in exports))

        def index_name(q: bytes) -> Any:
            return next(
                (i for i, (n, _, _) in enumerate(exports) if n is not None and low(n) == low(q)),
                UNDEF_INT,
            )

        def index_regex(q: Any) -> Any:
            return next(
                (i for i, (n, _, _) in enumerate(exports) if n is not None and search(q, n) != -1),
                UNDEF_INT,
            )

        def index_ordinal(q: int) -> Any:
            if n_exports == 0 or q == 0 or q > n_exports:
                return UNDEF_INT
            return next((i for i, (_, o, _) in enumerate(exports) if o == q), UNDEF_INT)

        def imphash() -> bytes:
            parts: list[bytes] = []
            for dll, fs in imports:
                dot = dll.rfind(b".")
                stem = (
                    dll[:dot]
                    if dot >= 0 and low(dll[dot : dot + 4]) in (b".ocx", b".sys", b".dll")
                    else dll
                )
                parts.extend(low(stem) + b"." + low(n or b"") for n, _, _ in fs)
            return hashlib.md5(b",".join(parts)).hexdigest().encode()  # noqa: S324 - the digest is defined as MD5

        def section_index_name(q: bytes) -> Any:
            count = f["number_of_sections"]
            for i in range(min(count, Image.MAX_SECTIONS)):
                if i < len(sections) and c(sections[i][0]) == c(q):
                    return i
            return UNDEF_INT

        def section_index_addr(addr: int) -> Any:
            count = f["number_of_sections"]
            for i in range(min(count, Image.MAX_SECTIONS)):
                if i < len(sections):
                    offset, size = sections[i][4], sections[i][3]
                else:
                    offset = size = Pe._signed64(Pe.UNDEFINED_VALUE)
                if addr >= offset and addr < Pe._signed64(offset + size):
                    return i
            return UNDEF_INT

        def rva_of(details: Array, count: Any, dll: bytes, match: Any) -> Any:
            if Values.undefined(count):
                return UNDEF_INT
            for i in range(count):
                item = details.items.get(i)
                if item is None or low(item.fields["library_name"]) != low(dll):
                    continue
                for fn in item.fields["functions"].items.values():
                    if match(fn.fields):
                        return fn.fields["rva"]
            return UNDEF_INT

        def by_name(name: bytes) -> Any:
            return lambda fn: isinstance(fn["name"], bytes) and low(fn["name"]) == low(name)

        def by_ordinal(ordinal: int) -> Any:
            return lambda fn: isinstance(fn["ordinal"], int) and fn["ordinal"] == ordinal

        def resource_languages() -> list[int]:
            out = []
            for i in range(f["number_of_resources"]):
                item = f["resources"].items.get(i)
                language: Any = item.fields["language"] if item is not None else UNDEF_INT
                out.append(
                    Pe.UNDEFINED_VALUE
                    if not isinstance(language, int)
                    else language & 0xFFFFFFFFFFFFFFFF
                )
            return out

        def checksum() -> int:
            where = img.opt + 64
            csum = 0
            size = len(data)
            for i in range(size // 4 + 1):
                if 4 * i == where:
                    continue
                if 4 * i + 4 <= size:
                    csum += int.from_bytes(data[4 * i : 4 * i + 4], "little")
                else:
                    for j in range(size % 4):
                        csum += data[4 * i + j] << (8 * j)
                if csum > 0xFFFFFFFF:
                    csum = (csum & 0xFFFFFFFF) + (csum >> 32)
            csum = (csum & 0xFFFF) + (csum >> 16)
            csum += csum >> 16
            csum &= 0xFFFF
            return csum + size

        def offset_of(rva: int) -> Any:
            offset = img.rva_to_offset(rva & 0xFFFFFFFFFFFFFFFF)
            return UNDEF_INT if offset == -1 else offset

        f["imports"] = Values.fn(
            (("str", "str"), lambda d, n: table_has(imports, d, n), "int"),
            (("str", "int"), lambda d, o: table_ordinal(imports, d, o), "int"),
            (("str",), lambda d: table_count(imports, d), "int"),
            (("r", "r"), lambda d, n: table_regex(imports, d, n), "int"),
            (("int", "str", "str"), lambda fl, d, n: flagged(fl, table_has, d, n), "int"),
            (("int", "str", "int"), lambda fl, d, o: flagged(fl, table_ordinal, d, o), "int"),
            (("int", "str"), lambda fl, d: flagged(fl, table_count, d, total=True), "int"),
            (("int", "r", "r"), lambda fl, d, n: flagged(fl, table_regex, d, n, total=True), "int"),
        )
        f["exports"] = Values.fn(
            (("str",), export_name, "int"),
            (("r",), export_regex, "int"),
            (("int",), export_ordinal, "int"),
        )
        f["exports_index"] = Values.fn(
            (("str",), index_name, "int"),
            (("int",), index_ordinal, "int"),
            (("r",), index_regex, "int"),
        )
        f["imphash"] = Values.fn(((), imphash, "str"))
        f["section_index"] = Values.fn(
            (("str",), section_index_name, "int"), (("int",), section_index_addr, "int")
        )
        f["is_dll"] = Values.fn(((), lambda: chars & 0x2000, "int"))
        f["is_32bit"] = Values.fn(((), lambda: 0 if img.is64 else 1, "int"))
        f["is_64bit"] = Values.fn(((), lambda: 1 if img.is64 else 0, "int"))
        f["rva_to_offset"] = Values.fn((("int",), offset_of, "int"))
        f["calculate_checksum"] = Values.fn(((), checksum, "int"))
        f["locale"] = Values.fn(
            (
                ("int",),
                lambda q: int(
                    any(lang & 0xFFFF == q & 0xFFFFFFFFFFFFFFFF for lang in resource_languages())
                ),
                "int",
            )
        )
        f["language"] = Values.fn(
            (
                ("int",),
                lambda q: int(
                    any(lang & 0xFF == q & 0xFFFFFFFFFFFFFFFF for lang in resource_languages())
                ),
                "int",
            )
        )
        f["import_rva"] = Values.fn(
            (
                ("str", "str"),
                lambda d, n: rva_of(f["import_details"], f["number_of_imports"], d, by_name(n)),
                "int",
            ),
            (
                ("str", "int"),
                lambda d, o: rva_of(f["import_details"], f["number_of_imports"], d, by_ordinal(o)),
                "int",
            ),
        )
        f["delayed_import_rva"] = Values.fn(
            (
                ("str", "str"),
                lambda d, n: rva_of(
                    f["delayed_import_details"], f["number_of_delayed_imports"], d, by_name(n)
                ),
                "int",
            ),
            (
                ("str", "int"),
                lambda d, o: rva_of(
                    f["delayed_import_details"], f["number_of_delayed_imports"], d, by_ordinal(o)
                ),
                "int",
            ),
        )


__all__ = ["Image", "Pe", "Reader"]
