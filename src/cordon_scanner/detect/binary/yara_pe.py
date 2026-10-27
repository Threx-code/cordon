"""YARA's `pe` and `elf` modules: a port of YARA 4.5.1's own readers (libyara/modules/pe/pe.c,
pe_utils.c, elf/elf.c; Apache License 2.0), guard for guard.

Each value is read where and as YARA reads it: `pe_get_header` before anything, RVAs mapped by
`pe_rva_to_offset`, directories read where the header puts them whatever `NumberOfRvaAndSizes`
says, YARA's limits (16384 imports and exports, 65536 resources, 96 sections) and its quirks kept,
so a rule sees the value YARA would give it -- including undefined, and including where YARA's
reading is loose. Signatures come from `yara_authenticode`, `telfhash` from `yara_tlsh`, the
.NET metadata from `yara_dotnet` (which shares `Image`). Measured field by field against
yara-python over every real executable in the corpus; `test_yara_modules.py` holds the values it
gives for a set of real files.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import struct
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_values import (
    UNDEF_INT,
    UNDEF_STR,
    Array,
    Dictionary,
    Struct,
    Values,
)
from cordon_scanner.detect.binary.yara_authenticode import Authenticode
from cordon_scanner.detect.binary.yara_constants import Constants
from cordon_scanner.detect.binary.yara_tlsh import Tlsh


class _Bytes:
    @staticmethod
    def or_undefined(value: Any, undef: Any = UNDEF_INT) -> Any:
        """A field read from the file, or the field's undefined value where it could not be."""
        return undef if value is None else value

    def __init__(self, data: bytes) -> None:
        self.data = data

    def u(self, fmt: str, at: int) -> tuple[Any, ...] | None:
        size = struct.calcsize(fmt)
        if at < 0 or at + size > len(self.data):
            return None
        return struct.unpack_from(fmt, self.data, at)

    def one(self, fmt: str, at: int) -> Any:
        v = self.u(fmt, at)
        return None if v is None else v[0]

    def cstr(self, at: int, limit: int = 4096) -> bytes | None:
        if at < 0 or at >= len(self.data):
            return None
        end = self.data.find(b"\x00", at, at + limit)
        return self.data[at : end if end >= 0 else min(len(self.data), at + limit)]


class Image:
    """The PE header as `pe_get_header` accepts it, and `pe_rva_to_offset` over its sections."""

    MAX_SECTIONS: ClassVar[int] = 96

    def __init__(self, data: bytes, e_lfanew: int, is64: bool) -> None:
        self.data, self.n, self.e_lfanew, self.is64 = data, len(data), e_lfanew, is64
        self.opt = e_lfanew + 24

    @staticmethod
    def header(data: bytes) -> Image | None:
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

    def fits(self, at: int, size: int) -> bool:
        size &= 0xFFFFFFFFFFFFFFFF
        return size <= self.n and 0 <= at <= self.n - size

    def u8(self, at: int) -> int:
        return self.data[at]

    def u16(self, at: int) -> int:
        if at < 0 or at + 2 > self.n:
            raise IndexError(at)
        return int.from_bytes(self.data[at : at + 2], "little")

    def u32(self, at: int) -> int:
        if at < 0 or at + 4 > self.n:
            raise IndexError(at)
        return int.from_bytes(self.data[at : at + 4], "little")

    def directory(self, entry: int) -> tuple[int, int] | None:
        at = self.opt + (112 if self.is64 else 96) + 8 * entry
        if not self.fits(at, 8):
            return None
        return self.u32(at), self.u32(at + 4)

    def number_of_rva_and_sizes(self) -> int:
        return self.u32(self.opt + (108 if self.is64 else 92))

    def rva_to_offset(self, rva: int) -> int:
        """`pe_rva_to_offset`, or -1."""
        count = struct.unpack_from("<H", self.data, self.e_lfanew + 6)[0]
        first = self.opt + struct.unpack_from("<H", self.data, self.e_lfanew + 20)[0]
        file_alignment = self.u32(self.opt + 36)
        section_alignment = self.u32(self.opt + 32)
        lowest = 0xFFFFFFFF
        s_rva = s_off = s_raw = 0
        for i in range(min(count, Image.MAX_SECTIONS)):
            at = first + 40 * i
            if not self.fits(at, 40):
                return -1
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", self.data, at + 8)
            lowest = min(lowest, vaddr)
            if vaddr <= rva and rva - vaddr < max(vsize, rsize) and s_rva <= vaddr:
                alignment = min(file_alignment, 0x200)
                s_rva, s_off, s_raw = vaddr, roff, rsize
                if alignment and s_off % alignment:
                    s_off -= s_off % alignment
                if section_alignment >= 0x1000:
                    s_off &= ~0x1FF
        if rva < lowest:
            s_rva, s_off, s_raw = 0, 0, self.n
        if rva < s_rva or rva - s_rva >= s_raw:
            return -1
        result = s_off + (rva - s_rva)
        return result if result < self.n else -1


class Pe:
    MACHINE: ClassVar[dict[str, int]] = {
        "MACHINE_UNKNOWN": 0x0, "MACHINE_AM33": 0x1D3, "MACHINE_AMD64": 0x8664, "MACHINE_ARM": 0x1C0,
        "MACHINE_ARMNT": 0x1C4, "MACHINE_ARM64": 0xAA64, "MACHINE_EBC": 0xEBC, "MACHINE_I386": 0x14C,
        "MACHINE_IA64": 0x200, "MACHINE_M32R": 0x9041, "MACHINE_MIPS16": 0x266, "MACHINE_MIPSFPU": 0x366,
        "MACHINE_MIPSFPU16": 0x466, "MACHINE_POWERPC": 0x1F0, "MACHINE_POWERPCFP": 0x1F1, "MACHINE_R4000": 0x166,
        "MACHINE_SH3": 0x1A2, "MACHINE_SH3DSP": 0x1A3, "MACHINE_SH4": 0x1A6, "MACHINE_SH5": 0x1A8,
        "MACHINE_THUMB": 0x1C2, "MACHINE_WCEMIPSV2": 0x169, "MACHINE_TARGET_HOST": 0x1, "MACHINE_R3000": 0x162,
        "MACHINE_R10000": 0x168, "MACHINE_ALPHA": 0x184, "MACHINE_SH3E": 0x01A4, "MACHINE_ALPHA64": 0x284,
        "MACHINE_AXP64": 0x284, "MACHINE_TRICORE": 0x520, "MACHINE_CEF": 0xCEF, "MACHINE_CEE": 0xC0EE,
    }  # fmt: skip
    SUBSYSTEM: ClassVar[dict[str, int]] = {
        "SUBSYSTEM_UNKNOWN": 0, "SUBSYSTEM_NATIVE": 1, "SUBSYSTEM_WINDOWS_GUI": 2, "SUBSYSTEM_WINDOWS_CUI": 3,
        "SUBSYSTEM_OS2_CUI": 5, "SUBSYSTEM_POSIX_CUI": 7, "SUBSYSTEM_NATIVE_WINDOWS": 8,
        "SUBSYSTEM_WINDOWS_CE_GUI": 9, "SUBSYSTEM_EFI_APPLICATION": 10, "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": 11,
        "SUBSYSTEM_EFI_RUNTIME_DRIVER": 12, "SUBSYSTEM_EFI_ROM_IMAGE": 13, "SUBSYSTEM_XBOX": 14,
        "SUBSYSTEM_WINDOWS_BOOT_APPLICATION": 16,
    }  # fmt: skip
    CHARACTERISTICS: ClassVar[dict[str, int]] = {
        "RELOCS_STRIPPED": 0x1, "EXECUTABLE_IMAGE": 0x2, "LINE_NUMS_STRIPPED": 0x4, "LOCAL_SYMS_STRIPPED": 0x8,
        "AGGRESIVE_WS_TRIM": 0x10, "LARGE_ADDRESS_AWARE": 0x20, "BYTES_REVERSED_LO": 0x80, "MACHINE_32BIT": 0x100,
        "DEBUG_STRIPPED": 0x200, "REMOVABLE_RUN_FROM_SWAP": 0x400, "NET_RUN_FROM_SWAP": 0x800, "SYSTEM": 0x1000,
        "DLL": 0x2000, "UP_SYSTEM_ONLY": 0x4000, "BYTES_REVERSED_HI": 0x8000,
    }  # fmt: skip
    DLL_CHARACTERISTICS: ClassVar[dict[str, int]] = {
        "HIGH_ENTROPY_VA": 0x20, "DYNAMIC_BASE": 0x40, "FORCE_INTEGRITY": 0x80, "NX_COMPAT": 0x100,
        "NO_ISOLATION": 0x200, "NO_SEH": 0x400, "NO_BIND": 0x800, "APPCONTAINER": 0x1000, "WDM_DRIVER": 0x2000,
        "GUARD_CF": 0x4000, "TERMINAL_SERVER_AWARE": 0x8000,
    }  # fmt: skip
    SECTION: ClassVar[dict[str, int]] = {
        "SECTION_NO_PAD": 0x8, "SECTION_CNT_CODE": 0x20, "SECTION_CNT_INITIALIZED_DATA": 0x40,
        "SECTION_CNT_UNINITIALIZED_DATA": 0x80, "SECTION_LNK_OTHER": 0x100, "SECTION_LNK_INFO": 0x200,
        "SECTION_LNK_REMOVE": 0x800, "SECTION_LNK_COMDAT": 0x1000, "SECTION_NO_DEFER_SPEC_EXC": 0x4000,
        "SECTION_GPREL": 0x8000, "SECTION_MEM_PURGEABLE": 0x20000, "SECTION_MEM_LOCKED": 0x40000,
        "SECTION_MEM_PRELOAD": 0x80000, "SECTION_ALIGN_1BYTES": 0x100000, "SECTION_ALIGN_MASK": 0xF00000,
        "SECTION_LNK_NRELOC_OVFL": 0x1000000, "SECTION_MEM_DISCARDABLE": 0x2000000,
        "SECTION_MEM_NOT_CACHED": 0x4000000, "SECTION_MEM_NOT_PAGED": 0x8000000, "SECTION_MEM_SHARED": 0x10000000,
        "SECTION_MEM_EXECUTE": 0x20000000, "SECTION_MEM_READ": 0x40000000, "SECTION_MEM_WRITE": 0x80000000,
        "SECTION_SCALE_INDEX": 0x1,
    }  # fmt: skip
    DIRECTORY: ClassVar[dict[str, int]] = {
        "IMAGE_DIRECTORY_ENTRY_EXPORT": 0, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1, "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2,
        "IMAGE_DIRECTORY_ENTRY_EXCEPTION": 3, "IMAGE_DIRECTORY_ENTRY_SECURITY": 4,
        "IMAGE_DIRECTORY_ENTRY_BASERELOC": 5, "IMAGE_DIRECTORY_ENTRY_DEBUG": 6,
        "IMAGE_DIRECTORY_ENTRY_COPYRIGHT": 7, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE": 7,
        "IMAGE_DIRECTORY_ENTRY_GLOBALPTR": 8, "IMAGE_DIRECTORY_ENTRY_TLS": 9, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": 10,
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": 11, "IMAGE_DIRECTORY_ENTRY_IAT": 12,
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": 13, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": 14,
    }  # fmt: skip
    RESOURCE_TYPE: ClassVar[dict[str, int]] = {
        "RESOURCE_TYPE_CURSOR": 1, "RESOURCE_TYPE_BITMAP": 2, "RESOURCE_TYPE_ICON": 3, "RESOURCE_TYPE_MENU": 4,
        "RESOURCE_TYPE_DIALOG": 5, "RESOURCE_TYPE_STRING": 6, "RESOURCE_TYPE_FONTDIR": 7, "RESOURCE_TYPE_FONT": 8,
        "RESOURCE_TYPE_ACCELERATOR": 9, "RESOURCE_TYPE_RCDATA": 10, "RESOURCE_TYPE_MESSAGETABLE": 11,
        "RESOURCE_TYPE_GROUP_CURSOR": 12, "RESOURCE_TYPE_GROUP_ICON": 14, "RESOURCE_TYPE_VERSION": 16,
        "RESOURCE_TYPE_DLGINCLUDE": 17, "RESOURCE_TYPE_PLUGPLAY": 19, "RESOURCE_TYPE_VXD": 20,
        "RESOURCE_TYPE_ANICURSOR": 21, "RESOURCE_TYPE_ANIICON": 22, "RESOURCE_TYPE_HTML": 23,
        "RESOURCE_TYPE_MANIFEST": 24,
    }  # fmt: skip

    @staticmethod
    def schema() -> Struct:
        """Every field `pe` declares, undefined: what a file that is not a PE gets."""
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
        fields: dict[str, Any] = dict(Constants.PE)
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
        fields |= Pe.functions_undefined()
        fields["is_pe"] = 0  # YARA sets it for every file it scans, before looking for a header
        return Struct(fields)

    #: each function's overloads (argument kinds, result kind), as `pe` declares them
    SIGNATURES: ClassVar[dict[str, tuple[tuple[tuple[str, ...], str], ...]]] = {
        "calculate_checksum": (((), "int"),), "imphash": (((), "str"),),
        "section_index": ((("str",), "int"), (("int",), "int")),
        "exports": ((("str",), "int"), (("r",), "int"), (("int",), "int")),
        "exports_index": ((("str",), "int"), (("int",), "int"), (("r",), "int")),
        "imports": ((("str", "str"), "int"), (("str", "int"), "int"), (("str",), "int"), (("r", "r"), "int"),
                    (("int", "str", "str"), "int"), (("int", "str", "int"), "int"), (("int", "str"), "int"),
                    (("int", "r", "r"), "int")),
        "import_rva": ((("str", "str"), "int"), (("str", "int"), "int")),
        "delayed_import_rva": ((("str", "str"), "int"), (("str", "int"), "int")),
        "locale": ((("int",), "int"),), "language": ((("int",), "int"),),
        "is_dll": (((), "int"),), "is_32bit": (((), "int"),), "is_64bit": (((), "int"),),
        "rva_to_offset": ((("int",), "int"),),
    }  # fmt: skip

    @staticmethod
    def _undefined_of(kind: str) -> Any:
        undefined = UNDEF_STR if kind == "str" else UNDEF_INT
        return lambda *_: undefined

    @staticmethod
    def functions_undefined() -> dict[str, Any]:
        """Every function, returning its kind's undefined: what a file that is not a PE gets."""
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
        """YARA's `module_load`: nothing but `is_pe = 0` unless `pe_get_header` accepts the
        file; then `pe_parse_header`, the Rich header, the debug directory, signatures, imports,
        delay-load imports and exports, each directory read where the header puts it."""
        img = Image.header(data)
        if img is None:
            return
        b = _Bytes(data)
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
        f.update(size_of_code=size_code, size_of_initialized_data=size_init, size_of_uninitialized_data=size_uninit,
                 base_of_code=base_code)  # fmt: skip
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
        # sections
        sec_at = opt + opt_size
        sections: list[tuple[bytes, int, int, int, int, int]] = []
        highest_ofs = highest_size = 0
        for i in range(min(nsec, Image.MAX_SECTIONS)):
            at = sec_at + 40 * i
            if not img.fits(at, 40):
                break
            s = struct.unpack_from("<8sIIIIIIHHI", data, at)
            name = s[0].rstrip(b"\x00")
            full = Pe._full_section_name(img, symptr, nsym, name)
            sections.append((name, s[1], s[2], s[3], s[4], s[9]))
            f["sections"].items[i] = Struct({
                "name": name, "full_name": UNDEF_STR if full is None else full, "virtual_size": s[1],
                "virtual_address": s[2], "raw_data_size": s[3], "raw_data_offset": s[4], "pointer_to_relocations": s[5],
                "pointer_to_line_numbers": s[6], "number_of_relocations": s[7], "number_of_line_numbers": s[8],
                "characteristics": s[9],
            })  # fmt: skip
            if s[4] + s[3] > highest_ofs + highest_size:
                highest_ofs, highest_size = s[4], s[3]
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
        """`pe_get_section_full_name`: a `/<n>` name's string from the COFF string table, when
        it is printable and ends inside the file; the short name otherwise; None if neither."""
        if symptr == 0 or not name.startswith(b"/"):
            return name
        index = 0
        for c in name[1:8]:
            if not 0x30 <= c <= 0x39:
                break
            index = index * 10 + c - 0x30
        at = symptr + nsym * 18 + index
        length = 0
        while img.fits(at, length + 1):
            c = img.data[at + length]
            if c == 0:
                return img.data[at : at + length]
            if not 0x20 <= c <= 0x7E:
                return None
            length += 1
        return None

    MAX_IMPORTS: ClassVar[int] = 16384
    MAX_EXPORTS: ClassVar[int] = 16384
    FUNCTION_NAME: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9._?@$()<>]+")

    @staticmethod
    def _valid_dll(b: _Bytes, at: int) -> bytes | None:
        """YARA's `pe_valid_dll_name`: printable, none of `"*<>?|`, shorter than 256."""
        name = b.data[at : at + 256].split(b"\x00", 1)
        if len(name) < 2 and len(b.data) - at >= 256:
            return None
        text = name[0]
        if not text or any(c < 0x20 or c > 0x7E or c in b'"*<>?|' for c in text):
            return None
        return text

    @staticmethod
    def _imports(b: _Bytes, rva: int, rva_to_offset: Any, is64: bool, out: list[Any]) -> None:
        """The import table as YARA reads it: each library with at least one function, each
        function `(name, ordinal, rva)` -- named, or by ordinal with YARA's ordinal name -- its rva
        the slot in the import address table; a name YARA would reject is skipped."""
        at = rva_to_offset(rva)
        if at is None:
            return
        size = 8 if is64 else 4
        flag = 1 << (63 if is64 else 31)
        parsed, total = 0, 0
        while parsed < Pe.MAX_IMPORTS:
            d = b.u("<IIIII", at)
            if d is None or d[3] == 0:
                return
            parsed += 1
            original, _, _, name_rva, first = d
            at += 20
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
                elif is64 or entry <= 0x8000FFFF:
                    ordinal = entry & 0xFFFF
                    name = Constants.ordinal_name(dll, ordinal)
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
    def _delayed(
        b: _Bytes,
        rva: int,
        rva_to_offset: Any,
        is64: bool,
        image_base: int,
        size_of_image: int,
        out: list[Any],
    ) -> None:
        """Delay-load imports as YARA reads them (`pe_parse_delayed_imports`)."""
        at = rva_to_offset(rva)
        if at is None:
            return
        size = 8 if is64 else 4
        flag = 1 << (63 if is64 else 31)

        def normal(value: int) -> int:
            return value - image_base if value >= image_base else value

        while True:
            d = b.u("<IIIIIIII", at)
            if d is None or not any(d):
                return
            at += 32
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
                    funcs.append((Constants.ordinal_name(dll, ordinal), ordinal, func_at))
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
                    j: Struct({"name": _Bytes.or_undefined(n, UNDEF_STR), "ordinal": _Bytes.or_undefined(o), "rva": slot})
                    for j, (n, o, slot) in enumerate(funcs)
                }),
            })  # fmt: skip

    @staticmethod
    def _exports(
        f: dict[str, Any], b: _Bytes, directory: tuple[int, int], rva_to_offset: Any, out: list[Any]
    ) -> None:
        """The export table as YARA reads it (`pe_parse_exports`)."""
        at = rva_to_offset(directory[0])
        if at is None:
            return
        e = b.u("<IIHHIIIIIII", at)
        if e is None:
            return
        _, ts, _, _, name_rva, base, nfuncs, nnames, funcs_rva, names_rva, ords_rva = e
        count = min(nfuncs, Pe.MAX_EXPORTS)
        f["export_timestamp"] = ts
        name_off = rva_to_offset(name_rva)
        if name_off is not None and name_off > 0:
            f["dll_name"] = b.data[name_off:].split(b"\x00", 1)[0]
        names_off = rva_to_offset(names_rva) if nnames else None
        if nnames and names_off is None:
            return
        ords_off, funcs_off = rva_to_offset(ords_rva), rva_to_offset(funcs_rva)
        if ords_off is None or funcs_off is None:
            return
        if len(b.data) - ords_off < 2 * count or len(b.data) - funcs_off < 4 * count:
            return
        named = min(nnames, count)
        ordinals = [b.one("<H", ords_off + 2 * j) for j in range(count)]
        start, end = at, at + directory[1]
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

    MAX_RESOURCES: ClassVar[int] = 65536

    @staticmethod
    def _resources(f: dict[str, Any], img: Image) -> None:
        """`pe_iterate_resources` with `pe_collect_resources`: three levels (type, name,
        language), each leaf a resource; the last value seen at a level is the one a leaf gets,
        and a zero entry ends its directory, as YARA's loop does."""
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
            at = base + (name & 0x7FFFFFFF)
            if not img.fits(at, 2) or not img.fits(at, 2 + img.u16(at) * 2):
                return None
            return data[at : at + 2 + img.u16(at) * 2]

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
                value = state[{"type": "type", "id": "id", "language": "language"}[num]]
                if string is not None:
                    fields[key] = string[2:]
                elif value != -1:
                    fields[num] = value
            found.items[index] = Struct(fields)
            if state["type"] == 16 and offset >= 0:
                Pe._version_info(f, data, offset)

        def walk(at: int, level: int, strings: list[bytes | None]) -> None:
            chars, _, _, _, named, ids = struct.unpack_from("<IIHHHH", data, at)
            if chars != 0 or named > 32768 or ids > 32768:
                return
            total = named + ids
            entry = at + 16
            if not img.fits(entry, total * 8):
                return
            for _ in range(total):
                name, child = struct.unpack_from("<II", data, entry)
                if child == 0:
                    return  # YARA's `continue` skips the step to the next entry: it sees this one again
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
        """`pe_parse_version_info`: StringFileInfo walked as YARA walks it, through the file (not
        the resource's length), each key kept to 63 bytes and each value to 255, a UTF-16 unit
        kept as its low byte and cut at the first unit whose low byte is zero (`strlcpy_w`)."""
        n = len(data)

        def fits(at: int, size: int) -> bool:
            return size <= n and 0 <= at <= n - size

        def u16(at: int) -> int:
            return data[at] | (data[at + 1] << 8)

        def align(at: int, add: int) -> int:
            return at + ((add + 3) & ~3)

        def wide_fits(at: int) -> bool:
            if not 0 <= at < n:
                return False
            i = at
            while n - i >= 2:
                if data[i] == 0 and data[i + 1] == 0:
                    return True
                i += 2
            return False

        def wide_len(at: int) -> int:
            i = at
            while data[i] or data[i + 1]:
                i += 2
            return (i - at) // 2

        def same(at: int, text: bytes) -> bool:
            i = 0
            while i < len(text) and data[at + 2 * i] == text[i] and data[at + 2 * i + 1] == 0:
                i += 1
            return i == len(text) and data[at + 2 * i + 1] == 0 and data[at + 2 * i] == 0

        def narrow(at: int, size: int) -> bytes:
            out = bytearray()
            while size > 1 and at < n and data[at] != 0:
                out.append(data[at])
                at += 2
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
        """`pe_parse_debug_directory`: the first CodeView entry (NB10, RSDS or MTOC) whose path
        ends within 260 bytes, found through its RVA and else its file pointer."""
        directory = img.directory(6)
        if directory is None or directory[1] == 0 or directory[0] == 0:
            return
        base = img.rva_to_offset(directory[0])
        if base < 0:
            return
        data = img.data
        for i in range(directory[1] // 28):
            at = base + 28 * i
            if not img.fits(at, 28):
                break
            kind, _, address, pointer = struct.unpack_from("<IIII", data, at + 12)
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
        """`pe_parse_rich_signature`: "Rich" sought back from the PE header a dword at a time, then
        the "DanS" its key unmasks, sought back from there; neither below the DOS header."""
        n = len(data)
        if n < 64 or data[:2] != b"MZ":
            return
        nt = int.from_bytes(data[0x3C:0x40], "little")
        if nt > n + 4 or nt < 4:
            return

        def dword(at: int) -> int:
            return int.from_bytes(data[at : at + 4].ljust(4, b"\x00"), "little")

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
        """`pe_parse_certificates`: the security directory read where the header puts it,
        whatever `NumberOfRvaAndSizes` says, and checked to lie in the file."""
        at = pe_off + 24 + (0x70 if is64 else 0x60) + 4 * 8
        if at + 8 > len(data):
            return
        va, size = struct.unpack_from("<II", data, at)
        if va == 0 or va > len(data) or size > len(data) or va + size > len(data):
            return
        found, signed = Authenticode.module_values(data)
        f["number_of_signatures"] = len(found)
        f["is_signed"] = int(signed)
        for i, sig in enumerate(found):
            f["signatures"].items[i] = sig

    UNDEFINED_VALUE: ClassVar[int] = (
        0xFFFABADAFABADAFF  # YR_UNDEFINED, as an integer field reads when missing
    )

    @staticmethod
    def _search(pattern: Any, text: bytes) -> int:
        """A regular expression run over a C string: where its match ends, or -1."""
        return int(pattern.run(text.split(b"\x00", 1)[0]))

    @staticmethod
    def _c(text: bytes) -> bytes:
        return text.split(b"\x00", 1)[0]

    @staticmethod
    def _lower(text: bytes) -> bytes:
        return bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in text)

    @staticmethod
    def _functions(f: dict[str, Any], img: Image, sections: list[Any], imports: list[Any], delayed: list[Any],
                   exports: list[Any], chars: int) -> None:  # fmt: skip
        """The `pe` functions, each as YARA defines it."""
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
            return hashlib.md5(b",".join(parts)).hexdigest().encode()  # noqa: S324 - imphash is defined as MD5

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
            at = img.opt + 64
            csum = 0
            size = len(data)
            for i in range(size // 4 + 1):
                if 4 * i == at:
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

    @staticmethod
    def _signed64(value: int) -> int:
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value & (1 << 63) else value


class Elf:
    @staticmethod
    def schema() -> Struct:
        u, s = UNDEF_INT, UNDEF_STR
        consts = dict(Constants.ELF)
        section = Struct({"type": u, "flags": u, "address": u, "name": s, "size": u, "offset": u})
        segment = Struct(dict.fromkeys(("type", "flags", "offset", "virtual_address", "physical_address", "file_size", "memory_size", "alignment"), u))  # fmt: skip
        symbol = Struct({"name": s, "value": u, "size": u, "type": u, "bind": u, "shndx": u})
        fields: dict[str, Any] = dict(consts)
        fields |= dict.fromkeys(("type", "machine", "entry_point", "number_of_sections", "sh_offset", "sh_entry_size", "number_of_segments", "ph_offset", "ph_entry_size", "dynamic_section_entries", "symtab_entries", "dynsym_entries"), u)  # fmt: skip
        fields |= {"sections": Array(section), "segments": Array(segment), "dynamic": Array(Struct({"type": u, "val": u})),
                   "symtab": Array(symbol), "dynsym": Array(symbol),
                   "telfhash": Values.fn(((), lambda: UNDEF_STR, "str")), "import_md5": Values.fn(((), lambda: UNDEF_STR, "str"))}  # fmt: skip
        return Struct(fields)

    @staticmethod
    def module(data: bytes) -> Struct:
        root = Elf.schema()
        with contextlib.suppress(IndexError, ValueError, struct.error):
            Elf._parse(root, data)
        return root

    SHN_LORESERVE: ClassVar[int] = 0xFF00
    PN_XNUM: ClassVar[int] = 0xFFFF

    @staticmethod
    def _parse(root: Struct, data: bytes) -> None:
        """YARA's `module_load` and `parse_elf_header`, guard for guard: the tables read with
        the sizes the format fixes (not the header's entry sizes) when the whole table fits,
        the last symbol table of each kind wins, and the dynamic table comes from the
        `PT_DYNAMIC` segment, as YARA reads them."""
        f = root.fields
        n = len(data)
        if n < 16 or data[:4] != b"\x7fELF":
            return
        cls, endian = data[4], data[5]
        if cls not in (1, 2) or endian not in (1, 2) or n <= (52 if cls == 1 else 64):
            return
        e = "<" if endian == 1 else ">"
        bits = 32 if cls == 1 else 64
        mask = (1 << bits) - 1
        word = "I" if cls == 1 else "Q"
        (etype, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(e + "HHI" + word * 3 + "IHHHHHH", data, 16)  # fmt: skip
        # `elf->sh_entry_count` compared unswapped where YARA forgets to swap it
        raw_shnum = struct.unpack_from(
            "<H", data, 16 + 2 + 2 + 4 + 3 * (bits // 8) + 4 + 2 + 2 + 2 + 2
        )[0]
        f.update(type=etype, machine=machine, sh_offset=shoff, sh_entry_size=shentsize, number_of_sections=shnum,
                 ph_offset=phoff, ph_entry_size=phentsize, number_of_segments=phnum)  # fmt: skip
        sec_size, seg_size, sym_size, dyn_size = (40, 32, 16, 8) if cls == 1 else (64, 56, 24, 16)
        sec_fmt = e + ("IIIIIIIIII" if cls == 1 else "IIQQQQIIQQ")
        seg_fmt = e + ("IIIIIIII" if cls == 1 else "IIQQQQQQ")

        def section(i: int) -> tuple[int, ...]:
            return struct.unpack_from(sec_fmt, data, shoff + i * sec_size)

        def segment(i: int) -> tuple[int, ...]:
            p = struct.unpack_from(seg_fmt, data, phoff + i * seg_size)
            # (type, flags, offset, virtual_address, physical_address, file_size, memory_size, alignment)
            return (p[0], p[6], p[1], p[2], p[3], p[4], p[5], p[7]) if cls == 1 else p

        if entry:
            f["entry_point"] = Elf._rva_to_offset(
                data, etype, entry, phoff, phnum, shoff, shnum, section, segment, mask
            )
        symtab: tuple[int, int, int, int] | None = None
        dynsym: tuple[int, int, int, int] | None = None
        if (
            shnum < Elf.SHN_LORESERVE
            and shstrndx < shnum
            and shoff < n
            and shoff + shnum * sec_size <= n
        ):
            names_at = section(shstrndx)[4]
            str_table = names_at if names_at < n else None
            for i in range(shnum):
                name, stype, flags, addr, offset, size, link, _, _, _ = section(i)
                fields: dict[str, Any] = {
                    "type": stype,
                    "flags": flags,
                    "address": addr,
                    "size": size,
                    "offset": offset,
                }
                if name < n and str_table is not None and str_table > 0:
                    fields["name"] = Elf._string(data, str_table, n, name)
                f["sections"].items[i] = Struct(
                    f["sections"].proto.fields | {k: v for k, v in fields.items() if v is not None}
                )
                if stype in (2, 11) and link < raw_shnum:
                    at = shoff + link * sec_size
                    if at + sec_size <= n:
                        linked = struct.unpack_from(sec_fmt, data, at)
                        if linked[1] == 3:
                            table = (offset, size & mask, linked[4], linked[5] & mask)
                            if stype == 2:
                                symtab = table
                            else:
                                dynsym = table
            lists: dict[str, list[tuple[bytes | None, int, int, int, int]]] = {}
            for kind, chosen in (("symtab", symtab), ("dynsym", dynsym)):
                if chosen is None:
                    continue
                sym_at, sym_len, str_at, str_len = chosen
                if not (
                    str_len <= n
                    and str_at + str_len <= n
                    and sym_len <= n
                    and sym_at + sym_len <= n
                ):
                    continue
                symbols = lists[kind] = []
                for j in range(sym_len // sym_size):
                    at = sym_at + j * sym_size
                    if cls == 1:
                        st_name, value, size, info, other, shndx = struct.unpack_from(
                            e + "IIIBBH", data, at
                        )
                    else:
                        st_name, info, other, shndx, value, size = struct.unpack_from(
                            e + "IBBHQQ", data, at
                        )
                    sym_name = Elf._symbol_name(data, str_at, str_at + str_len, st_name)
                    entry_fields: dict[str, Any] = {
                        "bind": info >> 4,
                        "type": info & 0xF,
                        "shndx": shndx,
                        "value": value,
                        "size": size,
                    }
                    if sym_name is not None:
                        entry_fields["name"] = sym_name
                    f[kind].items[j] = Struct(f[kind].proto.fields | entry_fields)
                    symbols.append((sym_name, info >> 4, info & 0xF, shndx, other & 3))
                f[kind + "_entries"] = len(symbols)
            Elf._functions(f, lists)
        if 0 < phnum < Elf.PN_XNUM and phoff < n and phoff + phnum * seg_size <= n:
            for i in range(phnum):
                seg = segment(i)
                f["segments"].items[i] = Struct(dict(zip(("type", "flags", "offset", "virtual_address", "physical_address", "file_size", "memory_size", "alignment"), seg, strict=True)))  # fmt: skip
                if seg[0] == 2:
                    at = seg[2]
                    j = 0
                    tag_fmt = e + (
                        ("i" if endian == 1 else "I") + "I"
                        if cls == 1
                        else ("q" if endian == 1 else "Q") + "Q"
                    )
                    while dyn_size <= n and at + dyn_size <= n:
                        tag, val = struct.unpack_from(tag_fmt, data, at)
                        f["dynamic"].items[j] = Struct({"type": tag, "val": val})
                        j += 1
                        at += dyn_size
                        if tag == 0:
                            break
                    f["dynamic_section_entries"] = j

    @staticmethod
    def _rva_to_offset(data: bytes, etype: int, rva: int, phoff: int, phnum: int, shoff: int, shnum: int,
                       section: Any, segment: Any, mask: int) -> Any:  # fmt: skip
        """`elf_rva_to_offset`: through the program headers for an executable, the sections
        that hold data otherwise; undefined where none holds the address."""
        n = len(data)
        if etype == 2:
            if (
                phoff == 0
                or phoff > n
                or phoff + phnum * (32 if mask == 0xFFFFFFFF else 56) > n
                or phnum == 0
            ):
                return UNDEF_INT
            for i in range(phnum):
                _, _, offset, vaddr, _, _, msize, _ = segment(i)
                if vaddr <= rva < (vaddr + msize) & mask:
                    return (offset + (rva - vaddr)) & ((1 << 64) - 1)
            return UNDEF_INT
        if (
            shoff == 0
            or shoff > n
            or shoff + shnum * (40 if mask == 0xFFFFFFFF else 64) > n
            or shnum == 0
        ):
            return UNDEF_INT
        for i in range(shnum):
            _, stype, _, addr, offset, size, _, _, _, _ = section(i)
            if stype not in (0, 8) and addr <= rva < (addr + size) & mask:
                return (offset + (rva - addr)) & ((1 << 64) - 1)
        return UNDEF_INT

    @staticmethod
    def _string(data: bytes, base: int, limit: int, index: int) -> bytes | None:
        """`str_table_entry`: the NUL-terminated string at `index`, when the table starts with
        NUL and the string ends before `limit`."""
        if base >= limit or data[base] != 0 or index >= 1 << 31:
            return None
        at = base + index
        if at >= limit:
            return None
        end = data.find(b"\x00", at, limit)
        return None if end < 0 else data[at:end]

    @staticmethod
    def _symbol_name(data: bytes, base: int, limit: int, index: int) -> bytes | None:
        return Elf._string(data, base, limit, index)

    @staticmethod
    def _functions(
        f: dict[str, Any], lists: dict[str, list[tuple[bytes | None, int, int, int, int]]]
    ) -> None:
        """`telfhash()` and `import_md5()` over the dynamic symbols, else the static ones."""
        symbols = lists.get("dynsym", lists.get("symtab"))
        if symbols is None:
            return
        excluded = {
            b"__libc_start_main",
            b"main",
            b"abort",
            b"cachectl",
            b"cacheflush",
            b"puts",
            b"atol",
            b"malloc_trim",
        }
        clean = sorted(
            Elf._lower(name) for name, bind, kind, _, visibility in symbols
            if name is not None and bind == 1 and kind == 2 and visibility == 0
            and not name.startswith((b".", b"_")) and not name.endswith(b"64")
            and not name.startswith((b"str", b"mem")) and name not in excluded
        )  # fmt: skip
        telfhash: Any = Tlsh.digest(b",".join(clean)) if clean else UNDEF_STR
        imports = sorted(
            Elf._lower(name) for name, _, _, shndx, _ in symbols if name and shndx == 0
        )
        md5: Any = hashlib.md5(b",".join(imports)).hexdigest().encode() if imports else UNDEF_STR  # noqa: S324 - YARA's import hash is MD5
        f["telfhash"] = Values.fn(((), lambda: telfhash, "str"))
        f["import_md5"] = Values.fn(((), lambda: md5, "str"))

    @staticmethod
    def _lower(name: bytes) -> bytes:
        return bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in name)


__all__ = ["Elf", "Pe"]
