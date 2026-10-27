"""The `pe` module reader for cordon-rule, built from a declared schema.

A PE file is reached through its DOS stub (MZ, e_lfanew) to the PE signature, the COFF file header and the
optional header (PE32 or PE32+); from there the section table, the data directories, the import, delayed-
import and export tables, resources and their version information, the Rich stub, the debug (PDB) entry and
the certificate table. `ImageMap` (rule_layout) accepts the image and maps a virtual address to a file
offset, shared with the .NET reader. Each fixed structure is described once as a `Layout` and read through a
`Cursor`; the heavy arrays decode on access. `data()` returns plain dicts and lists, an absent key being
undefined, exactly as the reference reports an undefined field by omitting it.

Values follow the reference's `pe` module; bounds live in the Cursor, so a truncated or malformed image
yields a defined, partial result rather than a crash.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_layout import (
    ABSENT,
    U8,
    U16,
    U32,
    U64,
    Blob,
    Cursor,
    Grid,
    ImageMap,
    Layout,
)
from cordon_scanner.detect.binary.rule_tables import Tables
from cordon_scanner.detect.binary.rule_values import (
    Call,
    Keyed,
    Legacy,
    Record,
    Scalar,
    Seq,
    Sig,
)
from cordon_scanner.detect.binary.yara_authenticode import Authenticode

INT, TEXT = Scalar.INT, Scalar.TEXT


class Shape:
    """Every fixed PE structure described once as a Layout (little-endian). The optional header has a 32- and
    a 64-bit form that differ after base-of-code: PE32 has base_of_data and 32-bit image base and stack/heap
    sizes, PE32+ drops base_of_data and widens those to 64 bits."""

    COFF :ClassVar [Layout ]=Layout ((
    ("machine",U16 ),("number_of_sections",U16 ),("timestamp",U32 ),
    ("pointer_to_symbol_table",U32 ),("number_of_symbols",U32 ),
    ("size_of_optional_header",U16 ),("characteristics",U16 ),
    ))  # fmt: skip

    _STD :ClassVar [tuple [tuple [str ,Any ],...]]=(
    ("magic",U16 ),("major_linker",U8 ),("minor_linker",U8 ),("size_of_code",U32 ),
    ("size_of_initialized_data",U32 ),("size_of_uninitialized_data",U32 ),
    ("entry_point",U32 ),("base_of_code",U32 ),
    )  # fmt: skip
    _WIN :ClassVar [tuple [tuple [str ,Any ],...]]=(
    ("section_alignment",U32 ),("file_alignment",U32 ),
    ("os_major",U16 ),("os_minor",U16 ),("image_major",U16 ),("image_minor",U16 ),
    ("subsys_major",U16 ),("subsys_minor",U16 ),("win32_version",U32 ),("size_of_image",U32 ),
    ("size_of_headers",U32 ),("checksum",U32 ),("subsystem",U16 ),("dll_characteristics",U16 ),
    )  # fmt: skip
    OPT32 :ClassVar [Layout ]=Layout ((
    *_STD ,("base_of_data",U32 ),("image_base",U32 ),*_WIN ,
    ("size_of_stack_reserve",U32 ),("size_of_stack_commit",U32 ),
    ("size_of_heap_reserve",U32 ),("size_of_heap_commit",U32 ),
    ("loader_flags",U32 ),("number_of_rva_and_sizes",U32 ),
    ))  # fmt: skip
    OPT64 :ClassVar [Layout ]=Layout ((
    *_STD ,("image_base",U64 ),*_WIN ,
    ("size_of_stack_reserve",U64 ),("size_of_stack_commit",U64 ),
    ("size_of_heap_reserve",U64 ),("size_of_heap_commit",U64 ),
    ("loader_flags",U32 ),("number_of_rva_and_sizes",U32 ),
    ))  # fmt: skip

    SECTION :ClassVar [Layout ]=Layout ((
    ("name",Blob (8 )),("virtual_size",U32 ),("virtual_address",U32 ),
    ("raw_data_size",U32 ),("raw_data_offset",U32 ),("pointer_to_relocations",U32 ),
    ("pointer_to_line_numbers",U32 ),("number_of_relocations",U16 ),
    ("number_of_line_numbers",U16 ),("characteristics",U32 ),
    ))  # fmt: skip

    IMPORT_DIR :ClassVar [Layout ]=Layout ((
    ("lookup",U32 ),("stamp",U32 ),("forwarder",U32 ),("name",U32 ),("address",U32 ),
    ))  # fmt: skip
    DELAY_DIR :ClassVar [Layout ]=Layout ((
    ("attributes",U32 ),("name",U32 ),("handle",U32 ),("address",U32 ),
    ("lookup",U32 ),("bound",U32 ),("unload",U32 ),("stamp",U32 ),
    ))  # fmt: skip
    EXPORT_DIR :ClassVar [Layout ]=Layout ((
    ("flags",U32 ),("stamp",U32 ),("major",U16 ),("minor",U16 ),("name",U32 ),
    ("base",U32 ),("count",U32 ),("name_count",U32 ),
    ("addresses",U32 ),("names",U32 ),("ordinals",U32 ),
    ))  # fmt: skip


class Pe:
    """The `pe` module reader."""

    MAX_SECTIONS: ClassVar[int] = 96
    MAX_IMPORTS: ClassVar[int] = 16384
    MAX_EXPORTS: ClassVar[int] = 16384
    MAX_RESOURCES: ClassVar[int] = 65536
    UNDEFINED_VALUE: ClassVar[int] = (
        0xFFFABADAFABADAFF  # the reference's sentinel, for a resource language
    )
    FUNCTION_NAME: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9._?@$()<>]+")

    #: Each function's overloads (parameter kinds, result scalar), in the order data() holds their callables.
    CALLS :ClassVar [dict [str ,tuple [Sig ,...]]]={
    "calculate_checksum":(Sig ((),INT ),),
    "imphash":(Sig ((),TEXT ),),
    "section_index":(Sig (("text",),INT ),Sig (("int",),INT )),
    "exports":(Sig (("text",),INT ),Sig (("regex",),INT ),Sig (("int",),INT )),
    "exports_index":(Sig (("text",),INT ),Sig (("int",),INT ),Sig (("regex",),INT )),
    "imports":(
    Sig (("text","text"),INT ),Sig (("text","int"),INT ),Sig (("text",),INT ),
    Sig (("regex","regex"),INT ),Sig (("int","text","text"),INT ),
    Sig (("int","text","int"),INT ),Sig (("int","text"),INT ),Sig (("int","regex","regex"),INT ),
    ),
    "import_rva":(Sig (("text","text"),INT ),Sig (("text","int"),INT )),
    "delayed_import_rva":(Sig (("text","text"),INT ),Sig (("text","int"),INT )),
    "locale":(Sig (("int",),INT ),),
    "language":(Sig (("int",),INT ),),
    "is_dll":(Sig ((),INT ),),
    "is_32bit":(Sig ((),INT ),),
    "is_64bit":(Sig ((),INT ),),
    "rva_to_offset":(Sig (("int",),INT ),),
    }  # fmt: skip

    _VERSION: ClassVar[Record] = Record({"major": INT, "minor": INT})
    _FUNCTION: ClassVar[Record] = Record({"name": TEXT, "ordinal": INT, "rva": INT})
    _IMPORT: ClassVar[Record] = Record(
        {"library_name": TEXT, "number_of_functions": INT, "functions": Seq(_FUNCTION)}
    )
    _SECTION :ClassVar [Record ]=Record ({
    **dict .fromkeys ((
    "characteristics","virtual_address","virtual_size","raw_data_offset","raw_data_size",
    "pointer_to_relocations","pointer_to_line_numbers","number_of_relocations",
    "number_of_line_numbers",
    ),INT ),
    "name":TEXT ,"full_name":TEXT ,
    })  # fmt: skip
    _RESOURCE :ClassVar [Record ]=Record ({
    **dict .fromkeys (("rva","offset","length","type","id","language"),INT ),
    "type_string":TEXT ,"name_string":TEXT ,"language_string":TEXT ,
    })  # fmt: skip
    _RICH :ClassVar [Record ]=Record ({
    "offset":INT ,"length":INT ,"key":INT ,"raw_data":TEXT ,"clear_data":TEXT ,
    "version_data":TEXT ,"version":Call (Sig (("int",),INT ),Sig (("int","int"),INT )),
    "toolid":Call (Sig (("int",),INT ),Sig (("int","int"),INT )),
    })  # fmt: skip

    #: the arrays the reference always presents (empty when nothing fills them); version_info is Keyed.
    ARRAYS :ClassVar [tuple [str ,...]]=(
    "sections","data_directories","resources","import_details","delayed_import_details",
    "export_details","signatures","version_info_list",
    )  # fmt: skip

    SCHEMA :ClassVar [Record ]=Record ({
    **dict .fromkeys (Tables .PE ,INT ),
    **dict .fromkeys ((
    "is_pe","machine","number_of_sections","timestamp","pointer_to_symbol_table",
    "number_of_symbols","size_of_optional_header","characteristics","entry_point",
    "entry_point_raw","image_base","number_of_rva_and_sizes","number_of_version_infos",
    "opthdr_magic","size_of_code","size_of_initialized_data","size_of_uninitialized_data",
    "base_of_code","base_of_data","section_alignment","file_alignment","win32_version_value",
    "size_of_image","size_of_headers","checksum","subsystem","dll_characteristics",
    "size_of_stack_reserve","size_of_stack_commit","size_of_heap_reserve","size_of_heap_commit",
    "loader_flags","number_of_resources","resource_timestamp","number_of_imports",
    "number_of_imported_functions","number_of_delayed_imports",
    "number_of_delayed_imported_functions","number_of_exports","export_timestamp",
    "number_of_signatures","is_signed",
    ),INT ),
    "dll_name":TEXT ,"pdb_path":TEXT ,
    "linker_version":_VERSION ,"os_version":_VERSION ,"image_version":_VERSION ,
    "subsystem_version":_VERSION ,"resource_version":_VERSION ,
    "overlay":Record ({"offset":INT ,"size":INT }),
    "rich_signature":_RICH ,
    "sections":Seq (_SECTION ),"data_directories":Seq (Record ({"virtual_address":INT ,"size":INT })),
    "resources":Seq (_RESOURCE ),"import_details":Seq (_IMPORT ),"delayed_import_details":Seq (_IMPORT ),
    "export_details":Seq (Record (
    {"name":TEXT ,"ordinal":INT ,"rva":INT ,"offset":INT ,"forward_name":TEXT }
    )),
    # bridged full-fidelity from yara_authenticode (nested certs, signer_info, valid_on); rule_signature
    # replaces this one declaration and its data() call site.
    "signatures":Seq (Legacy .declared (Authenticode .proto ())),
    "version_info":Keyed (TEXT ),"version_info_list":Seq (Record ({"key":TEXT ,"value":TEXT })),
    **{name :Call (*sigs )for name ,sigs in CALLS .items ()},
    })  # fmt: skip

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = dict(Tables.PE)  # the module constants are present for every file
        for name in Pe.ARRAYS:
            out[name] = {}
        out["version_info"] = {}
        for (
            name,
            sigs,
        ) in Pe.CALLS.items():  # undefined until a PE fills them (each callable returns None)
            out[name] = tuple((lambda *_a: None) for _ in sigs)
        out["is_pe"] = 0  # set for every file scanned, before a header is looked for
        Pe._read(out, file)
        return out

    @staticmethod
    def _read(out: dict[str, Any], file: bytes) -> None:
        cur = Cursor(file)
        img = ImageMap.accept(
            cur, strict=True
        )  # the pe RVA rule: a non-fitting section header fails the map
        if img is None:
            return
        opt = img.opt
        is64 = img.is64
        coff = Shape.COFF.read(cur, img.nt + 4)
        out["is_pe"] = 1
        out.update(
            machine=coff["machine"],
            number_of_sections=coff["number_of_sections"],
            timestamp=coff["timestamp"],
            pointer_to_symbol_table=coff["pointer_to_symbol_table"],
            number_of_symbols=coff["number_of_symbols"],
            size_of_optional_header=coff["size_of_optional_header"],
            characteristics=coff["characteristics"],
        )
        out.update(
            number_of_resources=0, number_of_version_infos=0, number_of_signatures=0, is_signed=0
        )
        header = (Shape.OPT64 if is64 else Shape.OPT32).read(cur, opt)
        out["opthdr_magic"] = header["magic"]
        entry = header["entry_point"]
        out["entry_point"] = img.to_offset(entry)
        out["entry_point_raw"] = entry
        out["image_base"] = header["image_base"]
        out["number_of_rva_and_sizes"] = header["number_of_rva_and_sizes"]
        out["linker_version"] = {"major": header["major_linker"], "minor": header["minor_linker"]}
        out.update(
            size_of_code=header["size_of_code"],
            size_of_initialized_data=header["size_of_initialized_data"],
            size_of_uninitialized_data=header["size_of_uninitialized_data"],
            base_of_code=header["base_of_code"],
        )
        if not is64:
            out["base_of_data"] = header["base_of_data"]
        out.update(
            section_alignment=header["section_alignment"],
            file_alignment=header["file_alignment"],
            win32_version_value=header["win32_version"],
            size_of_image=header["size_of_image"],
            size_of_headers=header["size_of_headers"],
            checksum=header["checksum"],
            subsystem=header["subsystem"],
            dll_characteristics=header["dll_characteristics"],
        )
        out["os_version"] = {"major": header["os_major"], "minor": header["os_minor"]}
        out["image_version"] = {"major": header["image_major"], "minor": header["image_minor"]}
        out["subsystem_version"] = {
            "major": header["subsys_major"],
            "minor": header["subsys_minor"],
        }
        out.update(
            size_of_stack_reserve=header["size_of_stack_reserve"],
            size_of_stack_commit=header["size_of_stack_commit"],
            size_of_heap_reserve=header["size_of_heap_reserve"],
            size_of_heap_commit=header["size_of_heap_commit"],
            loader_flags=header["loader_flags"],
        )
        dd_at = opt + (112 if is64 else 96)
        directories: dict[int, Any] = {}
        for i in range(min(Pe._int(header["number_of_rva_and_sizes"]), 16)):
            if not cur.fits(dd_at + 8 * i, 8):
                break
            directories[i] = {
                "virtual_address": cur.uint(dd_at + 8 * i, 4),
                "size": cur.uint(dd_at + 8 * i + 4, 4),
            }
        out["data_directories"] = directories
        Pe._sections(out, cur, img, coff)
        Pe._read_imports(out, cur, img, is64, header)
        out["number_of_exports"] = 0
        directory = img.directory(0)
        if directory is not None and directory[0]:
            Pe._read_exports(out, cur, img, directory)
        Pe._read_resources(out, cur, img)
        out["number_of_version_infos"] = len(out["version_info_list"])
        Pe._read_pdb(out, cur, img)
        Pe._read_rich(out, cur)
        Pe._read_signatures(out, cur, img.nt, is64)
        Pe._import_calls(out)
        Pe._import_rva_calls(out)
        Pe._export_calls(out)
        Pe._section_calls(out, cur, img, Pe._int(coff["characteristics"]))
        Pe._resource_calls(out)

    @staticmethod
    def _int(value: Any) -> int:
        """A header integer as a plain count; 0 when the field did not fit (ABSENT)."""
        return value if isinstance(value, int) else 0

    @staticmethod
    def _sections(out: dict[str, Any], cur: Cursor, img: ImageMap, coff: dict[str, Any]) -> None:
        """The section table read in bulk, and from it the overlay (the highest raw_offset + raw_size, as the
        reference computes it). A ``/<n>`` section name is resolved to its long COFF-string-table name."""
        nsec = Pe._int(coff["number_of_sections"])
        symptr = Pe._int(coff["pointer_to_symbol_table"])
        nsym = Pe._int(coff["number_of_symbols"])
        sec_at = img.opt + Pe._int(coff["size_of_optional_header"])
        grid = Grid(cur, sec_at, Shape.SECTION, min(nsec, Pe.MAX_SECTIONS), None)
        rows = grid.tuples()
        pos = {name: i for i, name in enumerate(grid.names)}
        plain =(
        "virtual_size","virtual_address","raw_data_size","raw_data_offset",
        "pointer_to_relocations","pointer_to_line_numbers","number_of_relocations",
        "number_of_line_numbers","characteristics",
        )  # fmt: skip
        sections: dict[int, Any] = {}
        highest_ofs = highest_size = 0
        for i, row in enumerate(rows):
            name = row[pos["name"]].rstrip(b"\x00")
            entry: dict[str, Any] = {k: row[pos[k]] for k in plain}
            entry["name"] = name
            full = Pe._section_long_name(cur, symptr, nsym, name)
            if full is not None:
                entry["full_name"] = full
            sections[i] = entry
            if entry["raw_data_offset"] + entry["raw_data_size"] > highest_ofs + highest_size:
                highest_ofs, highest_size = entry["raw_data_offset"], entry["raw_data_size"]
        out["sections"] = sections
        last = highest_ofs + highest_size
        out["overlay"] = (
            {"offset": last, "size": cur.n - last}
            if last and cur.n > last
            else {"offset": 0, "size": 0}
        )

    @staticmethod
    def _section_long_name(cur: Cursor, symptr: int, nsym: int, name: bytes) -> bytes | None:
        """A ``/<n>`` section name resolved through the COFF string table to its long name, kept only when
        printable and terminated inside the file; the short name when it is not a ``/<n>`` form."""
        if symptr == 0 or not name.startswith(b"/"):
            return name
        index = 0
        for c in name[1:8]:
            if not 0x30 <= c <= 0x39:
                break
            index = index * 10 + c - 0x30
        where = symptr + nsym * 18 + index
        length = 0
        while cur.fits(where, length + 1):
            c = cur.data[where + length]
            if c == 0:
                return cur.data[where : where + length]
            if not 0x20 <= c <= 0x7E:
                return None
            length += 1
        return None

    @staticmethod
    def _off(img: ImageMap, rva: int) -> int | None:
        """``ImageMap.to_offset`` in the reference's convention: None (not -1) when nothing maps the RVA."""
        offset = img.to_offset(rva)
        return None if offset < 0 else offset

    @staticmethod
    def _dll_name(cur: Cursor, at: int) -> bytes | None:
        """A library name at ``at``: printable, free of ``"*<>?|``, NUL-terminated inside a 256-byte window."""
        parts = cur.data[at : at + 256].split(b"\x00", 1)
        if len(parts) < 2 or not parts[0]:
            return None
        text = parts[0]
        return None if any(ch < 0x20 or ch > 0x7E or ch in b'"*<>?|' for ch in text) else text

    @staticmethod
    def _read_imports(
        out: dict[str, Any], cur: Cursor, img: ImageMap, is64: bool, header: dict[str, Any]
    ) -> None:
        """Both import tables into the out dict, each as a library list and the two counts the module reports."""
        standard = list(Pe._standard_imports(cur, img, is64))
        out["number_of_imports"] = len(standard)
        out["number_of_imported_functions"] = sum(len(entries) for _, entries in standard)
        out["import_details"] = Pe._as_details(standard)
        delayed = list(
            Pe._delay_imports(
                cur, img, is64, Pe._int(header["image_base"]), Pe._int(header["size_of_image"])
            )
        )
        out["number_of_delayed_imports"] = len(delayed)
        out["number_of_delayed_imported_functions"] = sum(len(entries) for _, entries in delayed)
        out["delayed_import_details"] = Pe._as_details(delayed)

    @staticmethod
    def _standard_imports(cur: Cursor, img: ImageMap, is64: bool) -> Any:
        """Walk IMAGE_IMPORT_DESCRIPTORs, yielding (library, entries); each entry is (name, ordinal, slot)
        taken from the lookup table (the import address table when the lookup is absent)."""
        directory = img.directory(1)
        at = Pe._off(img, directory[0]) if directory and directory[0] else None
        width = 8 if is64 else 4
        high = 1 << (width * 8 - 1)
        libraries = functions = 0
        while at is not None and cur.fits(at, 20) and libraries < Pe.MAX_IMPORTS:
            desc = Shape.IMPORT_DIR.read(cur, at)
            if not desc["name"]:
                return
            at += 20
            libraries += 1
            named = Pe._off(img, desc["name"])
            library = Pe._dll_name(cur, named) if named is not None else None
            if library is None:
                continue
            lookup = Pe._off(img, desc["lookup"])
            if lookup is None or lookup <= 0:
                lookup = Pe._off(img, desc["address"])
            if lookup is None:
                continue
            entries: list[Any] = []
            index = 0
            while functions < Pe.MAX_IMPORTS:
                word = cur.uint(lookup + width * index, width)
                if word is ABSENT or not word:
                    break
                name, ordinal = Pe._thunk(cur, img, word, high, library)
                slot = desc["address"] + width * index
                index += 1
                if name is not None and not Pe.FUNCTION_NAME.fullmatch(name):
                    continue
                if name is not None or ordinal is not None:
                    entries.append((name, ordinal, slot))
                    functions += 1
            if entries:
                yield library, entries

    @staticmethod
    def _thunk(
        cur: Cursor, img: ImageMap, word: int, high: int, library: bytes
    ) -> tuple[bytes | None, int | None]:
        """One standard-import lookup word -> (name, ordinal): the high bit with a low-16 ordinal names it by
        ordinal (anything in between is not an ordinal); otherwise the word is an RVA to a hint then a name."""
        if word & high:
            if word <= high | 0xFFFF:
                number = word & 0xFFFF
                return Tables.ordinal_name(library, number), number
            return None, None
        hint = Pe._off(img, word)
        if hint is not None and hint + 2 < cur.n:
            return cur.data[hint + 2 : hint + 2 + 512].split(b"\x00", 1)[0], None
        return None, None

    @staticmethod
    def _delay_imports(cur: Cursor, img: ImageMap, is64: bool, base: int, span: int) -> Any:
        """Walk the delay-load descriptors, yielding (library, entries). Addresses are RVAs, or for an old
        32-bit descriptor virtual addresses relative to the image base (rebased here)."""
        directory = img.directory(13)
        at = Pe._off(img, directory[0]) if directory and directory[0] else None
        width = 8 if is64 else 4
        high = 1 << (width * 8 - 1)

        def rebase(value: int) -> int:
            return value - base if value >= base else value

        while at is not None and cur.fits(at, 32):
            desc = Shape.DELAY_DIR.read(cur, at)
            if not any(desc.values()):
                return
            at += 32
            attrs = desc["attributes"]
            if attrs > 1:
                return
            name_rva, address, lookup = desc["name"], desc["address"], desc["lookup"]
            if not is64 and not attrs:
                name_rva, address, lookup = rebase(name_rva), rebase(address), rebase(lookup)
            if lookup >= span or address >= span or name_rva < 64 or lookup < 64:
                return
            named = Pe._off(img, name_rva)
            library = Pe._dll_name(cur, named) if named is not None else None
            if library is None:
                continue
            entries: list[Any] = []
            name_at, func_at = lookup, address
            while True:
                name_off, func_off = Pe._off(img, name_at), Pe._off(img, func_at)
                if name_off is None or func_off is None:
                    break
                name_word, func_word = cur.uint(name_off, width), cur.uint(func_off, width)
                if name_word is ABSENT or not name_word or func_word is ABSENT or not func_word:
                    break
                if name_word & high:
                    number = name_word & 0xFFFF
                    entries.append((Tables.ordinal_name(library, number), number, func_at))
                else:
                    target = name_word if attrs else rebase(name_word)
                    hint = Pe._off(img, target + 2)
                    if hint is None:
                        name_at += width
                        func_at += width
                        continue
                    entries.append(
                        (cur.data[hint : hint + 512].split(b"\x00", 1)[0], None, func_at)
                    )
                name_at += width
                func_at += width
            yield library, entries

    @staticmethod
    def _read_exports(
        out: dict[str, Any], cur: Cursor, img: ImageMap, directory: tuple[int, int]
    ) -> None:
        """The export table: each entry (name, ordinal, rva) -- a forwarded name when the target lies inside
        the export directory, otherwise an offset; ordinal is the directory base plus the index. The address,
        name and ordinal arrays are read only where they fit the file."""
        head = Pe._off(img, directory[0])
        if head is None or not cur.fits(head, 40):
            return
        table = Shape.EXPORT_DIR.read(cur, head)
        total = min(table["count"], Pe.MAX_EXPORTS)
        out["export_timestamp"] = table["stamp"]
        label = Pe._off(img, table["name"])
        if label is not None and label > 0:
            out["dll_name"] = cur.data[label:].split(b"\x00", 1)[0]
            # the function count must leave room past the name offset, or the table is not walked
        if total * 4 > cur.n - (label if label is not None else -1):
            return
        names_at = Pe._off(img, table["names"]) if table["name_count"] else None
        if table["name_count"] and (names_at is None or table["name_count"] * 4 > cur.n - names_at):
            return
        slots_at, addrs_at = Pe._off(img, table["ordinals"]), Pe._off(img, table["addresses"])
        if slots_at is None or addrs_at is None:
            return
        if cur.n - slots_at < 2 * total or cur.n - addrs_at < 4 * total:
            return
        named = min(table["name_count"], total)
        low, high = head, head + directory[1]
        # the first name slot (in order) that points at each export index, so a name is an O(1) lookup
        # rather than a scan of every slot per export -- a 16384-export table would otherwise be quadratic
        name_slot: dict[int, int] = {}
        if names_at is not None:
            for j in range(named):
                name_slot.setdefault(cur.uint(slots_at + 2 * j, 2), j)
        details: dict[int, Any] = {}
        for index in range(total):
            target = cur.uint(addrs_at + 4 * index, 4)
            entry: dict[str, Any] = {"ordinal": table["base"] + index, "rva": target}
            landing = Pe._off(img, target)
            if landing is not None and low < landing < high:
                entry["forward_name"] = cur.data[landing : landing + 512].split(b"\x00", 1)[0]
            elif landing is not None:
                entry["offset"] = landing
            if names_at is not None and index in name_slot:
                name = Pe._export_label(cur, img, names_at, name_slot[index])
                if name is not None:
                    entry["name"] = name
            details[index] = entry
        out["export_details"] = details
        out["number_of_exports"] = total

    @staticmethod
    def _export_label(cur: Cursor, img: ImageMap, names_at: int, j: int) -> bytes | None:
        """The exported name at name-table slot ``j``; None when that slot carries no resolvable name."""
        nrva = cur.uint(names_at + 4 * j, 4)
        noff = Pe._off(img, nrva) if nrva is not ABSENT else None
        if noff is not None and noff > 0:
            return cur.data[noff : noff + 512].split(b"\x00", 1)[0]
        return None

    @staticmethod
    def _read_resources(out: dict[str, Any], cur: Cursor, img: ImageMap) -> None:
        """The resource tree at its three levels (type, name, language), walked with an explicit frame stack
        in the directory's own order. The last identifier seen at each level carries to a leaf (the reference
        lets it persist across subtrees); a zero child ends a directory. Bounded by MAX_RESOURCES and by each
        node fitting the file, so a malformed tree cannot loop."""
        directory = img.directory(2)
        if directory is None or directory[0] == 0:
            return
        base = img.to_offset(directory[0])
        if base < 0 or not cur.fits(base, 16):
            return
        out["resource_timestamp"] = cur.uint(base + 4, 4)
        out["resource_version"] = {"major": cur.uint(base + 8, 2), "minor": cur.uint(base + 10, 2)}
        seen = {"type": -1, "id": -1, "language": -1}
        level_key = ("type", "id", "language")
        stack: list[list[Any]] = [[base, 0, [None, None, None], 0]]
        while stack:
            where, level, labels, cursor = stack[-1]
            flags, named, ids = cur.uint(where, 4), cur.uint(where + 12, 2), cur.uint(where + 14, 2)
            count = named + ids
            first = where + 16
            if (
                cursor >= count
                or flags != 0
                or named > 32768
                or ids > 32768
                or not cur.fits(first, count * 8)
            ):
                stack.pop()
                continue
            stack[-1][3] = cursor + 1
            name, child = cur.uint(first + 8 * cursor, 4), cur.uint(first + 8 * cursor + 4, 4)
            if child == 0:  # a zero child ends this directory
                stack.pop()
                continue
            here = labels
            if level < 3:
                seen[level_key[level]] = name - (1 << 32) if name & 0x80000000 else name
                here = [*labels]
                here[level] = Pe._wide_name(cur, base, name)
            target = base + (child & 0x7FFFFFFF)
            if child & 0x80000000 and level < 2:
                if cur.fits(target, 16):
                    stack.append([target, level + 1, here, 0])
            elif cur.fits(target, 16) and 0 < cur.uint(target + 4, 4) < cur.n:
                Pe._place(out, cur, img, target, here, seen)
        out["number_of_resources"] = len(out["resources"])

    @staticmethod
    def _wide_name(cur: Cursor, base: int, name: int) -> bytes | None:
        """The UTF-16 name a high-bit directory entry points at (its length word kept), else None."""
        if not name & 0x80000000:
            return None
        where = base + (name & 0x7FFFFFFF)
        units = cur.uint(where, 2) if cur.fits(where, 2) else None
        if units is None or not cur.fits(where, 2 + units * 2):
            return None
        return cur.data[where : where + 2 + units * 2]

    @staticmethod
    def _place(
        out: dict[str, Any],
        cur: Cursor,
        img: ImageMap,
        at: int,
        labels: list[bytes | None],
        seen: dict[str, int],
    ) -> None:
        """One resource leaf into the resources list: its data rva/offset/length, plus the type/name/language
        as a UTF-16 string where the entry named it, else the numeric id carried down from the tree."""
        resources: dict[int, Any] = out["resources"]
        if len(resources) >= Pe.MAX_RESOURCES:
            return
        rva, size = cur.uint(at, 4), cur.uint(at + 4, 4)
        offset = img.to_offset(rva)
        entry: dict[str, Any] = {"rva": rva, "length": size}
        if offset >= 0:
            entry["offset"] = offset
        for label, (as_text, as_id) in zip(
            labels,
            (("type_string", "type"), ("name_string", "id"), ("language_string", "language")),
            strict=True,
        ):
            if label is not None:
                entry[as_text] = label[2:]
            elif seen[as_id] != -1:
                entry[as_id] = seen[as_id]
        resources[len(resources)] = entry
        if seen["type"] == 16 and offset >= 0:
            Pe._read_version_info(out, cur, offset)

    @staticmethod
    def _read_version_info(out: dict[str, Any], cur: Cursor, offset: int) -> None:
        """The StringFileInfo key/value pairs inside VS_VERSION_INFO, each read as a little-endian node
        (length, value length, a UTF-16 key, then children). A UTF-16 unit is taken as its low byte and cut
        at the first zero; keys are kept to 63 bytes, values to 255."""
        data, n = cur.data, cur.n

        def room(at: int, size: int) -> bool:
            return size <= n and 0 <= at <= n - size

        def word16(at: int) -> int:
            return data[at] | (data[at + 1] << 8)

        def padded(at: int, grown: int) -> int:
            return at + ((grown + 3) & ~3)

        def terminated(at: int) -> bool:
            if not 0 <= at < n:
                return False
            i = at
            while n - i >= 2:
                if data[i] == 0 and data[i + 1] == 0:
                    return True
                i += 2
            return False

        def units(at: int) -> int:
            i = at
            while data[i] or data[i + 1]:
                i += 2
            return (i - at) // 2

        def label_is(at: int, text: bytes) -> bool:
            i = 0
            while i < len(text) and data[at + 2 * i] == text[i] and data[at + 2 * i + 1] == 0:
                i += 1
            return i == len(text) and data[at + 2 * i + 1] == 0 and data[at + 2 * i] == 0

        def ascii_text(at: int, cap: int) -> bytes:
            chars = bytearray()
            while cap > 1 and at < n and data[at] != 0:
                chars.append(data[at])
                at += 2
                cap -= 1
            return bytes(chars)

        if (
            not room(offset, 6)
            or not room(offset + 6, 32)
            or not label_is(offset + 6, b"VS_VERSION_INFO")
        ):
            return
        node = padded(offset, 6 + 86)
        while room(node + 6, 24) and label_is(node + 6, b"VarFileInfo") and word16(node) != 0:
            node = padded(node, word16(node))
        while room(node + 6, 30) and label_is(node + 6, b"StringFileInfo") and word16(node) != 0:
            group = padded(node, 6 + 30)
            node = padded(node, word16(node))
            while room(group, 6) and terminated(group + 6) and word16(group) != 0 and group < node:
                record = padded(group, 6 + 2 * (units(group + 6) + 1))
                group = padded(group, word16(group))
                while (
                    room(record, 6)
                    and terminated(record + 6)
                    and word16(record) != 0
                    and record < group
                ):
                    value_off = padded(record, 6 + 2 * (units(record + 6) + 1))
                    if terminated(value_off):
                        key = ascii_text(record + 6, 64)
                        value = b"" if word16(record + 2) == 0 else ascii_text(value_off, 256)
                        out["version_info"][key] = value
                        out["version_info_list"][len(out["version_info_list"])] = {
                            "key": key,
                            "value": value,
                        }
                    record = padded(record, word16(record))

    @staticmethod
    def _read_pdb(out: dict[str, Any], cur: Cursor, img: ImageMap) -> None:
        """The first CodeView debug entry (NB10, RSDS or MTOC) whose path ends within 260 bytes, found
        through its RVA and else its file pointer."""
        directory = img.directory(6)
        if directory is None or directory[1] == 0 or directory[0] == 0:
            return
        base = img.to_offset(directory[0])
        if base < 0:
            return
        data = cur.data
        for i in range(directory[1] // 28):
            where = base + 28 * i
            if not cur.fits(where, 28):
                break
            kind = cur.uint(where + 12, 4)
            if kind != 2:
                continue
            address, pointer = cur.uint(where + 20, 4), cur.uint(where + 24, 4)
            header = 0
            if address != 0:
                header = img.to_offset(address)
            if header <= 0 and pointer != 0:
                header = pointer
            if header <= 0 or not cur.fits(header, 8):
                continue
            signature = cur.uint(header, 4)
            path_at = None
            if signature == 0x3031424E and cur.fits(header, 17):
                path_at = header + 16
            elif signature == 0x53445352 and cur.fits(header, 25):
                path_at = header + 24
            elif signature == 0x434F544D and cur.fits(header, 21):
                path_at = header + 20
            if path_at is not None:
                limit = min(max(cur.n - path_at, 0), 260)
                end = data.find(b"\x00", path_at, path_at + limit)
                length = (end - path_at) if end >= 0 else limit
                if length < 260:
                    out["pdb_path"] = data[path_at : path_at + length]
                    return

    @staticmethod
    def _read_rich(out: dict[str, Any], cur: Cursor) -> None:
        """The Rich stub: "Rich" sought back from the PE header a dword at a time, then "DanS" (unmasked by
        the key after "Rich") sought back from there; neither below the DOS header. The masked body is
        cleared with the key and its (id-version, count) entries exposed through version()/toolid()."""
        data = cur.data
        n = cur.n
        if n < 64 or data[:2] != b"MZ":
            return
        nt = cur.uint(0x3C, 4)
        if nt is ABSENT or nt > n + 4 or nt < 4:
            return

        def le_word(where: int) -> int:
            b = data[where : where + 4].ljust(4, b"\x00")
            return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

        def scan_back(frm: int, target: int, xor: int) -> int:
            at = frm
            while at >= 64:
                if (le_word(at) ^ xor) == target:
                    return at
                at -= 4
            return -1

        rich = scan_back(nt - 4, 0x68636952, 0)
        if rich < 0:
            return
        key = le_word(rich + 4)
        if key == 0:
            return
        start = scan_back(rich - 4, 0x536E6144, key)
        if start < 0:
            return
        raw = data[start:rich]
        buf = bytearray()
        for i in range(0, len(raw), 4):
            w = raw[i : i + 4]
            v = ((w[0] | (w[1] << 8) | (w[2] << 16) | (w[3] << 24)) ^ key) & 0xFFFFFFFF
            buf += bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF))
        clear = bytes(buf)
        count = (len(raw) - 16) // 8 if len(raw) >= 16 else 0
        decoded = Cursor(clear)
        entries = [(decoded.uint(16 + 8 * i, 4), decoded.uint(20 + 8 * i, 4)) for i in range(count)]

        def score(version: int | None, toolid: int | None) -> int:
            if version is None and toolid is None:
                return 0
            return sum(
                times
                for id_version, times in entries
                if (version is None or id_version & 0xFFFF == version)
                and (toolid is None or id_version >> 16 == toolid)
            )

        rich_signature :dict [str ,Any ]={
        "offset":start ,"length":len (raw ),"key":key ,"raw_data":raw ,"clear_data":clear ,
        "version":(lambda v :score (v ,None ),lambda v ,t :score (v ,t )),
        "toolid":(lambda t :score (None ,t ),lambda t ,v :score (v ,t )),
        }  # fmt: skip
        if len(raw) >= 16:
            rich_signature["version_data"] = b"".join(
                clear[16 + 8 * i : 20 + 8 * i] for i in range(count)
            )
        out["rich_signature"] = rich_signature

    @staticmethod
    def _read_signatures(out: dict[str, Any], cur: Cursor, pe_off: int, is64: bool) -> None:
        """The certificate table, read where the optional header's security directory points and checked to
        lie within the file. The values are bridged from yara_authenticode through the Legacy adapter until
        rule_signature replaces this reader (one declaration in SCHEMA and this call site change over then)."""
        where = pe_off + 24 + (0x70 if is64 else 0x60) + 4 * 8
        if where + 8 > cur.n:
            return
        va, size = cur.uint(where, 4), cur.uint(where + 4, 4)
        if va == 0 or va > cur.n or size > cur.n or va + size > cur.n:
            return
        found, signed = Authenticode.module_values(cur.data)
        out["number_of_signatures"] = len(found)
        out["is_signed"] = int(signed)
        out["signatures"] = {i: Legacy.data(sig) for i, sig in enumerate(found)}

    @staticmethod
    def _as_details(libraries: list[Any]) -> dict[int, Any]:
        """A library list as the import_details / delayed_import_details array; an absent name or ordinal is
        omitted, as the reference reports it undefined."""
        details: dict[int, Any] = {}
        for position, (library, entries) in enumerate(libraries):
            functions: dict[int, Any] = {}
            for place, (name, ordinal, rva) in enumerate(entries):
                record: dict[str, Any] = {"rva": rva}
                if name is not None:
                    record["name"] = name
                if ordinal is not None:
                    record["ordinal"] = ordinal
                functions[place] = record
            details[position] = {
                "library_name": library,
                "number_of_functions": len(entries),
                "functions": functions,
            }
        return details

    @staticmethod
    def _cstr(text: bytes) -> bytes:
        return text.split(b"\x00", 1)[0]

    @staticmethod
    def _run_regex(pattern: Any, text: bytes) -> int:
        """A regular expression run over a C string: where its match ends, or -1."""
        return int(pattern.run(text.split(b"\x00", 1)[0]))

    @staticmethod
    def _as_signed(value: int) -> int:
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value & (1 << 63) else value

    @staticmethod
    def _import_calls(out: dict[str, Any]) -> None:
        """imports(), over views rebuilt from the import arrays (no bytes re-read)."""
        low, c, search = bytes.lower, Pe._cstr, Pe._run_regex
        imports, delayed = (
            Pe._pairs(out, "import_details"),
            Pe._pairs(out, "delayed_import_details"),
        )

        def for_dll(table: Any, dll: bytes) -> Any:
            needle = low(c(dll))
            for name, fs in table:
                if low(name) == needle:
                    yield from fs

        def count(table: Any, dll: bytes) -> int:
            return sum(1 for _ in for_dll(table, dll))

        def has(table: Any, dll: bytes, fn: bytes) -> int:
            target = low(c(fn))
            return int(any(low(n or b"") == target for n, _, _ in for_dll(table, dll)))

        def ordinal(table: Any, dll: bytes, want: int) -> int:
            return int(any(o == want for _, o, _ in for_dll(table, dll) if o is not None))

        def regex(table: Any, dll_re: Any, fn_re: Any) -> int:
            return sum(
                1
                for name, fs in table
                if search(dll_re, name) > 0
                for n, _, _ in fs
                if search(fn_re, n or b"") > 0
            )

        def combine(flags: int, one: Any, *args: Any, total: bool = False) -> int:
            standard = one(imports, *args) if flags & 1 else 0
            if not total and standard:
                return 1
            later = one(delayed, *args) if flags & 2 else 0
            return standard + later if total else int(bool(later))

        out["imports"] = (
            lambda d, n: has(imports, d, n),
            lambda d, o: ordinal(imports, d, o),
            lambda d: count(imports, d),
            lambda d, n: regex(imports, d, n),
            lambda fl, d, n: combine(fl, has, d, n),
            lambda fl, d, o: combine(fl, ordinal, d, o),
            lambda fl, d: combine(fl, count, d, total=True),
            lambda fl, d, n: combine(fl, regex, d, n, total=True),
        )

    @staticmethod
    def _pairs(out: dict[str, Any], key: str) -> list[Any]:
        """A table's (library, [(name, ordinal, rva)]) list rebuilt from its decoded array."""
        return [
            (
                it["library_name"],
                [(f.get("name"), f.get("ordinal"), f["rva"]) for f in it["functions"].values()],
            )
            for it in out[key].values()
        ]

    @staticmethod
    def _import_rva_calls(out: dict[str, Any]) -> None:
        """imphash(), import_rva(), delayed_import_rva()."""
        low = bytes.lower

        def import_hash() -> bytes:
            parts: list[bytes] = []
            for dll, fs in Pe._pairs(out, "import_details"):
                dot = dll.rfind(b".")
                stem = (
                    dll[:dot]
                    if dot >= 0 and low(dll[dot : dot + 4]) in (b".ocx", b".sys", b".dll")
                    else dll
                )
                parts.extend(low(stem) + b"." + low(n or b"") for n, _, _ in fs)
            return hashlib.md5(b",".join(parts)).hexdigest().encode()  # noqa: S324 - the digest is MD5

        def locate_rva(key: str, n: Any, dll: bytes, match: Any) -> int | None:
            for it in out[key].values() if isinstance(n, int) else ():
                if low(it["library_name"]) == low(dll):
                    for f in it["functions"].values():
                        if match(f):
                            return int(f["rva"])
            return None

        def matching_name(name: bytes) -> Any:
            return lambda f: isinstance(f.get("name"), bytes) and low(f["name"]) == low(name)

        def at_ordinal(want: int) -> Any:
            return lambda f: isinstance(f.get("ordinal"), int) and f["ordinal"] == want

        ni, nd = out["number_of_imports"], out["number_of_delayed_imports"]
        out["imphash"] = (import_hash,)
        out["import_rva"] = (
            lambda d, n: locate_rva("import_details", ni, d, matching_name(n)),
            lambda d, o: locate_rva("import_details", ni, d, at_ordinal(o)),
        )
        out["delayed_import_rva"] = (
            lambda d, n: locate_rva("delayed_import_details", nd, d, matching_name(n)),
            lambda d, o: locate_rva("delayed_import_details", nd, d, at_ordinal(o)),
        )

    @staticmethod
    def _export_calls(out: dict[str, Any]) -> None:
        """exports / exports_index, over the export array."""
        low, search = bytes.lower, Pe._run_regex
        exports = [(e.get("name"), e["ordinal"], e["rva"]) for e in out["export_details"].values()]
        n_exports = len(exports)

        def ordinal_ok(q: int) -> bool:
            return not (n_exports == 0 or q == 0 or q > n_exports)

        out["exports"] = (
            lambda q: int(any(n is not None and low(n) == low(q) for n, _, _ in exports)),
            lambda q: int(any(n is not None and search(q, n) != -1 for n, _, _ in exports)),
            lambda q: int(ordinal_ok(q) and any(o == q for _, o, _ in exports)),
        )
        out["exports_index"] = (
            lambda q: next(
                (i for i, (n, _, _) in enumerate(exports) if n is not None and low(n) == low(q)),
                None,
            ),
            lambda q: (
                next((i for i, (_, o, _) in enumerate(exports) if o == q), None)
                if ordinal_ok(q)
                else None
            ),
            lambda q: next(
                (i for i, (n, _, _) in enumerate(exports) if n is not None and search(q, n) != -1),
                None,
            ),
        )

    @staticmethod
    def _section_calls(out: dict[str, Any], cur: Cursor, img: ImageMap, chars: int) -> None:
        """section_index, is_dll/is_32bit/is_64bit, rva_to_offset, calculate_checksum."""
        c = Pe._cstr
        sections = [
            (s["name"], s["raw_data_size"], s["raw_data_offset"]) for s in out["sections"].values()
        ]
        data = cur.data

        def by_label(q: bytes) -> int | None:
            for i in range(min(out["number_of_sections"], Pe.MAX_SECTIONS)):
                if i < len(sections) and c(sections[i][0]) == c(q):
                    return i
            return None

        def by_addr(addr: int) -> int | None:
            for i in range(min(out["number_of_sections"], Pe.MAX_SECTIONS)):
                size, offset = (
                    (sections[i][1], sections[i][2])
                    if i < len(sections)
                    else (Pe._as_signed(Pe.UNDEFINED_VALUE),) * 2
                )
                if offset <= addr < Pe._as_signed(offset + size):
                    return i
            return None

        def compute_sum() -> int:
            where, csum, size = img.opt + 64, 0, cur.n
            for i in range(size // 4 + 1):
                if 4 * i == where:
                    continue
                if 4 * i + 4 <= size:
                    csum += cur.uint(4 * i, 4)
                else:
                    for j in range(size % 4):
                        csum += data[4 * i + j] << (8 * j)
                if csum > 0xFFFFFFFF:
                    csum = (csum & 0xFFFFFFFF) + (csum >> 32)
            csum = (csum & 0xFFFF) + (csum >> 16)
            csum += csum >> 16
            return (csum & 0xFFFF) + size

        def to_file_offset(rva: int) -> int | None:
            offset = img.to_offset(rva & 0xFFFFFFFFFFFFFFFF)
            return None if offset == -1 else offset

        out["section_index"] = (by_label, by_addr)
        out["is_dll"] = (lambda: chars & 0x2000,)
        out["is_32bit"] = (lambda: 0 if img.is64 else 1,)
        out["is_64bit"] = (lambda: 1 if img.is64 else 0,)
        out["rva_to_offset"] = (to_file_offset,)
        out["calculate_checksum"] = (compute_sum,)

    @staticmethod
    def _resource_calls(out: dict[str, Any]) -> None:
        """locale / language, over the resource languages."""
        mask = 0xFFFFFFFFFFFFFFFF

        def languages() -> list[int]:
            langs: list[int] = []
            for i in range(out["number_of_resources"]):
                item = out["resources"].get(i)
                language = item.get("language") if item is not None else None
                langs.append(
                    Pe.UNDEFINED_VALUE if not isinstance(language, int) else language & mask
                )
            return langs

        out["locale"] = (lambda q: int(any(lang & 0xFFFF == q & mask for lang in languages())),)
        out["language"] = (lambda q: int(any(lang & 0xFF == q & mask for lang in languages())),)


__all__ = ["Pe", "Shape"]
