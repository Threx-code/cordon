"""The `pe` module reader for cordon-rule, built from a declared schema.

A PE file is reached through its DOS stub (MZ, e_lfanew) to the PE signature, the COFF file header and the
optional header (PE32 or PE32+); from there the section table, the data directories, the import, delayed-
import and export tables, resources and their version information, the Rich stub, the debug (PDB) entry and
the certificate table. `ImageMap` (modules.layout) accepts the image and maps a virtual address to a file
offset, shared with the .NET reader. Each fixed structure is described once as a `Layout` and read through a
`Cursor`; the heavy arrays decode on access. `data()` returns plain dicts and lists, an absent key being
undefined, exactly as the reference reports an undefined field by omitting it.

Values follow the reference's `pe` module; bounds live in the Cursor, so a truncated or malformed image
yields a defined, partial result rather than a crash.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import (
    ABSENT,
    Cursor,
    Grid,
    ImageMap,
    LazyGroups,
)
from cordon_scanner.detect.binary.modules.pe_functions import PeFunctions
from cordon_scanner.detect.binary.modules.pe_imports import PeImports, Shape
from cordon_scanner.detect.binary.modules.signature import SIGNATURE, Signatures
from cordon_scanner.detect.binary.modules.tables import Tables
from cordon_scanner.detect.binary.modules.values import (
    Call,
    Keyed,
    Record,
    Scalar,
    Seq,
    Sig,
)

INT, TEXT = Scalar.INT, Scalar.TEXT


class Pe:
    """The `pe` module reader."""

    MAX_RESOURCES: ClassVar[int] = 65536

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
    "signatures":Seq (SIGNATURE ),
    "version_info":Keyed (TEXT ),"version_info_list":Seq (Record ({"key":TEXT ,"value":TEXT })),
    **{name :Call (*sigs )for name ,sigs in CALLS .items ()},
    })  # fmt: skip

    @staticmethod
    def data(file: bytes) -> Mapping[str, Any]:
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
        context = Pe._read(out, file)
        if context is None:
            return out
        # The signatures, the imports and the exports are the costly parts of a PE to read (an Authenticode
        # parse with each signature verified; an address lookup per import and per export), and most rules
        # read at most one of them: each is read on the first access of one of its fields, and never
        # otherwise. A group is read on a copy of the rest of the record with its own starting values, so
        # it sees what it saw when everything was read at once.
        defaults = {
            name: out.pop(name) for name in Pe.IMPORT_FIELDS + Pe.EXPORT_FIELDS if name in out
        }
        for name in Pe.SIGNATURE_FIELDS:
            out.pop(name, None)
        base = dict(out)
        cur, img, is64, header = context

        def group(names: tuple[str, ...], *steps: Any) -> Any:
            def build() -> dict[str, Any]:
                part = {**base, **{k: defaults[k] for k in names if k in defaults}}
                for step in steps:
                    step(part)
                return {k: part[k] for k in names if k in part}

            return build

        imports = group(
            Pe.IMPORT_FIELDS,
            lambda part: PeImports.read_imports(part, cur, img, is64, header),
            PeFunctions.import_calls,
            PeFunctions.import_rva_calls,
        )
        exports = group(
            Pe.EXPORT_FIELDS,
            lambda part: PeImports.exports(part, cur, img),
            PeFunctions.export_calls,
        )
        return LazyGroups(
            out,
            [
                (Pe.SIGNATURE_FIELDS, lambda: Pe._signature_fields(file)),
                (Pe.IMPORT_FIELDS, imports),
                (Pe.EXPORT_FIELDS, exports),
            ],
        )

    #: The fields of a PE's imports and exports, each group read when a rule reads one of its fields.
    IMPORT_FIELDS: ClassVar[tuple[str, ...]] = (
        "import_details",
        "delayed_import_details",
        "number_of_imports",
        "number_of_imported_functions",
        "number_of_delayed_imports",
        "number_of_delayed_imported_functions",
        "imports",
        "import_rva",
        "delayed_import_rva",
        "imphash",
    )
    EXPORT_FIELDS: ClassVar[tuple[str, ...]] = (
        "export_details",
        "number_of_exports",
        "dll_name",
        "export_timestamp",
        "exports",
        "exports_index",
    )

    @staticmethod
    def _read(
        out: dict[str, Any], file: bytes
    ) -> tuple[Cursor, ImageMap, bool, dict[str, Any]] | None:
        """The header, sections, resources, debug entry and Rich stub into `out`; the reader's state for the
        groups read later (`data`), or None when the file is not a PE."""
        cur = Cursor(file)
        img = ImageMap.accept(
            cur, strict=True
        )  # the pe RVA rule: a non-fitting section header fails the map
        if img is None:
            return None
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
        for i in range(min(PeImports.as_count(header["number_of_rva_and_sizes"]), 16)):
            if not cur.fits(dd_at + 8 * i, 8):
                break
            directories[i] = {
                "virtual_address": cur.uint(dd_at + 8 * i, 4),
                "size": cur.uint(dd_at + 8 * i + 4, 4),
            }
        out["data_directories"] = directories
        Pe._sections(out, cur, img, coff)
        Pe._read_resources(out, cur, img)
        out["number_of_version_infos"] = len(out["version_info_list"])
        Pe._read_pdb(out, cur, img)
        Pe._read_rich(out, cur)
        PeFunctions.section_calls(out, cur, img, PeImports.as_count(coff["characteristics"]))
        PeFunctions.resource_calls(out)
        return cur, img, is64, header

    @staticmethod
    def _sections(out: dict[str, Any], cur: Cursor, img: ImageMap, coff: dict[str, Any]) -> None:
        """The section table read in bulk, and from it the overlay (the highest raw_offset + raw_size, as the
        reference computes it). A ``/<n>`` section name is resolved to its long COFF-string-table name."""
        nsec = PeImports.as_count(coff["number_of_sections"])
        symptr = PeImports.as_count(coff["pointer_to_symbol_table"])
        nsym = PeImports.as_count(coff["number_of_symbols"])
        sec_at = img.opt + PeImports.as_count(coff["size_of_optional_header"])
        grid = Grid(cur, sec_at, Shape.SECTION, min(nsec, PeFunctions.MAX_SECTIONS), None)
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

    #: The fields a PE's signatures give, read together and only when a rule reads one of them.
    SIGNATURE_FIELDS: ClassVar[tuple[str, ...]] = (
        "number_of_signatures",
        "is_signed",
        "signatures",
    )

    @staticmethod
    def _signature_fields(file: bytes) -> dict[str, Any]:
        """pe.signatures and pe.is_signed: the file's Authenticode signatures, read by modules.signature from
        the certificate table (it locates and bounds-checks the security directory itself)."""
        found, signed = Signatures.signature_values(file)
        return {"number_of_signatures": len(found), "is_signed": signed, "signatures": found}


__all__ = ["Pe"]
