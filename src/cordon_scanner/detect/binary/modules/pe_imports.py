"""A PE file's import and export tables, read the way the reference reads them.

The standard import descriptors and their thunks (by name or by ordinal), the delay-load
descriptors, the library names they point at, and the export directory with each entry's name,
ordinal and RVA -- every address mapped to the file through the image's sections, and a table that
runs off the file or past its limits read only as far as it holds."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import (
    ABSENT,
    U8,
    U16,
    U32,
    U64,
    Blob,
    Cursor,
    ImageMap,
    Layout,
)
from cordon_scanner.detect.binary.modules.tables import Tables


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


class PeImports:
    """Reading a PE file's import and export tables."""

    MAX_IMPORTS: ClassVar[int] = 16384

    MAX_EXPORTS: ClassVar[int] = 16384

    FUNCTION_NAME: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9._?@$()<>]+")

    @staticmethod
    def exports(out: dict[str, Any], cur: Cursor, img: ImageMap) -> None:
        """The export directory, when there is one: its count is 0 otherwise."""
        out["number_of_exports"] = 0
        directory = img.directory(0)
        if directory is not None and directory[0]:
            PeImports._read_exports(out, cur, img, directory)

    @staticmethod
    def as_count(value: Any) -> int:
        """A header integer as a plain count; 0 when the field did not fit (ABSENT)."""
        return value if isinstance(value, int) else 0

    @staticmethod
    def to_offset(img: ImageMap, rva: int) -> int | None:
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
    def read_imports(
        out: dict[str, Any], cur: Cursor, img: ImageMap, is64: bool, header: dict[str, Any]
    ) -> None:
        """Both import tables into the out dict, each as a library list and the two counts the module reports."""
        standard = list(PeImports._standard_imports(cur, img, is64))
        out["number_of_imports"] = len(standard)
        out["number_of_imported_functions"] = sum(len(entries) for _, entries in standard)
        out["import_details"] = PeImports._as_details(standard)
        delayed = list(
            PeImports._delay_imports(
                cur,
                img,
                is64,
                PeImports.as_count(header["image_base"]),
                PeImports.as_count(header["size_of_image"]),
            )
        )
        out["number_of_delayed_imports"] = len(delayed)
        out["number_of_delayed_imported_functions"] = sum(len(entries) for _, entries in delayed)
        out["delayed_import_details"] = PeImports._as_details(delayed)

    @staticmethod
    def _standard_imports(cur: Cursor, img: ImageMap, is64: bool) -> Any:
        """Walk IMAGE_IMPORT_DESCRIPTORs, yielding (library, entries); each entry is (name, ordinal, slot)
        taken from the lookup table (the import address table when the lookup is absent)."""
        directory = img.directory(1)
        at = PeImports.to_offset(img, directory[0]) if directory and directory[0] else None
        width = 8 if is64 else 4
        high = 1 << (width * 8 - 1)
        libraries = functions = 0
        while at is not None and cur.fits(at, 20) and libraries < PeImports.MAX_IMPORTS:
            desc = Shape.IMPORT_DIR.read(cur, at)
            if not desc["name"]:
                return
            at += 20
            libraries += 1
            named = PeImports.to_offset(img, desc["name"])
            library = PeImports._dll_name(cur, named) if named is not None else None
            if library is None:
                continue
            lookup = PeImports.to_offset(img, desc["lookup"])
            if lookup is None or lookup <= 0:
                lookup = PeImports.to_offset(img, desc["address"])
            if lookup is None:
                continue
            entries: list[Any] = []
            index = 0
            while functions < PeImports.MAX_IMPORTS:
                word = cur.uint(lookup + width * index, width)
                if word is ABSENT or not word:
                    break
                name, ordinal = PeImports._thunk(cur, img, word, high, library)
                slot = desc["address"] + width * index
                index += 1
                if name is not None and not PeImports.FUNCTION_NAME.fullmatch(name):
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
        hint = PeImports.to_offset(img, word)
        if hint is not None and hint + 2 < cur.n:
            return cur.data[hint + 2 : hint + 2 + 512].split(b"\x00", 1)[0], None
        return None, None

    @staticmethod
    def _delay_imports(cur: Cursor, img: ImageMap, is64: bool, base: int, span: int) -> Any:
        """Walk the delay-load descriptors, yielding (library, entries). Addresses are RVAs, or for an old
        32-bit descriptor virtual addresses relative to the image base (rebased here)."""
        directory = img.directory(13)
        at = PeImports.to_offset(img, directory[0]) if directory and directory[0] else None
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
            named = PeImports.to_offset(img, name_rva)
            library = PeImports._dll_name(cur, named) if named is not None else None
            if library is None:
                continue
            entries: list[Any] = []
            name_at, func_at = lookup, address
            while True:
                name_off, func_off = (
                    PeImports.to_offset(img, name_at),
                    PeImports.to_offset(img, func_at),
                )
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
                    hint = PeImports.to_offset(img, target + 2)
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
        head = PeImports.to_offset(img, directory[0])
        if head is None or not cur.fits(head, 40):
            return
        table = Shape.EXPORT_DIR.read(cur, head)
        total = min(table["count"], PeImports.MAX_EXPORTS)
        out["export_timestamp"] = table["stamp"]
        label = PeImports.to_offset(img, table["name"])
        if label is not None and label > 0:
            out["dll_name"] = cur.data[label:].split(b"\x00", 1)[0]
            # the function count must leave room past the name offset, or the table is not walked
        if total * 4 > cur.n - (label if label is not None else -1):
            return
        names_at = PeImports.to_offset(img, table["names"]) if table["name_count"] else None
        if table["name_count"] and (names_at is None or table["name_count"] * 4 > cur.n - names_at):
            return
        slots_at, addrs_at = (
            PeImports.to_offset(img, table["ordinals"]),
            PeImports.to_offset(img, table["addresses"]),
        )
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
            landing = PeImports.to_offset(img, target)
            if landing is not None and low < landing < high:
                entry["forward_name"] = cur.data[landing : landing + 512].split(b"\x00", 1)[0]
            elif landing is not None:
                entry["offset"] = landing
            if names_at is not None and index in name_slot:
                name = PeImports._export_label(cur, img, names_at, name_slot[index])
                if name is not None:
                    entry["name"] = name
            details[index] = entry
        out["export_details"] = details
        out["number_of_exports"] = total

    @staticmethod
    def _export_label(cur: Cursor, img: ImageMap, names_at: int, j: int) -> bytes | None:
        """The exported name at name-table slot ``j``; None when that slot carries no resolvable name."""
        nrva = cur.uint(names_at + 4 * j, 4)
        noff = PeImports.to_offset(img, nrva) if nrva is not ABSENT else None
        if noff is not None and noff > 0:
            return cur.data[noff : noff + 512].split(b"\x00", 1)[0]
        return None

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


__all__ = ["PeImports", "Shape"]
