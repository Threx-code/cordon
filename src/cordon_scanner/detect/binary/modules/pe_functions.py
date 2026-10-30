"""The functions the `pe` module gives a rule: imports() and imphash(), import_rva() and
delayed_import_rva(), exports() and exports_index(), section_index(), rva_to_offset(), is_dll(),
is_32bit() and is_64bit(), locale() and language() -- each over the views the reader built, answering
as the reference does for an absent name, a regular expression, an ordinal or an out-of-range address."""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import (
    Cursor,
    ImageMap,
)


class PeFunctions:
    """The pe module's functions, built over the parsed file."""

    MAX_SECTIONS: ClassVar[int] = 96

    UNDEFINED_VALUE: ClassVar[int] = (
        0xFFFABADAFABADAFF  # the reference's sentinel, for a resource language
    )

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
    def import_calls(out: dict[str, Any]) -> None:
        """imports(), over views rebuilt from the import arrays (no bytes re-read)."""
        low, c, search = bytes.lower, PeFunctions._cstr, PeFunctions._run_regex
        imports, delayed = (
            PeFunctions._pairs(out, "import_details"),
            PeFunctions._pairs(out, "delayed_import_details"),
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
                [
                    (f.get("name"), f.get("ordinal"), f.get("rva", 0))
                    for f in it["functions"].values()
                ],
            )
            for it in out[key].values()
        ]

    @staticmethod
    def import_rva_calls(out: dict[str, Any]) -> None:
        """imphash(), import_rva(), delayed_import_rva()."""
        low = bytes.lower

        def import_hash() -> bytes:
            parts: list[bytes] = []
            for dll, fs in PeFunctions._pairs(out, "import_details"):
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
                            # An RVA of 0 is not reported as a field, and the function still answers 0.
                            return int(f.get("rva", 0))
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
    def export_calls(out: dict[str, Any]) -> None:
        """exports / exports_index, over the export array."""
        low, search = bytes.lower, PeFunctions._run_regex
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
    def section_calls(out: dict[str, Any], cur: Cursor, img: ImageMap, chars: int) -> None:
        """section_index, is_dll/is_32bit/is_64bit, rva_to_offset, calculate_checksum."""
        c = PeFunctions._cstr
        sections = [
            (s["name"], s["raw_data_size"], s["raw_data_offset"]) for s in out["sections"].values()
        ]
        data = cur.data

        def by_label(q: bytes) -> int | None:
            for i in range(min(out["number_of_sections"], PeFunctions.MAX_SECTIONS)):
                if i < len(sections) and c(sections[i][0]) == c(q):
                    return i
            return None

        def by_addr(addr: int) -> int | None:
            for i in range(min(out["number_of_sections"], PeFunctions.MAX_SECTIONS)):
                size, offset = (
                    (sections[i][1], sections[i][2])
                    if i < len(sections)
                    else (PeFunctions._as_signed(PeFunctions.UNDEFINED_VALUE),) * 2
                )
                if offset <= addr < PeFunctions._as_signed(offset + size):
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
    def resource_calls(out: dict[str, Any]) -> None:
        """locale / language, over the resource languages."""
        mask = 0xFFFFFFFFFFFFFFFF

        def languages() -> list[int]:
            langs: list[int] = []
            for i in range(out["number_of_resources"]):
                item = out["resources"].get(i)
                language = item.get("language") if item is not None else None
                langs.append(
                    PeFunctions.UNDEFINED_VALUE
                    if not isinstance(language, int)
                    else language & mask
                )
            return langs

        out["locale"] = (lambda q: int(any(lang & 0xFFFF == q & mask for lang in languages())),)
        out["language"] = (lambda q: int(any(lang & 0xFF == q & mask for lang in languages())),)


__all__ = ["PeFunctions"]
