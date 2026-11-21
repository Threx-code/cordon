"""Whether an `ar` archive is an MSVC import library, decided whole and by structure (notes/75 fix 2).

An import library names every member for the DLL it imports from (`libvips-42.dll`), so its COFF
descriptor objects read "named .dll, contents not a PE" to the polyglot check: 3 benign npm units
(sharp's libvips, npcap, tree-sitter). Its members hold names and fixed-size tables and nothing that
runs. The archive passes only when every byte of it is in the linker's exact layout, measured on those
three libraries; anything else, including an archive read only in part, is an ordinary archive:

```
  "!<arch>\\n", read to its end, at most max_archive_entries members, no bytes after the last
  linker members  "/" (once or twice; first big-endian, second little-endian), "//"; every symbol
                  offset at a real member header; no other special member
  each member     a short import stub, whole: 20-byte header (0, 0xFFFF, Version 0, known Machine),
                  SizeOfData exact, then symbol NUL dll NUL, printable, nothing after
                  or a descriptor object, whole: no optional header, one of three section shapes,
                  each section bounded, no code or execute flag, only descriptor symbols, every
                  byte accounted for
                  and named for the DLL it imports from
  at least one stub
```
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.foundation.limits import Limits

MAGIC: Final = b"!<arch>\n"
_STUB_SIG: Final = b"\x00\x00\xff\xff"


class ImportLibrary:
    """The whole-archive test. Pure: bytes in, a yes or no out."""

    MACHINES: ClassVar[dict[int, int]] = {
        0x14C: 4,
        0x1C0: 4,
        0x1C4: 4,
        0x8664: 8,
        0xAA64: 8,
        0xA641: 8,
        0xA64E: 8,
    }
    """Known machines and their word size (.idata$4 / $5)."""
    DEBUG_MAX: ClassVar[int] = 64
    """The largest C13 (signature 4) `.debug$S` let through: no C13 import library has been measured,
    so it keeps the bound the first three libraries set (60, 63 and 64 bytes)."""
    CV_MACHINE: ClassVar[dict[int, int]] = {0x14C: 0x03, 0x8664: 0xD0, 0xAA64: 0xF6}
    """The CodeView machine lib.exe writes in a C11 compiler record, by COFF machine (measured, 141
    sections in 9 benign PyPI units). A machine not here is refused until it is measured."""
    _OBJNAME: ClassVar[int] = 0x0009
    """S_OBJNAME_ST: signature 0, then the object's name, length-prefixed: in an import library the DLL's."""
    _COMPILE2: ClassVar[int] = 0x1013
    """S_COMPILE2_ST: flags, machine, six version shorts, then the linker's banner, length-prefixed."""
    _COMPILE_FLAGS: ClassVar[int] = 7
    """The compiler record's flags in all 141 measured sections."""
    NAME_MAX: ClassVar[int] = 260
    #: Section flags that mark code or execution: no descriptor object has either.
    _CODE: ClassVar[int] = 0x00000020 | 0x20000000
    #: The three descriptor shapes: section name -> (exact size or None for the DLL name or word,
    #: the most relocations it may carry).
    _SHAPES: ClassVar[tuple[dict[str, int], ...]] = (
        {".idata$2": 3, ".idata$6": 0},
        {".idata$3": 0},
        {".idata$5": 0, ".idata$4": 0},
    )

    @staticmethod
    def verify(data: bytes, limits: Limits) -> bool:
        """Total: any archive this cannot read whole and exactly is ordinary, and nothing raises out
        of it -- the test must never cost an archive its extraction (a `.deb` is an ar too)."""
        try:
            return ImportLibrary._verify(data, limits)
        except (ValueError, struct.error, IndexError, UnicodeDecodeError, OverflowError):
            return False

    @staticmethod
    def _verify(data: bytes, limits: Limits) -> bool:
        members = ImportLibrary._members(data, limits)
        if members is None:
            return False
        headers = {at for at, _name, _body in members}
        stubs = 0
        linkers = 0
        long_names: bytes | None = None
        for _at, name, body in members:
            if name == b"/":
                linkers += 1
                if linkers > 2 or not ImportLibrary._linker(body, headers, linkers):
                    return False
                continue
            if name == b"//":
                if long_names is not None:
                    return False
                long_names = body
                continue
            dll = ImportLibrary._dll_name(name, long_names)
            if dll is None:
                return False
            if body[:4] == _STUB_SIG:
                if not ImportLibrary._stub(body, dll):
                    return False
                stubs += 1
            elif not ImportLibrary._descriptor(body, dll):
                return False
        return stubs > 0

    @staticmethod
    def _dll_name(name: bytes, long_names: bytes | None) -> bytes | None:
        """The member's name: short (`jc.dll/`), or a GNU long name (`/123`) from the `//` table.
        Any other special name (`/SYM64/`, BSD `#1/`, `__.SYMDEF`) is not an import library's."""
        if name.startswith(b"/") and name[1:].isdigit():
            offset = int(name[1:])
            if long_names is None or offset >= len(long_names):
                return None
            # GNU ends a long name with "/\n", Microsoft's lib.exe with a NUL: the first of the two
            # (as ArReader reads the table, 33d5d5dd).
            ends = [
                e
                for e in (long_names.find(b"/\n", offset), long_names.find(b"\x00", offset))
                if e >= 0
            ]
            stop = min(ends) if ends else -1
            return long_names[offset:stop] if stop > offset else None
        if name.startswith((b"/", b"#1/", b"__.SYMDEF")) or not name.endswith(b"/"):
            return None
        return name[:-1] or None

    @staticmethod
    def _members(data: bytes, limits: Limits) -> list[tuple[int, bytes, bytes]] | None:
        """(header offset, raw name, body) of every member, or None if the archive is not read whole."""
        if not data.startswith(MAGIC):
            return None
        out: list[tuple[int, bytes, bytes]] = []
        at = len(MAGIC)
        while at < len(data):
            header = data[at : at + 60]
            if len(header) < 60 or header[58:60] != b"`\n":
                return None
            size = int(header[48:58].strip() or b"0")
            start, end = at + 60, at + 60 + size
            if end > len(data):
                return None
            out.append((at, header[:16].rstrip(b" "), data[start:end]))
            if len(out) > limits.max_archive_entries:
                return None
            at = end + (end & 1)
        return out if at == len(data) or (at == len(data) + 1 and len(data) & 1) else None

    @staticmethod
    def _linker(body: bytes, headers: set[int], which: int) -> bool:
        """The first linker member (big-endian count, offsets) or the second (little-endian member
        count, offsets, symbol count, indices): every offset at a member header."""
        if which == 1:
            (count,) = struct.unpack_from(">I", body)
            offsets = struct.unpack_from(f">{count}I", body, 4)
        else:
            (count,) = struct.unpack_from("<I", body)
            offsets = struct.unpack_from(f"<{count}I", body, 4)
            (symbols,) = struct.unpack_from("<I", body, 4 + 4 * count)
            indices = struct.unpack_from(f"<{symbols}H", body, 8 + 4 * count)
            if any(not 1 <= i <= count for i in indices):
                return False
        return all(o in headers for o in offsets)

    @staticmethod
    def _stub(body: bytes, dll: bytes) -> bool:
        """A short import object, whole: exactly its header and two printable names."""
        if len(body) < 20:
            return False
        version, machine, _stamp, size = struct.unpack_from("<HHII", body, 4)
        if version != 0 or machine not in ImportLibrary.MACHINES or len(body) != 20 + size:
            return False
        parts = body[20:].split(b"\x00")
        if len(parts) != 3 or parts[2] != b"":
            return False
        symbol, named = parts[0], parts[1]
        return (
            ImportLibrary._printable(symbol)
            and ImportLibrary._printable(named)
            and named.lower() == dll.lower()
        )

    @staticmethod
    def _descriptor(body: bytes, dll: bytes) -> bool:
        """One of the three descriptor objects, whole: every byte accounted for."""
        machine, count, _stamp, symtab, nsym, optional, _flags = struct.unpack_from(
            "<HHIIIHH", body
        )
        word = ImportLibrary.MACHINES.get(machine)
        if word is None or optional != 0 or not 1 <= count <= 3 or nsym > 16:
            return False
        spans = [(0, 20 + 40 * count)]
        names: list[str] = []
        for i in range(count):
            head = body[20 + 40 * i : 60 + 40 * i]
            name = head[:8].rstrip(b"\x00").decode("ascii")
            _vs, _va, raw, ptr, rel, lines, nrel, nlines, flags = struct.unpack_from(
                "<IIIIIIHHI", head, 8
            )
            if flags & ImportLibrary._CODE or lines or nlines:
                return False
            data = body[ptr : ptr + raw]
            if len(data) != raw:
                return False
            if not ImportLibrary._section(name, data, nrel, word, dll, machine):
                return False
            names.append(name)
            if raw:
                spans.append((ptr, ptr + raw))
            if nrel:
                spans.append((rel, rel + 10 * nrel))
        shape = {n for n in names if n != ".debug$S"}
        if names.count(".debug$S") > 1 or not any(
            shape == set(s) and all(names.count(n) == 1 for n in s) for s in ImportLibrary._SHAPES
        ):
            return False
        strings = struct.unpack_from("<I", body, symtab + 18 * nsym)[0]
        if strings < 4:
            return False
        spans.append((symtab, symtab + 18 * nsym + strings))
        if not ImportLibrary._symbols(body, symtab, nsym, strings, set(names), dll):
            return False
        return ImportLibrary._covered(spans, len(body))

    @staticmethod
    def _section(name: str, data: bytes, nrel: int, word: int, dll: bytes, machine: int) -> bool:
        if name == ".debug$S":
            if nrel != 0 or len(data) < 4:
                return False
            signature = struct.unpack_from("<I", data)[0]
            if signature == 2:
                return ImportLibrary._codeview(data, dll, machine)
            return signature == 4 and len(data) <= ImportLibrary.DEBUG_MAX
        limit = next((s[name] for s in ImportLibrary._SHAPES if name in s), None)
        if limit is None or nrel > limit:
            return False
        if name in (".idata$2", ".idata$3"):
            return len(data) == 20
        if name in (".idata$4", ".idata$5"):
            return len(data) == word
        # .idata$6: the DLL's name, NUL-terminated, padded to an even size at most.
        named = data.rstrip(b"\x00")
        return (
            len(data) <= ImportLibrary.NAME_MAX
            and len(data) - len(named) in (1, 2)
            and named.lower() == dll.lower()
        )

    @staticmethod
    def _codeview(data: bytes, dll: bytes, machine: int) -> bool:
        """A C11 `.debug$S` (signature 2) as lib.exe writes it into a descriptor object: exactly one
        object-name record and one compiler record, in either order, covering the section to its last
        byte. The object name is the DLL's own name and the banner is printable, so the section holds
        nothing a reader could not name (08-BENIGN-F-SHAPES §1)."""
        records: dict[int, bytes] = {}
        at = 4
        while at < len(data):
            if at + 4 > len(data):
                return False
            length, kind = struct.unpack_from("<HH", data, at)
            end = at + 2 + length
            if length < 2 or end > len(data) or kind in records:
                return False
            records[kind] = data[at + 4 : end]
            at = end
        if set(records) != {ImportLibrary._OBJNAME, ImportLibrary._COMPILE2}:
            return False
        return ImportLibrary._object_name(records[ImportLibrary._OBJNAME], dll) and (
            ImportLibrary._compiler(records[ImportLibrary._COMPILE2], machine)
        )

    @staticmethod
    def _object_name(body: bytes, dll: bytes) -> bool:
        """Signature 0, then the DLL's own name, length-prefixed, filling the record exactly."""
        if len(body) < 5 or struct.unpack_from("<I", body)[0] != 0:
            return False
        size = body[4]
        name = body[5:]
        return size > 0 and len(name) == size and name.lower() == dll.lower()

    @staticmethod
    def _compiler(body: bytes, machine: int) -> bool:
        """The measured flags, the CodeView machine of the object's COFF machine, six version
        shorts, then a printable banner, length-prefixed, filling the record exactly."""
        if len(body) < 19:
            return False
        flags, cv_machine = struct.unpack_from("<IH", body)
        expected = ImportLibrary.CV_MACHINE.get(machine)
        if flags != ImportLibrary._COMPILE_FLAGS or expected is None or cv_machine != expected:
            return False
        size = body[18]
        banner = body[19:]
        return size > 0 and len(banner) == size and all(0x20 <= b < 0x7F for b in banner)

    @staticmethod
    def _symbols(
        body: bytes, symtab: int, nsym: int, strings: int, sections: set[str], dll: bytes
    ) -> bool:
        base = dll.rsplit(b".", 1)[0].decode("latin-1")
        allowed = {
            "@comp.id",
            f"__IMPORT_DESCRIPTOR_{base}",
            "__NULL_IMPORT_DESCRIPTOR",
            f"\x7f{base}_NULL_THUNK_DATA",
            *sections,
            ".idata$4",
            ".idata$5",
            ".idata$6",
        }
        table = body[symtab + 18 * nsym : symtab + 18 * nsym + strings]
        i = 0
        while i < nsym:
            entry = body[symtab + 18 * i : symtab + 18 * i + 18]
            if entry[:4] == b"\x00\x00\x00\x00":
                (offset,) = struct.unpack_from("<I", entry, 4)
                stop = table.find(b"\x00", offset)
                if offset < 4 or stop < 0:
                    return False
                raw = table[offset:stop]
            else:
                raw = entry[:8].rstrip(b"\x00")
            if raw.decode("latin-1") not in allowed:
                return False
            i += 1 + entry[17]
        return True

    @staticmethod
    def _covered(spans: list[tuple[int, int]], size: int) -> bool:
        """The spans tile the object from 0 to its end: no gap and nothing after."""
        at = 0
        for start, end in sorted(spans):
            if start > at:
                return False
            at = max(at, end)
        return at == size

    @staticmethod
    def _printable(text: bytes) -> bool:
        return bool(text) and all(0x20 < b < 0x7F for b in text)


__all__ = ["ImportLibrary"]
