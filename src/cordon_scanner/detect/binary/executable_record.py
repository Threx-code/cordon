"""The record of one executable, for the facts output (SI-T9): what it is, what it imports, where it sends and what it hides.

One record per ELF, PE or Mach-O file, from its own bytes and never by running it. The record holds counts, names from fixed
vocabularies (the import groups) and a few measures: no string, host name or code of the file. What cannot be known from the
bytes alone is `null` and says why (`signature.valid`, `signature.signer`: checking a signature needs the vendor's trust roots).
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from typing import Any, ClassVar

from cordon_scanner.detect.binary.features import BinaryFeatures
from cordon_scanner.detect.binary.imports import ImportCapabilities, ImportReader
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths


class ExecutableRecord:
    """`of(data, whole)`: the record of one executable, or None when `data` is not one."""

    #: Sections measured at most, and the bytes of each that are measured.
    MAX_SECTIONS: ClassVar[int] = 96
    SECTION_BYTES: ClassVar[int] = 1 << 20
    #: The bytes read for strings and packer marks; a larger file is recorded with `read_whole` false.
    STRING_BYTES: ClassVar[int] = 8 << 20
    FUNCTIONS: ClassVar[int] = 32
    GROUPS: ClassVar[tuple[str, ...]] = (
        "process",
        "network",
        "file",
        "crypto",
        "registry",
        "injection",
    )
    #: A record group and the import group of `ImportCapabilities` that fills it.
    SHARED: ClassVar[dict[str, str]] = {
        "process": "execute",
        "network": "network",
        "injection": "inject",
    }
    ELF_MACHINES: ClassVar[dict[int, str]] = {
        3: "x86",
        8: "mips",
        20: "ppc",
        21: "ppc64",
        22: "s390",
        40: "arm",
        62: "x86_64",
        183: "arm64",
        243: "riscv",
    }
    PE_MACHINES: ClassVar[dict[int, str]] = {
        0x14C: "x86",
        0x1C0: "arm",
        0x1C4: "arm",
        0x8664: "x86_64",
        0xAA64: "arm64",
        0x200: "ia64",
    }
    MACHO_CPUS: ClassVar[dict[int, str]] = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        18: "ppc",
        0x01000012: "ppc64",
    }
    PACKER_NAMES: ClassVar[tuple[tuple[bytes, str], ...]] = (
        (b"UPX", "upx"),
        (b"MPRESS", "mpress"),
        (b"themida", "themida"),
        (b"vmp0", "vmprotect"),
    )
    _SHAPE_NAMES: ClassVar[tuple[str, ...]] = ("url", "ip", "onion", "b64", "psenc")
    _HOST: ClassVar[re.Pattern[bytes]] = re.compile(rb"^https?://([A-Za-z0-9.-]+)")
    MODULE_SIGNATURE: ClassVar[bytes] = b"~Module signature appended~\n"

    @staticmethod
    @OneOff.cache
    def vocabulary() -> dict[str, frozenset[str]]:
        """The imported function names of each record group, from package data."""
        shared = ImportCapabilities.groups()
        out = {
            name: shared.get(source, frozenset())
            for name, source in ExecutableRecord.SHARED.items()
        }
        names = ScannedJson.loads(
            (PackagePaths.data("detect") / "executable-groups.json").read_text(encoding="utf-8")
        )
        out.update({group: frozenset(str(n) for n in listed) for group, listed in names.items()})
        return {group: out[group] for group in ExecutableRecord.GROUPS}

    @classmethod
    def of(
        cls, data: bytes, whole: bool = True, reason: str | None = None
    ) -> dict[str, Any] | None:
        """The record of the executable `data`. `whole` is whether `data` is the whole file; if not, `reason` says why."""
        fmt = BinaryFeatures.format_of(data[:4])
        if fmt not in ("elf", "pe", "macho") or (fmt == "pe" and cls._pe_header(data) is None):
            return None
        if fmt == "macho" and data[:4] == b"\xca\xfe\xba\xbe" and not cls._fat(data):
            return None
        arch, ranges, signed = cls._structure(data, fmt)
        limited = len(data) > cls.STRING_BYTES
        head = data[: cls.STRING_BYTES]
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "format": fmt,
            "architecture": arch,
            "imports": cls._imports(data),
            "strings": cls._strings(head),
            "packer": cls._packer(head),
            "entropy": cls._entropy(data, ranges),
            "signature": {
                "present": signed,
                "valid": None,
                "signer": None,
                "unchecked": "needs the vendor's trust roots; not decided from the bytes",
            },
            "read_whole": whole and not limited,
            "unread_reason": None if whole and not limited else (reason or "over_the_read_limit"),
        }

    # -- what the file is -----------------------------------------------------------------

    @classmethod
    def _structure(cls, data: bytes, fmt: str) -> tuple[str, list[tuple[int, int]], bool]:
        try:
            if fmt == "elf":
                return cls._elf(data)
            if fmt == "pe":
                return cls._pe(data)
            return cls._macho_any(data)
        except (struct.error, ValueError, IndexError):
            return "unknown", [], False

    @classmethod
    def _elf(cls, data: bytes) -> tuple[str, list[tuple[int, int]], bool]:
        order = ">" if data[5] == 2 else "<"
        wide = data[4] == 2
        machine = struct.unpack_from(order + "H", data, 18)[0]
        if wide:
            shoff = struct.unpack_from(order + "Q", data, 40)[0]
            shentsize, shnum = struct.unpack_from(order + "HH", data, 58)
        else:
            shoff = struct.unpack_from(order + "I", data, 32)[0]
            shentsize, shnum = struct.unpack_from(order + "HH", data, 46)
        ranges: list[tuple[int, int]] = []
        for i in range(min(shnum, cls.MAX_SECTIONS)):
            base = shoff + i * shentsize
            if base + shentsize > len(data):
                break
            kind = struct.unpack_from(order + "I", data, base + 4)[0]
            offset, size = struct.unpack_from(
                order + ("QQ" if wide else "II"), data, base + (24 if wide else 16)
            )
            if kind != 8 and size and offset + size <= len(data):
                ranges.append((offset, size))
        signed = data.endswith(cls.MODULE_SIGNATURE)
        return cls.ELF_MACHINES.get(machine, "other"), ranges, signed

    @staticmethod
    def _pe_header(data: bytes) -> int | None:
        if len(data) < 0x40:
            return None
        offset = int(struct.unpack_from("<I", data, 0x3C)[0])
        if offset + 24 > len(data) or data[offset : offset + 4] != b"PE\x00\x00":
            return None
        return offset

    @classmethod
    def _pe(cls, data: bytes) -> tuple[str, list[tuple[int, int]], bool]:
        pe = cls._pe_header(data) or 0
        machine, count, _t, _s, _n, optional_size, _c = struct.unpack_from("<HHIIIHH", data, pe + 4)
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        directory = optional + (112 if magic == 0x20B else 96)
        signed = False
        if optional_size >= (directory - optional) + 40:
            _address, size = struct.unpack_from("<II", data, directory + 32)
            signed = size > 0
        ranges: list[tuple[int, int]] = []
        table = optional + optional_size
        for i in range(min(count, cls.MAX_SECTIONS)):
            if table + i * 40 + 24 > len(data):
                break
            size, pointer = struct.unpack_from("<II", data, table + i * 40 + 16)
            if size and pointer + size <= len(data):
                ranges.append((pointer, size))
        return cls.PE_MACHINES.get(machine, "other"), ranges, signed

    @classmethod
    def _fat(cls, data: bytes) -> list[tuple[int, int, int]]:
        """The (cputype, offset, size) of each slice of a universal binary; empty when it is not one (a Java class)."""
        if len(data) < 8:
            return []
        count = struct.unpack_from(">I", data, 4)[0]
        if not 1 <= count <= 8 or len(data) < 8 + count * 20:
            return []
        slices = []
        for i in range(count):
            cpu, _sub, offset, size, _align = struct.unpack_from(">iIIII", data, 8 + i * 20)
            if offset + size > len(data) or data[offset : offset + 4] not in (
                b"\xcf\xfa\xed\xfe",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xfe\xed\xfa\xce",
            ):
                return []
            slices.append((cpu, offset, size))
        return slices

    @classmethod
    def _macho_any(cls, data: bytes) -> tuple[str, list[tuple[int, int]], bool]:
        if data[:4] != b"\xca\xfe\xba\xbe":
            return cls._macho(data, 0)
        names: list[str] = []
        ranges: list[tuple[int, int]] = []
        signed = False
        for _cpu, offset, size in cls._fat(data):
            arch, found, sig = cls._macho(data[offset : offset + size], 0)
            names.append(arch)
            ranges.extend((offset + start, length) for start, length in found)
            signed = signed or sig
        return "+".join(sorted(set(names))), ranges[: cls.MAX_SECTIONS], signed

    @classmethod
    def _macho(cls, data: bytes, base: int) -> tuple[str, list[tuple[int, int]], bool]:
        order = ">" if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") else "<"
        wide = data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        cpu, _sub, _type, count, _size = struct.unpack_from(order + "iIIII", data, 4)
        cursor = 32 if wide else 28
        ranges: list[tuple[int, int]] = []
        signed = False
        for _ in range(min(count, 256)):
            if cursor + 8 > len(data):
                break
            kind, size = struct.unpack_from(order + "II", data, cursor)
            if size < 8:
                break
            if kind == 0x1D:
                signed = True
            elif kind == 0x19 and wide:
                sections = struct.unpack_from(order + "I", data, cursor + 64)[0]
                for j in range(min(sections, cls.MAX_SECTIONS)):
                    at = cursor + 72 + j * 80
                    length = struct.unpack_from(order + "Q", data, at + 40)[0]
                    offset = struct.unpack_from(order + "I", data, at + 48)[0]
                    if offset and length and offset + length <= len(data):
                        ranges.append((base + offset, length))
            cursor += size
        return cls.MACHO_CPUS.get(cpu, "other"), ranges[: cls.MAX_SECTIONS], signed

    # -- what it does ------------------------------------------------------------------------

    @classmethod
    def _imports(cls, data: bytes) -> dict[str, Any]:
        table = ImportReader.read(data)
        imported = set(table.symbols) if table is not None else set()
        return {
            "read": table is not None,
            "total": len(imported),
            "functions": {
                group: sorted(imported & names)[: cls.FUNCTIONS]
                for group, names in ExecutableRecord.vocabulary().items()
            },
        }

    @classmethod
    def _strings(cls, head: bytes) -> dict[str, int]:
        """Counts of the shapes the strings take, and of the distinct hosts the URLs name; never the strings."""
        text = BinaryFeatures.strings(head)
        out = {name: len(BinaryFeatures.SHAPES[name].findall(text)) for name in cls._SHAPE_NAMES}
        hosts = {
            m.group(1).lower()
            for found in BinaryFeatures.SHAPES["url"].findall(text)
            if (m := cls._HOST.match(found))
        }
        out["url_hosts"] = len(hosts)
        return out

    @classmethod
    def _packer(cls, head: bytes) -> str | None:
        found = BinaryFeatures.PACKERS.search(head)
        if found is None:
            return None
        return next((name for mark, name in cls.PACKER_NAMES if mark in found.group(0)), "other")

    @classmethod
    def _entropy(cls, data: bytes, ranges: list[tuple[int, int]]) -> dict[str, float | int | None]:
        values = [
            cls._bits(data[start : start + min(size, cls.SECTION_BYTES)]) for start, size in ranges
        ]
        if not values:
            return {"max": None, "mean": None, "sections": 0}
        return {
            "max": round(max(values), 2),
            "mean": round(sum(values) / len(values), 2),
            "sections": len(values),
        }

    @staticmethod
    def _bits(block: bytes) -> float:
        counts = Counter(block)
        n = len(block)
        return -sum(c / n * math.log2(c / n) for c in counts.values())


__all__ = ["ExecutableRecord"]
