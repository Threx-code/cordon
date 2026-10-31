"""lnk and zip held to YARA-X 1.21.0's own output, recorded (data/rule_reference/yarax/lnk-zip-1.21.0.json.gz).

The shortcuts are built here, deterministically: the full shortcut, every combination of sections
the builder writes in steps of three flag values, ANSI and Unicode, and 200 seeded damages (cut short,
a byte changed, a size made 0xFFFF). Each is looked up by its SHA-256 in `yr dump --module lnk` and
compared value by value as a rule reads it (enum names as their numbers, bytes decoded). The zip cases
are the acceptance rules (prefixed, trailing bytes, empty, empty after a prefix, not a zip, a strong-
encryption entry ending the listing, a method without an enum value, ZIP64, a full-length comment,
bad UTF-8) from `yr scan` printing each entry through `console`, since `yr dump` has no zip. The one
named difference: 150,000 entries, where the reference stops at 100,000 and this reader lists all.

Recorded, so the comparison runs without the reference: 288 shortcuts, 5,145 values, identical; 16
zip cases identical but the named one. The same run held 138 real archives (wheels, jars, nupkgs,
vsix) identical, 121,798 entries; their bytes are corpus files and are not committed.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import random
import struct
import zipfile
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.formats.lnk import Lnk
from cordon_scanner.detect.binary.modules.formats.zip import Zip
from support import ROOT
from unit.detect.binary.modules.formats.test_lnk import GUID, Shortcut

RECORD: dict[str, Any] = json.loads(
    gzip.decompress(
        (ROOT / "tests/unit/data/rule_reference/yarax/lnk-zip-1.21.0.json.gz").read_bytes()
    )
)


class Shortcuts:
    """The differential's shortcut set, as it was built for the recording."""

    @staticmethod
    def all() -> list[bytes]:
        files = [Shortcut.full(), Shortcut.full(overlay=b"PK\x03\x04" + b"x" * 100)]
        for flags in range(0, 256, 3):
            head = Shortcut.header(flags | 0x80 * (flags & 1))
            body = b""
            if flags & Lnk.ID_LIST:
                body += Shortcut.id_list(
                    b"\x1f\x50" + GUID.bytes_le, b"\x32\x00" + b"\x00" * 10 + b"a.exe\x00"
                )
            if flags & Lnk.LINK_INFO:
                body += Shortcut.link_info(b"C:\\x.exe", b"VOL")
            unicode = bool(flags & Lnk.UNICODE)
            for bit, text in (
                (Lnk.NAME, "name"),
                (Lnk.RELATIVE, "..\\r"),
                (Lnk.WORKING, "C:\\w"),
                (Lnk.ARGUMENTS, "/c x"),
                (Lnk.ICON, "i.dll"),
            ):
                if flags & bit:
                    body += (
                        Shortcut.utf16(text)
                        if unicode
                        else struct.pack("<H", len(text)) + text.encode()
                    )
            files.append(head + body + Shortcut.tracker() + struct.pack("<I", 0))
        rng = random.Random(20261031)  # noqa: S311 -- the recorded set's seed, not key material
        base = list(files)
        for _ in range(200):
            f = bytearray(rng.choice(base))
            kind = rng.randrange(3)
            if kind == 0:
                f = f[: rng.randrange(76, len(f) + 1)]
            elif kind == 1:
                f[rng.randrange(76, len(f))] = rng.randrange(256)
            else:
                at = rng.randrange(76, max(77, len(f) - 2))
                f[at : at + 2] = b"\xff\xff"
            files.append(bytes(f))
        return files


class Values:
    """Both sides as a rule reads them: enum names as numbers, bytes decoded, constants left out."""

    ENUMS: ClassVar[dict[str, int]] = {
        **{k: v for e in Lnk.ENUMS.values() for k, v in e.items()},
        **Zip.COMPRESSION,
    }

    @staticmethod
    def reference(v: Any) -> Any:
        if isinstance(v, dict):
            if set(v) == {"encoding", "value"}:
                return base64.b64decode(v["value"])
            return {k: Values.reference(x) for k, x in v.items()}
        if isinstance(v, list):
            return [Values.reference(x) for x in v]
        if isinstance(v, str):
            return Values.ENUMS.get(v, v.encode("utf-8"))
        return v

    @staticmethod
    def ours(v: Any, drop: frozenset[str] = frozenset()) -> Any:
        if hasattr(v, "keys"):
            keys = list(v.keys())
            if keys and all(isinstance(k, int) for k in keys):
                return [Values.ours(v[k]) for k in sorted(keys)]
            return {k: Values.ours(v[k]) for k in keys if k not in drop}
        return v


class Zips:
    """The differential's crafted zip cases, by name."""

    @staticmethod
    def of(members: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=method) as z:
            for name, data in members.items():
                z.writestr(name, data)
        return out.getvalue()

    @staticmethod
    def case(name: str) -> bytes:
        base = Zips.of({"a.txt": b"hello" * 100, "dir/b.bin": b"\0" * 10})
        simple = {
            "plain": lambda: base,
            "prefixed": lambda: b"Cr24" + b"\0" * 300 + base,
            "trailing": lambda: base + b"junk" * 50,
            "empty": lambda: Zips.of({}),
            "empty-after-prefix": lambda: b"prefix" + Zips.of({}),
            "notzip": lambda: b"not a zip",
            "eocd-only": lambda: b"PK\x05\x06",
            "stored": lambda: Zips.of({"x": b"data"}, zipfile.ZIP_STORED),
            "bzip2": lambda: Zips.of({"x": b"data"}, zipfile.ZIP_BZIP2),
            "lzma": lambda: Zips.of({"x": b"data"}, zipfile.ZIP_LZMA),
        }
        if name in simple:
            return simple[name]()
        if name == "method7":
            f = bytearray(Zips.of({"x": b"data"}, zipfile.ZIP_STORED))
            c = f.index(b"PK\x01\x02")
            f[c + 10 : c + 12] = struct.pack("<H", 7)
            return bytes(f)
        if name == "strong-enc":
            f = bytearray(Zips.of({"one": b"1", "two": b"2", "three": b"3"}))
            s = f.index(b"PK\x01\x02", f.index(b"PK\x01\x02") + 4)
            f[s + 8 : s + 10] = struct.pack("<H", 1 << 6)
            return bytes(f)
        if name == "bad-utf8":
            f = bytearray(Zips.of({"ab": b"1"}, zipfile.ZIP_STORED))
            c = f.index(b"PK\x01\x02")
            f[c + 46 : c + 48] = b"a\xff"
            return bytes(f)
        out = io.BytesIO()
        if name == "zip64":
            with (
                zipfile.ZipFile(out, "w", allowZip64=True) as z,
                z.open("big", "w", force_zip64=True) as w,
            ):
                w.write(b"z" * 1000)
        elif name == "comment-max":
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("c", b"1")
                z.comment = b"x" * 0xFFFF
        else:
            with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as z:
                for i in range(150_000):
                    z.writestr(zipfile.ZipInfo(f"f{i}"), b"")
        return out.getvalue()


class TestLnkAgainstYaraX:
    def test_every_shortcut_gives_the_reference_values(self) -> None:
        constants = frozenset(Lnk.FILE_ATTRIBUTES) | frozenset(Lnk.ENUMS)
        files = Shortcuts.all()
        assert len(files) == len(RECORD["lnk"]) == 288
        for file in files:
            ref = Values.reference(RECORD["lnk"][hashlib.sha256(file).hexdigest()])
            ours = Values.ours(Lnk.data(file), constants)
            if not ours.get("target_id_list", True):
                ours.pop("target_id_list")  # the reference prints no empty list
            assert ours == ref, hashlib.sha256(file).hexdigest()


class TestZipAgainstYaraX:
    @pytest.mark.parametrize("name", sorted(n[:-4] for n in RECORD["zip"]))
    def test_each_case_gives_the_reference_listing(self, name: str) -> None:
        ref = RECORD["zip"][name + ".zip"]
        out = Zip.data(Zips.case(name))
        entries = out["entries"]
        ours = [
            [
                entries[i]["file_path"].decode("utf-8"),
                entries[i]["compression"],
                entries[i]["uncompressed_size"],
                entries[i]["compressed_size"],
            ]
            for i in range(len(entries))
        ]
        assert out["is_zip"] is ref["is_zip"]
        if name == "entries-150k":
            # The named difference: the reference lists 100,000; every entry is listed here.
            assert ref["entries"]["count"] == 100_000 and len(ours) == 150_000
            assert ours[0] == ref["entries"]["first"] and ours[99_999] == ref["entries"]["last"]
            return
        assert ours == ref["entries"]
