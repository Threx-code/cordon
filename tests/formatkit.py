"""Byte-level builders for the format readers' tests: PNG, JPEG, GIF, MS-CFB compound files with
VBA projects (MS-OVBA), OOXML packages. Shared by the unit tests and the fuzz seeds."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from cordon_scanner.formats import ole


def png(extra: bytes = b"") -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + chunk(b"IEND", b"")
        + extra
    )


def jpeg(extra: bytes = b"", *, thumbnail: bool = False) -> bytes:
    """SOI, an APP1 that (optionally) holds a whole thumbnail JPEG with its own EOI, a scan with
    stuffed 0xFF bytes and a restart marker, then EOI."""
    app1_body = b"Exif\x00\x00" + (b"\xff\xd8\xff\xd9" if thumbnail else b"")
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_body) + 2) + app1_body
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00"
    scan = b"\x12\xff\x00\x34\xff\xd0\x56"
    return b"\xff\xd8" + app1 + sos + scan + b"\xff\xd9" + extra


def gif(extra: bytes = b"") -> bytes:
    screen = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff"
    control = b"\x21\xf9\x04\x00\x00\x00\x00\x00"
    image = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02\x02\x44\x01\x00"
    return screen + control + image + b"\x3b" + extra


def ovba_literal(data: bytes) -> bytes:
    """MS-OVBA compression using literal tokens only: valid, if not small."""
    out = bytearray(b"\x01")
    for start in range(0, len(data), 3600):
        piece = data[start : start + 3600]
        body = b"".join(b"\x00" + piece[i : i + 8] for i in range(0, len(piece), 8))
        out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def compound(streams: dict[str, bytes]) -> bytes:
    """An MS-CFB file holding `streams` ("VBA/dir" and the like) in one storage level.

    Built with a mini-stream cutoff of zero, so every stream lives in the regular FAT; the
    mini-stream path is covered by `test_a_small_stream_is_read_from_the_ministream`.
    """
    sector = 512
    storages = sorted({name.split("/", 1)[0] for name in streams if "/" in name})
    blobs: list[bytes] = []
    chains: list[int] = []
    next_sector = 2  # 0 is the FAT, 1 the directory
    fat = [0xFFFFFFFD, 0xFFFFFFFE]
    for data in streams.values():
        count = max((len(data) + sector - 1) // sector, 1)
        chains.append(next_sector)
        for index in range(count):
            fat.append(next_sector + index + 1 if index < count - 1 else 0xFFFFFFFE)
        next_sector += count
        blobs.append(data.ljust(count * sector, b"\x00"))
    fat += [0xFFFFFFFF] * (128 - len(fat))

    def entry(
        name: str, kind: int, left: int, right: int, child: int, start: int, size: int
    ) -> bytes:
        encoded = (name + "\x00").encode("utf-16-le")
        return (
            encoded.ljust(64, b"\x00")
            + struct.pack("<HBB", len(encoded), kind, 1)
            + struct.pack("<III", left, right, child)
            + b"\x00" * 36
            + struct.pack("<IQ", start, size)
        )

    none = 0xFFFFFFFF
    records: list[bytes] = []
    names = list(streams)
    # Root, then each storage, then the streams; siblings chained through `right`.
    storage_index = {name: 1 + i for i, name in enumerate(storages)}
    first_stream = 1 + len(storages)
    top = [storage_index[s] for s in storages] + [
        first_stream + i for i, n in enumerate(names) if "/" not in n
    ]
    records.append(entry("Root Entry", 5, none, none, top[0] if top else none, 0xFFFFFFFE, 0))
    for position, storage in enumerate(storages):
        members = [first_stream + i for i, n in enumerate(names) if n.startswith(storage + "/")]
        after = (
            top[top.index(storage_index[storage]) + 1]
            if storage_index[storage] != top[-1]
            else none
        )
        records.append(entry(storage, 1, none, after, members[0] if members else none, 0, 0))
        del position
    for i, name in enumerate(names):
        parent = name.split("/", 1)[0] if "/" in name else None
        siblings = (
            [first_stream + j for j, n in enumerate(names) if n.startswith(parent + "/")]
            if parent
            else [t for t in top if t >= first_stream]
        )
        here = first_stream + i
        after = siblings[siblings.index(here) + 1] if here != siblings[-1] else none
        leaf = name.rsplit("/", 1)[-1]
        records.append(entry(leaf, 2, none, after, none, chains[i], len(streams[name])))
    directory = b"".join(records).ljust(sector, b"\x00")
    assert len(directory) == sector, "the builder keeps the directory to one sector"

    header = bytearray(512)
    header[0:8] = ole.MAGIC
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 0x28, 0, 1, 1, 0, 0, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    struct.pack_into("<109I", header, 0x4C, 0, *([0xFFFFFFFF] * 108))
    return bytes(header) + struct.pack("<128I", *fat) + directory + b"".join(blobs)


def dir_stream(modules: dict[str, int]) -> bytes:
    records = struct.pack("<HI", 0x0001, 4) + struct.pack("<I", 1)
    records += struct.pack("<HI", 0x0009, 4) + b"\x00" * 6
    for name, offset in modules.items():
        records += struct.pack("<HI", 0x001A, len(name)) + name.encode()
        records += struct.pack("<HI", 0x0031, 4) + struct.pack("<I", offset)
        records += struct.pack("<HI", 0x002B, 0)
    records += struct.pack("<HI", 0x0010, 0)
    return ovba_literal(records)


def vba_project(source: str, *, prefix: str = "") -> bytes:
    cache = b"\xcc" * 40
    code = ovba_literal(('Attribute VB_Name = "Module1"\r\n' + source).encode("latin-1"))
    return compound(
        {
            f"{prefix}VBA/dir": dir_stream({"Module1": len(cache)}),
            f"{prefix}VBA/Module1": cache + code,
        }
    )


def ooxml(parts: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        for name, data in parts.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def relationship(kind: str, target: str, *, external: bool = True) -> str:
    mode = ' TargetMode="External"' if external else ""
    return (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        f'relationships/{kind}" Target="{target}"{mode}/></Relationships>'
    )


class Reduces:
    """Pickles as a call to `target(*args)`. Pickling it calls nothing."""

    def __init__(self, target, *args) -> None:
        self.target, self.args = target, args

    def __reduce__(self):
        return self.target, self.args
