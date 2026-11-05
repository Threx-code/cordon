"""Android packages built to the format, for the androguard module's tests: a compiled manifest
(ResXMLTree), a resource table with string values (ResTable), and an APK zip of them with a dex. Google's
aapt2 reads what this writes (`aapt2 dump badging`, `dump xmltree`), and apksigner signs it; the signed
fixtures in tests/unit/data/rule_reference/android were made that way (see the README there)."""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Any

ANDROID = "http://schemas.android.com/apk/res/android"
IDS = {
    "label": 0x01010001, "name": 0x01010003, "enabled": 0x0101000E, "versionCode": 0x0101021B,
    "versionName": 0x0101021C, "minSdkVersion": 0x0101020C, "targetSdkVersion": 0x01010270,
    "maxSdkVersion": 0x01010271,
}  # fmt: skip
"""The framework attribute IDs the manifests here use."""


class Ref:
    """An attribute value that names a resource (`@string/app_name`)."""

    def __init__(self, resource_id: int) -> None:
        self.id = resource_id


class AndroidKit:
    @staticmethod
    def pool(strings: list[str]) -> bytes:
        """A UTF-8 ResStringPool chunk."""
        body, offsets = b"", []
        for s in strings:
            raw = s.encode("utf-8")
            assert len(s) < 128 and len(raw) < 128, "the kit writes one-byte lengths"
            offsets.append(len(body))
            body += bytes([len(s), len(raw)]) + raw + b"\x00"
        body = body.ljust((len(body) + 3) // 4 * 4, b"\x00")
        header = 28
        start = header + 4 * len(strings)
        size = start + len(body)
        return (
            struct.pack("<HHIIIIII", 0x0001, header, size, len(strings), 0, 0x100, start, 0)
            + b"".join(struct.pack("<I", o) for o in offsets) + body
        )  # fmt: skip

    @staticmethod
    def manifest(tree: tuple[str, dict[str, Any], list[Any]]) -> bytes:
        """A compiled XML document from (tag, attributes, children). An attribute named `android:x`
        is in Android's namespace and carries its resource ID; `x` is a plain one (the package)."""
        names: list[str] = []
        for _tag, attrs, _children in AndroidKit._walk(tree):
            for key in attrs:
                bare = key.split(":", 1)[-1]
                if key.startswith("android:") and bare not in names:
                    names.append(bare)
        strings = list(names)

        def index(s: str) -> int:
            if s not in strings:
                strings.append(s)
            return strings.index(s)

        index("android"), index(ANDROID)
        chunks: list[bytes] = []

        def element(node: tuple[str, dict[str, Any], list[Any]]) -> None:
            tag, attrs, children = node
            rows = b""
            for key, value in attrs.items():
                ns = index(ANDROID) if key.startswith("android:") else 0xFFFFFFFF
                name = index(key.split(":", 1)[-1])
                if isinstance(value, Ref):
                    raw, kind, data = 0xFFFFFFFF, 0x01, value.id
                elif isinstance(value, bool):
                    raw, kind, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if value else 0
                elif isinstance(value, int):
                    raw, kind, data = 0xFFFFFFFF, 0x10, value
                else:
                    raw = index(value)
                    kind, data = 0x03, raw
                rows += struct.pack("<IIIHBBI", ns, name, raw, 8, 0, kind, data)
            ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, index(tag), 20, 20, len(attrs), 0, 0, 0)
            chunks.append(
                struct.pack("<HHIII", 0x0102, 16, 16 + len(ext) + len(rows), 1, 0xFFFFFFFF)
                + ext
                + rows
            )
            for child in children:
                element(child)
            chunks.append(
                struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, index(tag))
            )

        element(tree)
        ns_start = struct.pack(
            "<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, index("android"), index(ANDROID)
        )
        ns_end = struct.pack(
            "<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, index("android"), index(ANDROID)
        )
        ids = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(names)) + b"".join(
            struct.pack("<I", IDS[n]) for n in names
        )
        body = AndroidKit.pool(strings) + ids + ns_start + b"".join(chunks) + ns_end
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body

    @staticmethod
    def _walk(
        node: tuple[str, dict[str, Any], list[Any]],
    ) -> list[tuple[str, dict[str, Any], list[Any]]]:
        out = [node]
        for child in node[2]:
            out.extend(AndroidKit._walk(child))
        return out

    @staticmethod
    def resources(package: str, strings: dict[str, str]) -> bytes:
        """A resource table of package 0x7f with one type, `string`, its entries in order (the first
        is 0x7f010000), each in the default configuration."""
        values = AndroidKit.pool(list(strings.values()))
        types, keys = AndroidKit.pool(["string"]), AndroidKit.pool(list(strings))
        count = len(strings)
        spec = struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * count, 1, 0, 0, count) + bytes(
            4 * count
        )
        config = struct.pack("<I", 64) + bytes(60)
        header = 20 + len(config)
        entries = b"".join(struct.pack("<HHIHBBI", 8, 0, i, 8, 0, 0x03, i) for i in range(count))
        offsets = b"".join(struct.pack("<I", 16 * i) for i in range(count))
        start = header + len(offsets)
        type_chunk = struct.pack(
            "<HHIBBHII", 0x0201, header, start + len(entries), 1, 0, 0, count, start
        )
        type_chunk += config + offsets + entries
        name = package.encode("utf-16-le").ljust(256, b"\x00")
        head = 288
        package_body = types + keys + spec + type_chunk
        package_chunk = (
            struct.pack("<HHII", 0x0200, head, head + len(package_body), 0x7F) + name
            + struct.pack("<IIIII", head, 1, head + len(types), count, 0) + package_body
        )  # fmt: skip
        body = values + package_chunk
        return struct.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body

    @staticmethod
    def apk(members: dict[str, bytes]) -> bytes:
        """A zip of the members, each stored (uncompressed), in the order given."""
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
            for name, data in members.items():
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 31, 0, 0, 0))
                z.writestr(info, data)
        return out.getvalue()


__all__ = ["ANDROID", "IDS", "AndroidKit", "Ref"]
