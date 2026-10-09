"""Container image tarballs built in memory: `docker save` and OCI layouts, with dpkg, apk and
RPM (SQLite) databases, whiteouts and compressed layers."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
import struct
import tarfile
import tempfile
from pathlib import Path

DEBIAN_RELEASE = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'
ALPINE_RELEASE = b'ID=alpine\nVERSION_ID=3.18.4\nPRETTY_NAME="Alpine Linux v3.18"\n'
ROCKY_RELEASE = b'ID="rocky"\nVERSION_ID="9.3"\nPRETTY_NAME="Rocky Linux 9.3"\n'


class ImageKit:
    """Container images and package databases built for tests."""

    @staticmethod
    def dpkg_stanza(
        name: str, version: str, *, source: str = "", status: str = "install ok installed"
    ) -> str:
        lines = [
            f"Package: {name}",
            f"Status: {status}" if status else "",
            "Architecture: amd64",
            f"Version: {version}",
        ]
        if source:
            lines.append(f"Source: {source}")
        lines.append("Description: a package\n with a continuation line")
        return "\n".join(line for line in lines if line) + "\n"

    @staticmethod
    def layer(files: dict[str, bytes | None], *, compress: str = "") -> bytes:
        """A layer tar. A value of None writes a whiteout for that path."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for path, data in files.items():
                if data is None:
                    directory, _, base = path.rpartition("/")
                    path = f"{directory}/.wh.{base}" if directory else f".wh.{base}"
                    data = b""
                info = tarfile.TarInfo(path)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        raw = buffer.getvalue()
        if compress == "gzip":
            return gzip.compress(raw)
        if compress == "zstd":
            return b"\x28\xb5\x2f\xfd" + raw
        return raw

    @staticmethod
    def docker_save(layers: list[bytes], config: dict | None = None) -> bytes:
        buffer = io.BytesIO()
        names = [f"{hashlib.sha256(data).hexdigest()}/layer.tar" for data in layers]
        manifest = json.dumps(
            [{"Config": "config.json", "RepoTags": ["demo:1"], "Layers": names}]
        ).encode()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in [
                ("manifest.json", manifest),
                ("config.json", json.dumps(config or {}).encode()),
                *zip(names, layers, strict=True),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def oci_layout(layers: list[bytes], *, nested_index: bool = False) -> bytes:
        blobs: dict[str, bytes] = {}

        def blob(data: bytes) -> str:
            digest = hashlib.sha256(data).hexdigest()
            blobs[digest] = data
            return f"sha256:{digest}"

        manifest = {"schemaVersion": 2, "layers": [{"digest": blob(data)} for data in layers]}
        top = {"digest": blob(json.dumps(manifest).encode())}
        if nested_index:
            top = {"digest": blob(json.dumps({"manifests": [top]}).encode())}
        index = json.dumps({"schemaVersion": 2, "manifests": [top]}).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            entries = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)]
            entries += [(f"blobs/sha256/{d}", data) for d, data in blobs.items()]
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def oci_multi_platform(platforms: dict[str, list[bytes]], *, attestation: bool = True) -> bytes:
        """An OCI layout whose index lists one image per platform (`"linux/arm64/v8"`), and, as
        buildx writes, an attestation manifest under `unknown/unknown`, which is no platform."""
        blobs: dict[str, bytes] = {}

        def blob(data: bytes) -> str:
            digest = hashlib.sha256(data).hexdigest()
            blobs[digest] = data
            return f"sha256:{digest}"

        manifests = []
        for label, layers in platforms.items():
            parts = label.split("/")
            manifest = {"schemaVersion": 2, "layers": [{"digest": blob(data)} for data in layers]}
            platform = {"os": parts[0], "architecture": parts[1]}
            if len(parts) > 2:
                platform["variant"] = parts[2]
            manifests.append({"digest": blob(json.dumps(manifest).encode()), "platform": platform})
        if attestation:
            statement = {"schemaVersion": 2, "layers": [{"digest": blob(b"{}")}]}
            manifests.append(
                {
                    "digest": blob(json.dumps(statement).encode()),
                    "platform": {"os": "unknown", "architecture": "unknown"},
                }
            )
        image_index = {"schemaVersion": 2, "manifests": manifests}
        index = json.dumps(
            {"schemaVersion": 2, "manifests": [{"digest": blob(json.dumps(image_index).encode())}]}
        ).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            entries = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)]
            entries += [(f"blobs/sha256/{d}", data) for d, data in blobs.items()]
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def rpm_header(tags: dict[int, str | int]) -> bytes:
        index, store = b"", b""
        for tag, value in sorted(tags.items()):
            if isinstance(value, int):
                while len(store) % 4:
                    store += b"\x00"
                index += struct.pack(">iiii", tag, 4, len(store), 1)
                store += struct.pack(">i", value)
            else:
                index += struct.pack(">iiii", tag, 6, len(store), 1)
                store += value.encode() + b"\x00"
        return struct.pack(">II", len(tags), len(store)) + index + store

    @staticmethod
    def rpmdb(packages: list[dict[int, str | int]]) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rpmdb.sqlite"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)"
            )
            connection.executemany(
                "INSERT INTO Packages (blob) VALUES (?)",
                [(ImageKit.rpm_header(p),) for p in packages],
            )
            connection.commit()
            connection.close()
            return path.read_bytes()

    @staticmethod
    def bdb_packages(blobs: list[bytes], page_size: int = 4096) -> bytes:
        """A Berkeley DB hash `Packages` file: a metadata page, one hash page of key/off-page pairs, and
        an overflow chain per header blob -- the layout RPM 4.14 and older write."""
        pages: list[bytearray] = [bytearray(page_size)]
        hash_page = bytearray(page_size)
        pages.append(hash_page)
        items: list[bytes] = []
        for number, blob in enumerate(blobs, 1):
            items.append(b"\x01" + struct.pack("<I", number))  # H_KEYDATA: the package number
            first = len(pages)
            chunk = page_size - 26
            parts = [blob[i : i + chunk] for i in range(0, len(blob), chunk)] or [b""]
            for index, part in enumerate(parts):
                page = bytearray(page_size)
                next_pgno = first + index + 1 if index < len(parts) - 1 else 0
                struct.pack_into("<IIIHH", page, 8, first + index, 0, next_pgno, 1, len(part))
                page[25] = 7  # P_OVERFLOW
                page[26 : 26 + len(part)] = part
                pages.append(page)
            items.append(b"\x03\x00\x00\x00" + struct.pack("<II", first, len(blob)))  # H_OFFPAGE
        offset = page_size
        offsets = []
        for item in items:
            offset -= len(item)
            hash_page[offset : offset + len(item)] = item
            offsets.append(offset)
        struct.pack_into("<IIIHH", hash_page, 8, 1, 0, 0, len(items), offset)
        hash_page[25] = 13  # P_HASH
        for index, item_offset in enumerate(offsets):
            struct.pack_into("<H", hash_page, 26 + 2 * index, item_offset)
        meta = pages[0]
        struct.pack_into("<I", meta, 12, 0x061561)
        struct.pack_into("<I", meta, 20, page_size)
        struct.pack_into("<I", meta, 32, len(pages) - 1)
        meta[25] = 8
        return b"".join(bytes(p) for p in pages)

    @staticmethod
    def ndb_packages(blobs: list[bytes]) -> bytes:
        """A SUSE NDB `Packages.db`: one slot page, then each blob in 16-byte blocks."""
        data = bytearray(4096)
        data[0:16] = b"RpmP" + struct.pack("<III", 0, 1, 1)
        block = 4096 // 16
        for number, blob in enumerate(blobs, 1):
            count = (16 + len(blob) + 15) // 16
            struct.pack_into("<4sIII", data, 16 * number, b"Slot", number, block, count)
            payload = b"BlbS" + struct.pack("<III", number, 0, len(blob)) + blob
            data += payload + b"\x00" * (count * 16 - len(payload))
            block += count
        return bytes(data)
