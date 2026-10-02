"""Data appended after the end of an image.

A PNG ends at its `IEND` chunk, a JPEG at `EOI`, a GIF at its trailer byte. Viewers stop there,
so bytes after the end are invisible to anyone looking at the picture -- which is why appending
a zip, a script or a second-stage payload to an image is how packages have smuggled code past
review (a README logo that is also an archive). The formats are walked by structure, not by
searching for the end marker, because a JPEG's embedded thumbnail carries an `EOI` of its own.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from cordon_scanner.formats import FormatBounds, FormatError

MIN_TRAILER: Final = 32
HIGH_ENTROPY_MIN_BYTES: Final = 4096
HIGH_ENTROPY_BITS: Final = 7.5
"""Editors pad; a few trailing bytes or a run of zeros is not a payload."""

PAYLOAD_MAGIC: Final = (
    (b"PK\x03\x04", "a zip archive"),
    (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (b"Rar!\x1a\x07", "a RAR archive"),
    (b"\x1f\x8b", "gzip data"),
    (b"MZ", "a Windows executable"),
    (b"\x7fELF", "an ELF executable"),
    (b"\xcf\xfa\xed\xfe", "a Mach-O executable"),
    (b"#!", "a script"),
    (b"<?php", "PHP"),
    (b"<script", "HTML script"),
)
_SCRIPT_WORDS: Final = (
    b"powershell",
    b"eval(",
    b"exec(",
    b"require(",
    b"import os",
    b"curl ",
    b"wget ",
)


@dataclass(frozen=True)
class Trailer:
    format: str
    offset: int
    size: int
    looks_like: str | None
    """What the appended bytes start as, when recognisable."""
    entropy: float = 0.0
    """Shannon entropy of the trailer, bits per byte. Encrypted or compressed payloads sit near 8;
    the metadata editors leave behind sits far lower."""

    @property
    def opaque(self) -> bool:
        """Large and near-random: what an encrypted second stage looks like, and not metadata."""
        return self.size >= HIGH_ENTROPY_MIN_BYTES and self.entropy >= HIGH_ENTROPY_BITS


class ImageTrailers:
    """Bytes appended after an image's end, and what they look like."""

    @staticmethod
    def image_format(raw: bytes) -> str | None:
        """PNG, JPEG, GIF -- or ZIP, whose end-of-central-directory record is just as final, and after
        which a second file can be appended to any jar, wheel, docx or vsix."""
        if raw[:4] == b"PK\x03\x04":
            return "ZIP"
        if raw[:8] == b"\x89PNG\r\n\x1a\n":
            return "PNG"
        if raw[:3] == b"\xff\xd8\xff":
            return "JPEG"
        if raw[:6] in (b"GIF87a", b"GIF89a"):
            return "GIF"
        return None

    @staticmethod
    @FormatBounds.bounded
    def trailer(raw: bytes) -> Trailer | None:
        """The bytes after the image's structural end, if there are enough to matter."""
        kind = ImageTrailers.image_format(raw)
        if kind is None:
            return None
        end = {
            "PNG": ImageTrailers._png_end,
            "JPEG": ImageTrailers._jpeg_end,
            "GIF": ImageTrailers._gif_end,
            "ZIP": ImageTrailers._zip_end,
        }[kind](raw)
        rest = raw[end:]
        if len(rest) < MIN_TRAILER or not rest.strip(b"\x00 \r\n\t\xff"):
            return None
        return Trailer(
            kind,
            end,
            len(rest),
            ImageTrailers._looks_like(rest),
            ImageTrailers.entropy(rest[: 1 << 16]),
        )

    @staticmethod
    def _looks_like(rest: bytes) -> str | None:
        head = rest.lstrip(b"\x00\r\n\t ")[:64]
        for magic, label in PAYLOAD_MAGIC:
            if head.startswith(magic):
                return label
        window = rest[:4096].lower()
        if any(word in window for word in _SCRIPT_WORDS):
            return "script text"
        # An archive further in: a zip's local header need not be at the start of the trailer.
        if b"PK\x03\x04" in rest[:65536]:
            return "a zip archive"
        return None

    @staticmethod
    def entropy(data: bytes) -> float:
        import math
        from collections import Counter

        if not data:
            return 0.0
        total = len(data)
        return -sum(count / total * math.log2(count / total) for count in Counter(data).values())

    @staticmethod
    def _zip_end(raw: bytes) -> int:
        """The byte after the end-of-central-directory record and its comment."""
        index = raw.rfind(b"PK\x05\x06", max(0, len(raw) - (1 << 16) - 22))
        while index >= 0:
            if index + 22 <= len(raw):
                comment = struct.unpack_from("<H", raw, index + 20)[0]
                return index + 22 + int(comment)
            index = raw.rfind(b"PK\x05\x06", 0, index)
        # Not in the last 64 KiB: the record is further back, so there is more than a comment after it.
        index = raw.rfind(b"PK\x05\x06")
        if index < 0 or index + 22 > len(raw):
            raise FormatError("the ZIP has no end-of-central-directory record")
        return index + 22 + int(struct.unpack_from("<H", raw, index + 20)[0])

    @staticmethod
    def _png_end(raw: bytes) -> int:
        position = 8
        while position + 12 <= len(raw):
            length, chunk = struct.unpack_from(">I4s", raw, position)
            position += 12 + int(length)
            if chunk == b"IEND":
                return position
        raise FormatError("the PNG has no IEND chunk")

    @staticmethod
    def _jpeg_end(raw: bytes) -> int:
        position = 2
        while position + 2 <= len(raw):
            if raw[position] != 0xFF:
                raise FormatError("the JPEG marker stream is broken")
            marker = raw[position + 1]
            if marker == 0xFF:
                position += 1
                continue
            if marker == 0xD9:
                return position + 2
            if 0xD0 <= marker <= 0xD7 or marker == 0x01:
                position += 2
                continue
            if position + 4 > len(raw):
                break
            length = struct.unpack_from(">H", raw, position + 2)[0]
            position += 2 + length
            if marker == 0xDA:
                # Entropy-coded data: 0xFF is followed by 0x00 (a stuffed byte) or a restart marker
                # inside it, and by anything else only where the scan ends.
                while position + 1 < len(raw):
                    if (
                        raw[position] == 0xFF
                        and raw[position + 1] != 0x00
                        and not 0xD0 <= raw[position + 1] <= 0xD7
                    ):
                        break
                    position += 1
        raise FormatError("the JPEG has no end-of-image marker")

    @staticmethod
    def _gif_end(raw: bytes) -> int:
        if len(raw) < 13:
            raise FormatError("the GIF is shorter than its header")
        flags = raw[10]
        position = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
        while position < len(raw):
            block = raw[position]
            if block == 0x3B:
                return position + 1
            if block == 0x21:
                position += 2
            elif block == 0x2C:
                if position + 10 > len(raw):
                    break
                local = raw[position + 9]
                position += 10 + (3 * (2 << (local & 7)) if local & 0x80 else 0) + 1
            else:
                raise FormatError("the GIF block stream is broken")
            while position < len(raw) and raw[position]:
                position += raw[position] + 1
            position += 1
        raise FormatError("the GIF has no trailer")


__all__ = ["ImageTrailers", "Trailer"]
