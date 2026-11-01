"""What a file's bytes are, read from their structure, never their name (items 36 and 30).

A member was opened as an archive only when its name said so (`ArchiveReader.is_archive`, a suffix
list), so a zip named `docs/notes.txt`, a zip appended to a PNG, or a lone `install.js.gz` was handed
on as opaque bytes and never read. The format decision after the gate was already by bytes
(`ArchiveReader.extract`); this is the gate's.

```
  bytes ──► CompressedHeader.format_of  gzip / bzip2 / xz / zstd, only when the full header parses
        ──► ArchiveSignatures.opens     a zip (a local header at 0, or a valid end-of-directory
                                        record: any prefix, a PNG or a stub), a tar (ustar and a
                                        header checksum that adds up), or a compressed stream
```

Stricter than `MemberNames.not_an_archive`'s "any archive signature anywhere", on purpose: that test
asks whether a member that CLAIMS to be an archive holds one at all; this one decides whether a
member that claims nothing is opened, so a chance `PK` or `\\x1f\\x8b` in an image must not make it one
(item 30's review: the magic alone is two or three bytes any file can start with).
"""

from __future__ import annotations

import io
import posixpath
import struct
import zipfile
import zlib

#: The suffixes a single compressed stream is named with; the inner name is the outer one without it.
STREAM_SUFFIXES = (".gz", ".gzip", ".bz2", ".xz", ".zst", ".zstd")


class CompressedHeader:
    """A compressed stream's format, from its full header, or None."""

    #: bzip2's two block magics after "BZh" and the block size: a compressed block, or the end of an
    #: empty stream.
    _BZIP2_BLOCKS = (b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90")

    @staticmethod
    def format_of(data: bytes) -> str | None:
        """ "gzip", "bzip2", "xz" or "zstd" when the format's full header parses; else None.

        gzip: CM is 8 (deflate) and FLG's reserved bits are zero. bzip2: "BZh", a block size digit
        1-9 and a block magic. xz: the six-byte magic, stream flags with their reserved bits zero
        and a CRC32 over them that matches. zstd: the frame magic and a frame header descriptor
        whose reserved bit is zero."""
        if len(data) >= 10 and data[:2] == b"\x1f\x8b":
            return "gzip" if data[2] == 8 and data[3] & 0xE0 == 0 else None
        if len(data) >= 10 and data[:3] == b"BZh":
            size_ok = 0x31 <= data[3] <= 0x39
            return "bzip2" if size_ok and data[4:10] in CompressedHeader._BZIP2_BLOCKS else None
        if len(data) >= 12 and data[:6] == b"\xfd7zXZ\x00":
            flags = data[6:8]
            (crc,) = struct.unpack("<I", data[8:12])
            valid = flags[0] == 0 and flags[1] & 0xF0 == 0 and zlib.crc32(flags) == crc
            return "xz" if valid else None
        if len(data) >= 5 and data[:4] == b"\x28\xb5\x2f\xfd":
            return "zstd" if data[4] & 0x08 == 0 else None
        return None


class ArchiveSignatures:
    """Whether bytes are an archive a reader would open, whatever they are called."""

    @staticmethod
    def opens(data: bytes) -> bool:
        """A zip, a tar or a compressed stream, by structure. A zip is read by its directory at the
        end, so any prefix (a PNG, a self-extracting stub) leaves it a zip: `zipfile.is_zipfile`
        reads the end-of-directory record; a spilled member's prefix holds no end, so only its head
        is read there."""
        if not data:
            return False
        if data.startswith(b"PK\x03\x04"):
            return True
        if CompressedHeader.format_of(data) is not None:
            return True
        if ArchiveSignatures.tar_header(data):
            return True
        # Every member passes here: one byte search of the tail (the end record lies in its last
        # 65,557 bytes) before `is_zipfile` builds a reader to check the record it found.
        tail = data[-65_557:]
        return b"PK\x05\x06" in tail and zipfile.is_zipfile(io.BytesIO(data))

    @staticmethod
    def tar_header(data: bytes) -> bool:
        """Whether bytes begin with a tar header: a whole 512-byte block whose checksum field
        (octal, bytes 148-156) equals the block's sum with the field read as spaces. A ustar, GNU
        or old v7 tar alike; a block of zeros (an empty tar's end) states no checksum and is not."""
        if len(data) < 512:
            return False
        field = data[148:156].split(b"\x00", 1)[0].strip()
        try:
            stated = int(field, 8)
        except ValueError:
            return False
        header = data[:148] + b" " * 8 + data[156:512]
        return stated == sum(header)

    @staticmethod
    def inner_name(path: str) -> str:
        """What a single compressed stream holds is named for the stream, without its suffix
        (install.js.gz holds install.js), never by the gzip header's FNAME, which the archive's
        author writes (item 30). A stream with no such suffix holds a file of its own name."""
        base = posixpath.basename(path.rsplit("!", 1)[-1])
        lowered = base.lower()
        for suffix in STREAM_SUFFIXES:
            if lowered.endswith(suffix) and len(base) > len(suffix):
                return base[: -len(suffix)]
        return base


__all__ = ["STREAM_SUFFIXES", "ArchiveSignatures", "CompressedHeader"]
