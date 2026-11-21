"""A lone gzip stream whose expansion is explained by its own format: the size it declares (08-BENIGN-F-SHAPES
7c).

Padding is how a payload is put out of a scanner's reach, so a stream that expands past
`max_archive_ratio` times its size is refused unread (`Rejection.PADDED`). Zero-filled data is real
too: astronomy masks (FITS), MRI volumes (NIfTI), disk images in test fixtures compress a thousandfold
(5 benign PyPI units, 05-CENSUS C2). The rule is fitted to what makes those real, never to "zeros are
fine":

```
  gzip, one member ──► first decompressed bytes: a format that declares its own total size
        │               FITS primary HDU · NIfTI-1 · NTFS boot sector (only formats measured)
        ▼
  declared size == ISIZE (the trailer), < 4 GiB so ISIZE cannot have wrapped, <= max_stream_bytes
        │ all three
        ▼
  read like any member, to its end, with the cap AT the declared size (a byte more is padding again)
        │
        ▼
  the payload is exactly the declared size, and the format's padding (FITS's rounding to 2880 after
  its data; a NIfTI header's gap before vox_offset) is all zeros -- else refused as padding
```

Anything else -- no recognised header, a size one byte off, more than one gzip member -- is refused
as today. A padding bomb would have to carry a valid header declaring its full expanded size, and is
then read whole within the ordinary limits.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.foundation.limits import Limits

_HEAD = 64 * 1024
_FITS_BLOCK = 2880


@dataclass(frozen=True, slots=True)
class Declared:
    """What a stream's own format declares: its name, its total size, and the byte ranges
    (start, end, fill) that are the format's padding and must hold only `fill` (zeros; a FITS header
    is padded with blanks)."""

    format: str
    size: int
    slack: tuple[tuple[int, int, int], ...]


class DeclaredSize:
    """The plan for one lone gzip stream, or None."""

    @staticmethod
    def of(data: bytes, limits: Limits) -> Declared | None:
        if len(data) < 18 or data[:2] != b"\x1f\x8b":
            return None
        (isize,) = struct.unpack("<I", data[-4:])
        try:
            head = zlib.decompressobj(31).decompress(data, _HEAD)
        except zlib.error:
            return None
        found = DeclaredSize._fits(head) or DeclaredSize._nifti(head) or DeclaredSize._ntfs(head)
        if found is None:
            return None
        if found.size != isize or found.size >= 1 << 32:
            return None
        if limits.max_stream_bytes and found.size > limits.max_stream_bytes:
            return None
        return found

    @staticmethod
    def _fits(head: bytes) -> Declared | None:
        """A FITS primary header: 80-byte cards from `SIMPLE  =` to `END`, in 2880-byte blocks; the
        data is |BITPIX|/8 x NAXIS1 x ... x NAXISn bytes, padded with zeros to a block."""
        if not head.startswith(b"SIMPLE  =") or b"T" not in head[10:30]:
            return None
        cards: dict[str, str] = {}
        end = None
        for i in range(0, min(len(head), _FITS_BLOCK * 36), 80):
            card = head[i : i + 80].decode("ascii", "replace")
            if card[:8].rstrip() == "END":
                end = i
                break
            if card[8:10] == "= ":
                cards[card[:8].strip()] = card[10:].split("/", 1)[0].strip()
        if end is None:
            return None
        # An extension after the primary data would make the stream longer than this declares, so
        # the equality with ISIZE below leaves none, whatever EXTEND says.
        try:
            bitpix, naxis = int(cards["BITPIX"]), int(cards["NAXIS"])
            axes = [int(cards[f"NAXIS{n}"]) for n in range(1, naxis + 1)]
        except (KeyError, ValueError):
            return None
        if bitpix not in (8, 16, 32, 64, -32, -64) or not 1 <= naxis <= 999 or min(axes) < 0:
            return None
        header = (end // _FITS_BLOCK + 1) * _FITS_BLOCK
        data = abs(bitpix) // 8
        for axis in axes:
            data *= axis
        size = header + -(-data // _FITS_BLOCK) * _FITS_BLOCK
        return Declared("FITS", size, ((end + 80, header, 0x20), (header + data, size, 0)))

    @staticmethod
    def _nifti(head: bytes) -> Declared | None:
        """A NIfTI-1 single file (`n+1`): sizeof_hdr 348, vox_offset where the voxels start, then
        dim[1..dim[0]] x bitpix/8 bytes. The four extension bytes and the gap to vox_offset are zeros."""
        if (
            len(head) < 352
            or struct.unpack_from("<i", head)[0] != 348
            or head[344:348] != b"n+1\x00"
        ):
            return None
        dims = struct.unpack_from("<8h", head, 40)
        bitpix = struct.unpack_from("<h", head, 72)[0]
        vox = struct.unpack_from("<f", head, 108)[0]
        if not 1 <= dims[0] <= 7 or bitpix not in (8, 16, 32, 64, 128) or vox != int(vox):
            return None
        start = int(vox)
        if start < 352:
            return None
        size = bitpix // 8
        for d in dims[1 : 1 + dims[0]]:
            if d < 1:
                return None
            size *= d
        return Declared("NIfTI-1", start + size, ((348, start, 0),))

    @staticmethod
    def _ntfs(head: bytes) -> Declared | None:
        """An NTFS volume image: the boot sector's OEM id, 512-byte sectors, and total sectors; the
        image is that many sectors plus the backup boot sector."""
        if len(head) < 512 or head[3:11] != b"NTFS    " or head[510:512] != b"\x55\xaa":
            return None
        (per_sector,) = struct.unpack_from("<H", head, 11)
        (total,) = struct.unpack_from("<Q", head, 0x28)
        if per_sector != 512 or total < 1:
            return None
        return Declared("NTFS", (total + 1) * per_sector, ())

    @staticmethod
    def slack_is_zero(payload: bytes, declared: Declared) -> bool:
        """Whether the payload is exactly the declared size and every padding byte is zero. A payload
        spilled to disk (`SpilledBytes`) is read from its file at each range, never held whole."""
        path = getattr(payload, "path", "")
        size = getattr(payload, "size", len(payload))
        if size != declared.size:
            return False
        if not path:
            return all(payload[a:b] == bytes([fill]) * (b - a) for a, b, fill in declared.slack)
        with Path(path).open("rb") as fh:
            for start, end, fill in declared.slack:
                fh.seek(start)
                left = end - start
                while left > 0:
                    chunk = fh.read(min(left, 1 << 20))
                    if not chunk or chunk != bytes([fill]) * len(chunk):
                        return False
                    left -= len(chunk)
        return True


__all__ = ["Declared", "DeclaredSize"]
