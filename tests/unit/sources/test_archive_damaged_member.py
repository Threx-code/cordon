"""A damaged compressed member is refused as unreadable, and the rest of the archive is read
(S1 fuzzing found a zlib.error escaping the walk, reviews/release-080/SECURITY-HARDENING.md)."""

from __future__ import annotations

import io
import zipfile

from cordon_scanner.sources.archive import ArchiveReader, Rejection


class TestADamagedDeflateMember:
    @staticmethod
    def archive() -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("pkg/damaged.py", b"import os\nprint(os.getcwd())\n" * 50)
            archive.writestr("pkg/sound.py", b"VALUE = 1\n", compress_type=zipfile.ZIP_STORED)
        data = bytearray(buffer.getvalue())
        start = data.index(b"pkg/damaged.py") + len("pkg/damaged.py")
        for offset in range(4, 40):
            data[start + offset] ^= 0x5A
        return bytes(data)

    def test_it_is_refused_and_the_rest_is_read(self) -> None:
        result = ArchiveReader.extract(self.archive(), path="pkg.zip")
        assert [m.name for m in result.members] == ["pkg/sound.py"]
        assert [(r.name, r.reason) for r in result.rejected] == [
            ("pkg/damaged.py", Rejection.UNREADABLE)
        ]
