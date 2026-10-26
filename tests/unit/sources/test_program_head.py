"""An oversized archive member that is a compiled program is read up to the member limit."""

from __future__ import annotations

import io
import tarfile
import zipfile

from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader, Rejection

LIMITS = DEFAULT_LIMITS.merged(max_member_bytes=4096, max_file_bytes=1024)
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 9


class Archives:
    @staticmethod
    def tar(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def zip(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()


class TestOversizedPrograms:
    def test_a_program_past_the_limit_is_read_to_the_limit(self) -> None:
        program = ELF + bytes(range(256)) * 40  # about 10 KB, past the 4 KB limit
        result = ArchiveReader.extract(
            Archives.tar({"package/bin/tool": program}), path="p.tgz", limits=LIMITS
        )
        kept = {m.name: m.data for m in result.members}
        assert kept["package/bin/tool"] == program[: ArchiveReader.member_limit(LIMITS)]

    def test_the_refusal_stays_on_the_record(self) -> None:
        program = ELF + bytes(range(256)) * 40
        result = ArchiveReader.extract(
            Archives.tar({"package/bin/tool": program}), path="p.tgz", limits=LIMITS
        )
        refused = [r for r in result.rejected if r.name == "package/bin/tool"]
        assert len(refused) == 1
        assert refused[0].reason == Rejection.SIZE
        assert "a compiled program" in refused[0].detail

    def test_a_zip_member_is_read_the_same_way(self) -> None:
        program = ELF + bytes(range(256)) * 40
        result = ArchiveReader.extract(
            Archives.zip({"bin/tool.exe": program}), path="p.zip", limits=LIMITS
        )
        assert any(m.name == "bin/tool.exe" for m in result.members)

    def test_an_oversized_file_that_is_no_program_is_still_refused_unread(self) -> None:
        data = b"x" * 10_000
        result = ArchiveReader.extract(
            Archives.tar({"package/data.bin": data}), path="p.tgz", limits=LIMITS
        )
        assert not any(m.name == "package/data.bin" for m in result.members)
        assert any(r.name == "package/data.bin" for r in result.rejected)

    def test_what_is_kept_is_charged_to_the_archive_total(self) -> None:
        # The tar stream's own budget refuses the archive past `max_uncompressed_bytes` as it is
        # read; the kept head counts toward that total like any member.
        program = ELF + bytes(range(256)) * 40
        result = ArchiveReader.extract(
            Archives.tar({"package/bin/tool": program}), path="p.tgz", limits=LIMITS
        )
        assert result.total_uncompressed >= ArchiveReader.member_limit(LIMITS)
