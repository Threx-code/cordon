"""A run of identical 4 KB blocks is read whole and metered at its own price (reviews/pypi-98/26).

Padding is how a payload is put beyond a scanner's reach: filler is cheap to compress, and the byte
budget runs out inside it. The content is never changed. Only the cost is: the first two blocks of a
run count against the expansion cap and the total budget as ordinary bytes, each further identical block
against separate ceilings (`max_elided_member_bytes`, `max_elided_bytes`) that bound a zero bomb."""

from __future__ import annotations

import gzip
import io
import os
import tarfile

import pytest

from cordon_scanner.foundation.limits import Limits
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection
from cordon_scanner.sources.budget import BlockRuns

BLOCK = BlockRuns.BLOCK


class TestTheMeter:
    def test_a_run_charges_two_blocks_and_elides_the_rest(self) -> None:
        meter = BlockRuns()
        meter.feed(b"\0" * (BLOCK * 10))
        assert meter.elided == BLOCK * 8
        assert meter.charged == BLOCK * 2

    def test_blocks_that_differ_are_all_charged(self) -> None:
        meter = BlockRuns()
        meter.feed(b"".join(bytes([i % 251 + 1]) * BLOCK for i in range(10)))
        assert meter.elided == 0

    def test_one_byte_changing_in_each_block_is_not_a_run(self) -> None:
        meter = BlockRuns()
        meter.feed(b"".join(bytes([i % 251]) + b"\0" * (BLOCK - 1) for i in range(40)))
        assert meter.elided == 0

    def test_the_answer_does_not_depend_on_how_the_stream_is_cut(self) -> None:
        data = b"\1" * 1000 + b"\0" * (BLOCK * 30 + 17) + b"x" * 5000
        whole = BlockRuns()
        whole.feed(data)
        cut = BlockRuns()
        for start in range(0, len(data), 777):
            cut.feed(data[start : start + 777])
        assert (cut.elided, cut.charged) == (whole.elided, whole.charged)

    def test_a_run_that_stops_and_starts_again_is_two_runs(self) -> None:
        meter = BlockRuns()
        meter.feed(b"\0" * (BLOCK * 6) + b"\1" * BLOCK + b"\0" * (BLOCK * 6))
        assert meter.elided == BLOCK * 8


class Kit:
    LIMITS = Limits(max_member_bytes=64 * 1024, max_archive_ratio=10)

    @staticmethod
    def tar(members: list[tuple[str, bytes]]) -> bytes:
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz", compresslevel=9) as archive:
            for name, body in members:
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return out.getvalue()

    @staticmethod
    def read(data: bytes, limits: Limits | None = None):
        return ArchiveReader.extract(data, path="pkg.tar.gz", limits=limits or Kit.LIMITS)

    @staticmethod
    def padded(result) -> bool:
        return any(r.reason == Rejection.PADDED for r in result.rejected)


class TestFillerIsReadNotRefused:
    FILLER = 8 * 1024 * 1024

    def test_a_member_after_a_long_run_is_reached(self) -> None:
        payload = b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        result = Kit.read(Kit.tar([("pkg/pad.bin", b"\0" * self.FILLER), ("pkg/run.py", payload)]))
        assert not Kit.padded(result), result.rejected
        assert any(m.name.endswith("run.py") and m.data == payload for m in result.members)

    def test_the_filler_member_is_kept_whole(self) -> None:
        result = Kit.read(Kit.tar([("pkg/pad.bin", b"\0" * self.FILLER)]))
        assert [len(m.data) for m in result.members] == [self.FILLER]

    def test_a_repeated_nonzero_block_is_a_run_too(self) -> None:
        block = bytes(range(256)) * 16
        result = Kit.read(Kit.tar([("pkg/pad.bin", block * (self.FILLER // len(block)))]))
        assert not Kit.padded(result), result.rejected

    def test_a_second_payload_after_the_filler_inside_one_member_is_whole(self) -> None:
        body = b"\0" * self.FILLER + b"MARK-ONE" + b"\0" * self.FILLER + b"MARK-TWO"
        result = Kit.read(Kit.tar([("pkg/x.bin", body)]))
        kept = result.members[0].data
        whole = kept.read_whole() if hasattr(kept, "read_whole") else kept
        assert whole.endswith(b"MARK-TWO") and b"MARK-ONE" in whole and len(whole) == len(body)


class TestTheCeilingsStillBind:
    def test_a_zero_bomb_ends_at_the_elided_ceiling_as_padding(self) -> None:
        limits = Limits(
            max_member_bytes=64 * 1024,
            max_archive_ratio=10,
            max_elided_member_bytes=2 * 1024 * 1024,
            max_elided_bytes=2 * 1024 * 1024,
        )
        result = Kit.read(Kit.tar([("pkg/pad.bin", b"\0" * (32 * 1024 * 1024))]), limits)
        assert Kit.padded(result)

    def test_the_archive_ceiling_binds_across_members(self) -> None:
        limits = Limits(
            max_member_bytes=64 * 1024,
            max_archive_ratio=10,
            max_elided_member_bytes=3 * 1024 * 1024,
            max_elided_bytes=4 * 1024 * 1024,
        )
        members = [(f"pkg/pad{i}.bin", b"\0" * (2 * 1024 * 1024)) for i in range(4)]
        assert Kit.padded(Kit.read(Kit.tar(members), limits))

    def test_filler_with_one_byte_changing_per_block_keeps_padding(self) -> None:
        blocks = [bytes([i % 251]) + b"\0" * (BLOCK - 1) for i in range(8 * 1024 * 1024 // BLOCK)]
        assert Kit.padded(Kit.read(Kit.tar([("pkg/pad.bin", b"".join(blocks))])))

    def test_elision_off_is_the_old_behaviour(self) -> None:
        limits = Limits(
            max_member_bytes=64 * 1024,
            max_archive_ratio=10,
            max_elided_member_bytes=0,
            max_elided_bytes=0,
        )
        assert Kit.padded(Kit.read(Kit.tar([("pkg/pad.bin", b"\0" * (8 * 1024 * 1024))]), limits))

    def test_a_config_cannot_raise_a_ceiling_past_the_hard_maximum(self) -> None:
        with pytest.raises(Exception, match="max_elided"):
            Limits().merged(max_elided_bytes=9 * 1024**3)

    def test_ordinary_archives_charge_nothing_as_elided(self) -> None:
        body = os.urandom(100_000)
        result = Kit.read(Kit.tar([("pkg/a.bin", body), ("pkg/b.bin", body[::-1])]))
        assert not Kit.padded(result)
        assert result.elided == 0


class TestAZipMember:
    def test_a_member_after_a_long_run_is_reached(self) -> None:
        import zipfile

        payload = b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("pkg/pad.bin", b"\0" * (8 * 1024 * 1024))
            archive.writestr("pkg/run.py", payload)
        result = ArchiveReader.extract(out.getvalue(), path="pkg.zip", limits=Kit.LIMITS)
        assert not Kit.padded(result), result.rejected
        assert any(m.name.endswith("run.py") and m.data == payload for m in result.members)


class TestALoneStream:
    def test_a_gzip_stream_is_metered_like_a_tar(self) -> None:
        data = gzip.compress(b"\0" * (8 * 1024 * 1024), compresslevel=9)
        result = ArchiveReader.extract(data, path="blob.bin.gz", limits=Kit.LIMITS)
        assert not Kit.padded(result), result.rejected
