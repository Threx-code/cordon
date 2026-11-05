"""A nested archive whose stream is damaged is refused as damaged, once: not as damage and then
again as "a limit" (stardrop 0.0.0-dev shipped a nested tgz cut mid-stream and got both, review 98).
A nested archive that stops at a real limit still says so.
"""

from __future__ import annotations

import io
import tarfile

from cordon_scanner.foundation.config.settings import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection


class NestedKit:
    @staticmethod
    def tgz(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def refusals(outer: bytes, nested: str) -> list[tuple[str, str]]:
        rejected: list[tuple[str, str, str]] = []
        for _ in ArchiveReader.walk_archive(outer, path="outer.tgz", rejected=rejected):
            pass
        return [(r[0], r[1]) for r in rejected if nested in r[0]]


class TestDamageIsReportedAsDamageOnce:
    def test_a_cut_nested_stream_is_refused_as_unreadable_only(self) -> None:
        # The first member is whole and read; the gzip stream ends inside the second, before
        # its end-of-stream marker, as stardrop's did.
        inner = NestedKit.tgz({"package/x": b"1", "package/bin/tool": b"\x7fELF" + b"\0" * 200000})
        cut = inner[: len(inner) // 2]
        outer = NestedKit.tgz({"package/package.json": b"{}", "package/inner.tgz": cut})
        refusals = NestedKit.refusals(outer, "inner.tgz")
        reasons = [reason for _path, reason in refusals]
        assert Rejection.UNREADABLE in reasons, refusals
        assert Rejection.ENTRIES not in reasons, refusals

    def test_a_nested_archive_that_will_not_open_is_refused_and_still_scanned_as_bytes(
        self,
    ) -> None:
        inner = NestedKit.tgz({"package/bin/tool": b"\x7fELF" + b"\0" * 20000, "package/x": b"1"})
        cut = inner[: len(inner) // 2]  # cut inside the first member: nothing of it can be read
        outer = NestedKit.tgz({"package/inner.tgz": cut})
        rejected: list[tuple[str, str, str]] = []
        yielded = dict(ArchiveReader.walk_archive(outer, path="outer.tgz", rejected=rejected))
        assert yielded.get("outer.tgz!package/inner.tgz") == cut  # the bytes are still scanned
        reasons = [(r[0], r[1]) for r in rejected if "inner.tgz" in r[0]]
        assert reasons == [("outer.tgz!package/inner.tgz", Rejection.UNREADABLE)], rejected

    def test_an_archive_level_refusal_carries_the_archive_path_once(self) -> None:
        inner = NestedKit.tgz({"package/x": b"1", "package/bin/tool": b"\0" * 200000})
        outer = NestedKit.tgz({"package/inner.tgz": inner[: len(inner) // 2]})
        rejected: list[tuple[str, str, str]] = []
        for _ in ArchiveReader.walk_archive(outer, path="outer.tgz", rejected=rejected):
            pass
        damaged = [r[0] for r in rejected if "damaged after" in r[2]]
        assert damaged == ["outer.tgz!package/inner.tgz"], rejected

    def test_a_nested_stream_that_stops_at_a_limit_still_says_so(self) -> None:
        inner = NestedKit.tgz({f"package/f{n}": b"x" for n in range(40)})
        outer = NestedKit.tgz({"package/inner.tgz": inner})
        limits = DEFAULT_LIMITS.merged(max_archive_entries=10)
        rejected: list[tuple[str, str, str]] = []
        for _ in ArchiveReader.walk_archive(
            outer, path="outer.tgz", rejected=rejected, limits=limits
        ):
            pass
        reasons = {r[1] for r in rejected if "inner.tgz" in r[0]}
        assert Rejection.ENTRIES in reasons, rejected
        assert Rejection.UNREADABLE not in reasons, rejected


__all__ = ["NestedKit"]
