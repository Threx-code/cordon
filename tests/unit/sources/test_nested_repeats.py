"""A nested archive past the depth limit that the walk already opened higher up was examined."""

from __future__ import annotations

import io
import zipfile

from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader, Rejection


class Zips:
    @staticmethod
    def of(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    @staticmethod
    def unexamined(data: bytes, depth: int = 1) -> list[str]:
        rejected: list[tuple[str, str, str]] = []
        limits = DEFAULT_LIMITS.merged(max_archive_depth=depth)
        list(ArchiveReader.walk_archive(data, path="pkg.zip", limits=limits, rejected=rejected))
        return [path for path, reason, _ in rejected if reason == Rejection.DEPTH]


class TestRepeatedReleases:
    def test_an_earlier_release_shipped_beside_the_one_that_contains_it(self):
        # `npm pack` run twice in the package directory: v2 carries v1, and v1 sits beside it.
        v1 = Zips.of({"index.js": b"module.exports = 1"})
        v2 = Zips.of({"index.js": b"module.exports = 2", "pkg-1.zip": v1})
        outer = Zips.of({"pkg-2.zip": v2, "pkg-1.zip": v1})
        assert Zips.unexamined(outer, depth=1) == []

    def test_the_order_the_copies_are_met_in_does_not_matter(self):
        v1 = Zips.of({"index.js": b"module.exports = 1"})
        v2 = Zips.of({"index.js": b"module.exports = 2", "pkg-1.zip": v1})
        outer = Zips.of({"pkg-1.zip": v1, "pkg-2.zip": v2})
        assert Zips.unexamined(outer, depth=1) == []

    def test_an_archive_nowhere_opened_is_still_reported(self):
        hidden = Zips.of({"payload.js": b"run()"})
        middle = Zips.of({"hidden.zip": hidden})
        outer = Zips.of({"middle.zip": middle})
        assert Zips.unexamined(outer, depth=1) == ["pkg.zip!middle.zip!hidden.zip"]

    def test_a_copy_with_different_bytes_is_not_the_same_archive(self):
        v1 = Zips.of({"index.js": b"module.exports = 1"})
        altered = Zips.of({"index.js": b"module.exports = 1", "extra.js": b"run()"})
        v2 = Zips.of({"index.js": b"module.exports = 2", "pkg-1.zip": altered})
        outer = Zips.of({"pkg-2.zip": v2, "pkg-1.zip": v1})
        assert Zips.unexamined(outer, depth=1) == ["pkg.zip!pkg-2.zip!pkg-1.zip"]
