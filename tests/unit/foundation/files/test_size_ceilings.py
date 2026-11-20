"""How large a file of each kind may be before its size is the finding (`SizeCeilings`, reviews/mcp-98/52-DETECTOR-SIZE-CAPS.md).

One test per kind on both sides of its ceiling: a file at the ceiling is read to its end in windows (the scan stays complete), a byte over is a size
anomaly (the windows stop at the ceiling and the scan is incomplete, never a pass). Sizes are claimed, not built: the content holds a few bytes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.files.size_ceilings import MIB, SizeCeilings
from cordon_scanner.foundation.limits import DEFAULT_LIMITS, HARD_MAX_STREAM_BYTES

GIB = 1024 * MIB
WINDOWS = (
    SimpleNamespace()
)  # stands for "the rest is read in windows": only its presence matters here


class Claims:
    @staticmethod
    def claimed(path: str, size: int, raw: bytes = b"text\n") -> FileContent:
        return FileContent(path=path, raw=raw, size=size, truncated=True, window_source=WINDOWS)  # type: ignore[arg-type]


KINDS = [
    # (a name of the kind, bytes of its content, the ceiling)
    ("package/index.js", b"var a = 1;\n", 128 * MIB),
    ("package/index.ts", b"var a = 1;\n", 128 * MIB),
    ("package/app.py", b"a = 1\n", 128 * MIB),
    ("package/table.json", b'{"a": 1}\n', 128 * MIB),
    ("package/table.yaml", b"a: 1\n", 128 * MIB),
    ("package/README.md", b"# title\n", 128 * MIB),
    ("package/main.go", b"package main\n", 16 * MIB),
    ("package/install.sh", b"#!/bin/sh\n", 16 * MIB),
    ("package/bundle.tar", b"x", 1 * GIB),
    ("package/bundle.zip", b"x", 1 * GIB),
    ("package/wheel-1.0-py3-none-any.whl", b"x", 1 * GIB),
]


class TestTheCeilings:
    @pytest.mark.parametrize(("path", "raw", "ceiling"), KINDS)
    def test_each_kind_has_its_ceiling(self, path: str, raw: bytes, ceiling: int) -> None:
        assert SizeCeilings.of(path, binary=False) == ceiling

    @pytest.mark.parametrize(
        "path", ["lib/libtorch_cuda.so", "model/weights.safetensors", "bin/tool", "data/blob.dat"]
    )
    def test_a_binary_file_is_bounded_by_the_stream_limit_alone(self, path: str) -> None:
        assert SizeCeilings.of(path, binary=True) == HARD_MAX_STREAM_BYTES
        assert SizeCeilings.of(path, binary=True) >= DEFAULT_LIMITS.max_stream_bytes

    def test_an_archive_members_name_is_its_inner_name(self) -> None:
        assert SizeCeilings.of("outer.tgz!package/index.js", binary=False) == 128 * MIB
        assert SizeCeilings.of("outer.tgz!package/run.sh", binary=False) == 16 * MIB

    def test_the_name_decides_before_the_bytes_for_a_script_and_an_archive(self) -> None:
        assert SizeCeilings.of("x.sh", binary=True) == 16 * MIB
        assert SizeCeilings.of("x.tar", binary=True) == 1 * GIB

    def test_a_text_file_with_a_binary_name_is_still_text(self) -> None:
        assert SizeCeilings.of("payload.dat", binary=False) == 128 * MIB

    def test_the_text_ceiling_is_above_the_largest_legitimate_text_file_measured(self) -> None:
        assert SizeCeilings.TEXT >= 2 * 55_945_967
        assert SizeCeilings.GO_AND_SHELL >= 2 * 1_503_812


class TestBothSidesOfTheCeiling:
    @pytest.mark.parametrize(("path", "raw", "ceiling"), KINDS)
    def test_at_the_ceiling_the_file_is_read_to_its_end(
        self, path: str, raw: bytes, ceiling: int
    ) -> None:
        content = Claims.claimed(path, ceiling, raw)
        assert content.stream_limit == ceiling
        assert ArchiveMembers.read_to_end(content)

    @pytest.mark.parametrize(("path", "raw", "ceiling"), KINDS)
    def test_a_byte_over_it_is_not(self, path: str, raw: bytes, ceiling: int) -> None:
        content = Claims.claimed(path, ceiling + 1, raw)
        assert content.stream_limit == ceiling
        assert not ArchiveMembers.read_to_end(content)
        note = ArchiveMembers.truncated_note(path, content)
        assert note.rule_id == "OPERATIONAL.FILE.TRUNCATED"
        assert "Size anomaly" in note.message

    def test_a_binary_file_reads_as_far_as_the_stream_limit(self) -> None:
        limit = DEFAULT_LIMITS.max_stream_bytes
        binary = b"\x00\xff\x00\xfe" * 8
        assert ArchiveMembers.read_to_end(Claims.claimed("lib/libcudnn.so", limit, binary))
        assert not ArchiveMembers.read_to_end(Claims.claimed("lib/libcudnn.so", limit + 1, binary))
        # a library or a weights file of one to two gigabytes is read whole, as it was
        assert ArchiveMembers.read_to_end(Claims.claimed("model/weights.bin", 2 * GIB, binary))

    def test_a_file_that_fits_in_the_prefix_is_never_an_anomaly(self) -> None:
        small = FileContent(path="package/index.js", raw=b"var a = 1;\n", size=11)
        assert small.stream_limit == 128 * MIB

    def test_an_organisation_cannot_raise_a_text_ceiling_through_the_stream_limit(self) -> None:
        raised = DEFAULT_LIMITS.merged(max_stream_bytes=HARD_MAX_STREAM_BYTES)
        content = FileContent(
            path="package/index.js",
            raw=b"x",
            size=129 * MIB,
            truncated=True,
            window_source=WINDOWS,
            limits=raised,
        )  # type: ignore[arg-type]
        assert content.stream_limit == 128 * MIB

    def test_a_lowered_stream_limit_still_lowers_it(self) -> None:
        lowered = DEFAULT_LIMITS.merged(max_stream_bytes=0)
        content = FileContent(
            path="package/index.js", raw=b"x", size=50 * MIB, truncated=True, limits=lowered
        )
        assert content.stream_limit == 0


class TestAScan:
    """A real scan with the text ceiling lowered under the size of a file, so no file of 128 MiB is built."""

    @staticmethod
    def scan(tmp_path, ceiling: int, monkeypatch: pytest.MonkeyPatch):
        line = "// " + "x" * 77 + "\n"
        (tmp_path / "package.json").write_text(
            '{"name": "padded", "version": "1.0.0", "main": "index.js"}\n'
        )
        (tmp_path / "index.js").write_text(line * (12 * MIB // len(line)), encoding="utf-8")
        monkeypatch.setattr(SizeCeilings, "TEXT", ceiling)
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

    def test_a_text_file_over_its_ceiling_is_a_size_anomaly_and_the_scan_is_incomplete(
        self, tmp_path, monkeypatch
    ) -> None:
        result = self.scan(tmp_path, 11 * MIB, monkeypatch)
        notes = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TRUNCATED"]
        assert any("Size anomaly" in f.message for f in notes)
        assert not result.content_complete

    def test_the_same_file_under_its_ceiling_is_read_whole_and_complete(
        self, tmp_path, monkeypatch
    ) -> None:
        result = self.scan(tmp_path, 13 * MIB, monkeypatch)
        notes = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TRUNCATED"]
        assert notes
        assert not any("Size anomaly" in f.message for f in notes)
        assert result.content_complete
