"""The whole of an oversized file, read a window at a time (review 98: padding hid payloads).

Small limits stand in for the real ones (10 MB windows, 512 MB reach) so the tests stay fast. The
token is inert: a string of the shape a secret detector recognises, in a file nothing runs.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.windows import (
    BytesWindows,
    DiskWindows,
    Windows,
    WindowSourceChanged,
)

# Assembled at run time, so this file does not itself carry the shape it tests for.
TOKEN = 'const t = "' + "ghp" + "_" + "9eU3aG0cF5dJ1sH6pY4nW7kR2bT9vX3mL8qZ"[::-1] + '";\n'
FILLER = "function add(a, b) { return a + b; }\n"


class WindowKit:
    @staticmethod
    def config(**limits: int) -> Config:
        base = Config.default()
        return base.with_overrides(limits=base.limits.merged(**limits), use_cache=False)

    @staticmethod
    def findings(target: Path, config: Config) -> list:
        return list(Scanner(config).scan(target).findings)


class TestTheWindows:
    @pytest.mark.parametrize("seed", range(20))
    def test_cover_every_byte_past_the_prefix_and_count_lines_exactly(self, seed: int) -> None:
        rng = random.Random(seed)  # noqa: S311 - test data, not secrets
        lines = [b"x" * rng.randint(0, 300) + b"\n" for _ in range(400)]
        if seed % 3 == 0:
            lines.append(b"y" * 5000)  # a last line longer than a window, without a newline
        data = b"".join(lines)
        prefix = data[: rng.randint(1, 2000)]
        windows = list(
            Windows.iterate(BytesWindows(data), prefix, size=700, overlap=128, limit=len(data))
        )
        covered = set()
        for window in windows:
            assert data[window.begin : window.begin + len(window.data)] == window.data
            assert window.lines_before == data[: window.begin].count(b"\n")
            covered.update(range(window.begin, window.begin + len(window.data)))
        assert set(range(len(prefix), len(data))) <= covered

    def test_a_construct_across_a_cut_is_whole_in_one_window(self) -> None:
        data = b"a" * 1000 + b"NEEDLE-ACROSS-THE-CUT" + b"b" * 1000
        windows = Windows.iterate(BytesWindows(data), data[:10], size=1010, overlap=64, limit=10**9)
        assert any(b"NEEDLE-ACROSS-THE-CUT" in w.data for w in windows)

    def test_stop_at_the_reach(self) -> None:
        data = b"line\n" * 1000
        windows = list(
            Windows.iterate(BytesWindows(data), data[:100], size=200, overlap=0, limit=1000)
        )
        assert max(w.begin + len(w.data) for w in windows) <= 1000

    def test_a_file_replaced_after_it_was_read_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "bundle.js"
        target.write_bytes(b"x\n" * 1000)
        source = DiskWindows(str(target), DiskWindows.identity_of(target.stat()))
        target.write_bytes(b"y\n" * 2000)
        with pytest.raises(WindowSourceChanged), source.reader():
            pass


class TestAPaddedFile:
    def test_a_token_past_the_prefix_is_found_on_its_own_line(self, tmp_path: Path) -> None:
        body = FILLER * 6000 + TOKEN
        (tmp_path / "bundle.js").write_text(body, encoding="utf-8")
        found = WindowKit.findings(tmp_path, WindowKit.config(max_file_bytes=65_536))
        secrets = [f for f in found if f.rule_id.startswith("SECRET.")]
        assert secrets, "the token past the first window was not read"
        assert {f.location.line for f in secrets} == {body.count("\n")}
        note = next(f for f in found if f.rule_id == "OPERATIONAL.FILE.TRUNCATED")
        assert note.message.startswith("Read to its end in windows.")

    def test_in_an_archive_member_too(self, tmp_path: Path) -> None:
        import io
        import tarfile

        body = (FILLER * 6000 + TOKEN).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in (
                ("package/package.json", b'{"name": "p", "version": "1.0.0"}'),
                ("package/dist/bundle.js", body),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        found = WindowKit.findings(target, WindowKit.config(max_file_bytes=65_536))
        assert any(f.rule_id.startswith("SECRET.") for f in found)

    def test_with_the_windows_off_only_the_prefix_is_read(self, tmp_path: Path) -> None:
        (tmp_path / "bundle.js").write_text(FILLER * 6000 + TOKEN, encoding="utf-8")
        found = WindowKit.findings(
            tmp_path, WindowKit.config(max_file_bytes=65_536, max_stream_bytes=0)
        )
        assert not any(f.rule_id.startswith("SECRET.") for f in found)

    def test_past_the_reach_the_note_says_how_far_it_read(self, tmp_path: Path) -> None:
        (tmp_path / "bundle.js").write_text(FILLER * 20000 + TOKEN, encoding="utf-8")
        found = WindowKit.findings(
            tmp_path, WindowKit.config(max_file_bytes=65_536, max_stream_bytes=300_000)
        )
        note = next(f for f in found if f.rule_id == "OPERATIONAL.FILE.TRUNCATED")
        assert "to limits.max_stream_bytes" in note.message
        assert not note.message.startswith("Read to its end")
