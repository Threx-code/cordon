"""A scan that is incomplete says why.

Found scanning real repositories. v2rayN carries a 10.5 MB font: read in part, it made the
scan incomplete -- which fails the GitHub Action's default gate -- and no finding said so, because
the truncation notice came from a detector that returns early for a binary file.
"""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.limits import DEFAULT_LIMITS


class TestATruncatedFileIsNamed:
    CONFIG = Config.default().with_overrides(
        use_cache=False, limits=DEFAULT_LIMITS.merged(max_file_bytes=100_000)
    )

    def test_a_binary_file_read_in_part(self, tmp_path) -> None:
        (tmp_path / "font.ttf").write_bytes(b"\x00\x01\x00\x00" + bytes(range(256)) * 1_000)
        result = Scanner(self.CONFIG).scan(tmp_path)
        assert result.complete is False
        truncated = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TRUNCATED"]
        assert [f.location.path for f in truncated] == ["font.ttf"]

    def test_a_source_file_read_in_part_is_named_once(self, tmp_path) -> None:
        (tmp_path / "data.py").write_text("PAD = b'" + "A" * 300_000 + "'\n", encoding="utf-8")
        result = Scanner(self.CONFIG).scan(tmp_path)
        assert result.complete is False
        rules = [f.rule_id for f in result.findings]
        assert rules.count("OPERATIONAL.FILE.TRUNCATED") == 1

    def test_an_archive_read_in_part_is_reported_once(self, tmp_path) -> None:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("big.bin", bytes(range(256)) * 1_000)
        (tmp_path / "app.war").write_bytes(buffer.getvalue())
        result = Scanner(self.CONFIG).scan(tmp_path)
        about = [f.rule_id for f in result.findings if f.location.path == "app.war"]
        assert about.count("OPERATIONAL.ARCHIVE.REJECTED") == 1
        assert "OPERATIONAL.FILE.TRUNCATED" not in about
