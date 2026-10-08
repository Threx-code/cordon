"""Archives found inside a directory scan are opened and their members scanned.

A vendored `.whl`, `.jar`, `.tgz` or `.nupkg` is part of what a repository ships. Before this, a
directory scan reported such a file as "not examined" and passed it, while scanning the same
archive directly found its payload. The fixtures here wrap an existing corpus sample in an
archive; nothing new is written.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from support import MALICIOUS, requires_malicious_corpus

DROPPER = MALICIOUS / "dropper-shell-python" / "setup.py"


class ArchivesInDirectoriesHelpers:
    """Helpers for test_archives_in_directories.py."""

    @staticmethod
    def _zip(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    @staticmethod
    def _tgz(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def _scan(root: Path, **overrides: object):
        return Scanner(Config.default().with_overrides(use_cache=False, **overrides)).scan(root)

    @staticmethod
    def _rules_at(result, path: str) -> set[str]:
        return {f.rule_id for f in result.findings if f.location.path == path}


@requires_malicious_corpus
class TestVendoredArchives:
    def test_a_payload_in_a_vendored_zip_is_found(self, tmp_path: Path) -> None:
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"setup.py": DROPPER.read_bytes()})
        )

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        assert "MALWARE.DROPPER.001" in ArchivesInDirectoriesHelpers._rules_at(
            result, "vendor/lib.zip!setup.py"
        )
        assert result.stats.archives_expanded == 1
        assert result.stats.archive_members == 1

    def test_the_same_finding_as_scanning_the_archive_itself(self, tmp_path: Path) -> None:
        archive = ArchivesInDirectoriesHelpers._zip({"pkg/setup.py": DROPPER.read_bytes()})
        (tmp_path / "tree").mkdir()
        (tmp_path / "tree" / "lib.whl").write_bytes(archive)
        (tmp_path / "lib.whl").write_bytes(archive)

        in_tree = ArchivesInDirectoriesHelpers._rules_at(
            ArchivesInDirectoriesHelpers._scan(tmp_path / "tree"), "lib.whl!pkg/setup.py"
        )
        direct = ArchivesInDirectoriesHelpers._rules_at(
            ArchivesInDirectoriesHelpers._scan(tmp_path / "lib.whl"), "lib.whl!pkg/setup.py"
        )

        # A directory scan folds a SUSPECT finding into the MALWARE one for the same
        # behaviour; every confirmed finding of the direct scan is present.
        confirmed = {rule for rule in direct if rule.split(".")[0] in ("MALWARE", "SECRET")}
        assert "MALWARE.DROPPER.001" in in_tree
        assert confirmed <= in_tree

    def test_a_nested_archive_is_opened_through(self, tmp_path: Path) -> None:
        inner = ArchivesInDirectoriesHelpers._tgz({"package/setup.py": DROPPER.read_bytes()})
        (tmp_path / "bundle.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"deps/inner.tgz": inner})
        )

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        assert "MALWARE.DROPPER.001" in ArchivesInDirectoriesHelpers._rules_at(
            result, "bundle.zip!deps/inner.tgz!package/setup.py"
        )

    def test_the_same_archive_twice_is_opened_once(self, tmp_path: Path) -> None:
        archive = ArchivesInDirectoriesHelpers._zip({"setup.py": DROPPER.read_bytes()})
        for directory in ("a", "b", "c"):
            (tmp_path / directory).mkdir()
            (tmp_path / directory / "lib.zip").write_bytes(archive)

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        # Opened once, and reported once: identical copies of one issue collapse to
        # one finding, as they do for any repeated file.
        assert result.stats.archives_expanded == 1
        assert any(
            "MALWARE.DROPPER.001"
            in ArchivesInDirectoriesHelpers._rules_at(result, f"{directory}/lib.zip!setup.py")
            for directory in ("a", "b", "c")
        )

    def test_parallel_and_serial_scans_agree(self, tmp_path: Path) -> None:
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"setup.py": DROPPER.read_bytes()})
        )
        for index in range(40):
            (tmp_path / f"m{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

        serial = ArchivesInDirectoriesHelpers._scan(
            tmp_path, limits=Config.default().limits.__class__(max_workers=1)
        )
        parallel = ArchivesInDirectoriesHelpers._scan(
            tmp_path, limits=Config.default().limits.__class__(max_workers=4)
        )

        key = lambda r: sorted((f.rule_id, f.location.path) for f in r.findings)  # noqa: E731
        assert key(serial) == key(parallel)


class TestExpansionIsNeverSilent:
    def test_no_expand_marks_the_scan_incomplete(self, tmp_path: Path) -> None:
        (tmp_path / "lib.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"README": b"hello\n"})
        )

        result = ArchivesInDirectoriesHelpers._scan(tmp_path, expand_archives=False)

        assert not result.complete
        assert any(f.rule_id == "OPERATIONAL.ARCHIVE.NOT_EXPANDED" for f in result.findings)

    def test_an_expanded_archive_is_not_reported_as_unexamined(self, tmp_path: Path) -> None:
        (tmp_path / "lib.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"README": b"hello\n"})
        )

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        binary = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.BINARY"]
        assert not any("lib.zip" in f.message for f in binary)
        assert result.complete

    def test_a_corrupt_archive_is_reported_and_incomplete(self, tmp_path: Path) -> None:
        (tmp_path / "broken.zip").write_bytes(b"PK\x03\x04 this is not a zip")

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        assert not result.complete
        assert any(
            f.rule_id == "OPERATIONAL.ARCHIVE.REJECTED" and f.location.path == "broken.zip"
            for f in result.findings
        )

    def test_a_vendored_lockfile_does_not_join_the_project_graph(self, tmp_path: Path) -> None:
        lock = b'{"name":"x","lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.0.0"}}}'
        (tmp_path / "vendor.zip").write_bytes(
            ArchivesInDirectoriesHelpers._zip({"package-lock.json": lock})
        )

        result = ArchivesInDirectoriesHelpers._scan(tmp_path)

        assert not any(d.name == "left-pad" for d in result.dependencies)

    def test_the_setting_round_trips_and_changes_the_fingerprint(self) -> None:
        on = Config.default()
        off = on.with_overrides(expand_archives=False)

        assert on.to_dict()["scan"]["expand_archives"] is True
        assert on.fingerprint() != off.fingerprint()
