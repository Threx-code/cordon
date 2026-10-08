"""`scripts/portability.py`: each check catches the code that actually broke another platform.

Every snippet below is the shape of a line that passed locally and failed on a CI runner on
8 October 2026. A check that stops catching its own incident is worse than none, since the
pre-push gate would then pass the very thing it exists to stop.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("portability", ROOT / "scripts" / "portability.py")
assert _spec is not None and _spec.loader is not None
portability = importlib.util.module_from_spec(_spec)
# Registered first: a dataclass looks its module up in `sys.modules` while it is being built.
sys.modules["portability"] = portability
_spec.loader.exec_module(portability)
Portability = portability.Portability


class Checks:
    @staticmethod
    def found(text: str, path: str = "tests/unit/test_x.py") -> list[str]:
        return [f.check for f in Portability.check(text, path)]


class TestEachIncidentIsCaught:
    @pytest.mark.parametrize(
        "line",
        [
            '(root / "requirements.txt").write_text(head + "\\n")',
            "text = path.read_text()",
            "with open(path) as handle: pass",
            'with open(path, "w") as handle: pass',
        ],
    )
    def test_text_in_the_platform_code_page(self, line) -> None:
        assert Checks.found(line) == ["default-encoding"]

    @pytest.mark.parametrize(
        "line",
        [
            'path.write_text(text, encoding="utf-8")',
            'path.read_text(encoding="utf-8")',
            'path.read_text("utf-8")',
            'with open(path, "rb") as handle: pass',
            'with open(path, encoding="utf-8") as handle: pass',
            # A URL opener, an archive member: not files, and they take no encoding.
            "with opener.open(request, timeout=5) as response: pass",
            "with archive.open(info) as handle: pass",
        ],
    )
    def test_what_is_already_portable(self, line) -> None:
        assert Checks.found(line) == []

    def test_a_native_relative_path_used_as_text(self) -> None:
        assert Checks.found("if str(p.relative_to(case.path)) in contributing: pass") == [
            "native-path-text"
        ]
        assert Checks.found("p.relative_to(case.path).as_posix()") == []
        assert Checks.found('str(p.relative_to(root)).replace(os.sep, "/")') == []

    def test_a_posix_only_module_at_module_level(self) -> None:
        assert Checks.found("import resource\n") == ["posix-only-import"]
        assert Checks.found('def test():\n    resource = __import__("resource")\n') == []
        assert Checks.found("import resource\n", "src/cordon_scanner/x.py") == []

    def test_the_tests_package_on_the_import_path(self) -> None:
        assert Checks.found("from tests.imagekit import ImageKit\n") == ["tests-package-import"]
        assert Checks.found("from imagekit import ImageKit\n") == []

    def test_a_document_break_that_misses_crlf(self) -> None:
        before = 'BREAK = re.compile(r"(?m)^---[ \\t]*$")'
        after = 'BREAK = re.compile(r"(?m)^---[ \\t]*\\r?$")'
        with_comment = 'BREAK = re.compile(r"(?m)^---[ \\t]*(?:#[^\\r\\n]*)?\\r?$")'
        assert Checks.found(before, "src/x.py") == ["yaml-break-crlf"]
        assert Checks.found(after, "src/x.py") == []
        assert Checks.found(with_comment, "src/x.py") == []

    def test_an_invisible_character_in_shipped_source(self) -> None:
        # Built at run time: this file must not hold the character it tests for.
        line = f'PATTERN = "[{chr(0x202A)}-{chr(0x202E)}]"\n'
        assert Checks.found(line, "src/cordon_scanner/x.py") == ["invisible-characters"]
        assert Checks.found(line, "tests/unit/test_x.py") == []
        assert Checks.found('PATTERN = "[\\u202a-\\u202e]"\n', "src/x.py") == []


class TestTheRepository:
    def test_has_no_finding(self) -> None:
        findings = Portability.run()
        assert not findings, "\n".join(f.render() for f in findings)
