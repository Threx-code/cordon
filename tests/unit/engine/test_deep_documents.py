"""No document nested to any depth can end a scan, and a JSON one is read to the end.

A `package.json` nested twenty thousand levels deep once ended the whole scan as "internal error",
exit 2, with no report (review 98, 27-PERFORMANCE, 7): the verdict read it outside any detector's
isolation, and Python's decoder recursed past its limit. A CI gate saw a scanner failure, not a
hostile package. JSON of scanned content is now read through `ScannedJson`, which reads any depth, so
every reader gets the document; one that then walks it by recursion (`str()` of a nested value) is a
defect this test finds. Every format is asked here, so a new reader cannot bring the failure back.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.foundation.errors import ExitCode


class Deep:
    """One deeply nested document of each kind, by the path it is written at."""

    #: Past the interpreter's recursion limit (1,000) for the formats read without `ScannedJson`.
    DEPTH = 3_000
    #: What a package.json was nested to when it ended the scan, exit 2, before the fix; and the
    #: depth of JSONTestSuite's `n_structure_100000_opening_arrays.json`, found in real packages.
    CRASHED = 20_000
    DEEPEST = 100_000

    @staticmethod
    def cases(d: int = DEPTH) -> dict[str, tuple[str, str]]:
        arrays = "[" * d + "]" * d
        return {
            **Deep.json_cases(Deep.CRASHED),
            "workflow YAML": (".github/workflows/ci.yml", f"on: push\njobs:\n  a: {arrays}\n"),
            "pnpm lockfile": (
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\nx: " + "{a: " * d + "1" + "}" * d + "\n",
            ),
            "pyproject TOML": (
                "pyproject.toml",
                f"[project]\nname='x'\nversion='1'\nx = {arrays}\n",
            ),
            "Cargo TOML": ("Cargo.toml", f"[package]\nname='x'\nversion='1.0.0'\nx = {arrays}\n"),
            "Maven XML": ("pom.xml", "<project>" + "<a>" * d + "</a>" * d + "</project>"),
            "csproj XML": ("x.csproj", "<Project>" + "<a>" * d + "</a>" * d + "</Project>"),
            "JavaScript": ("index.js", "x=" + "(" * d + "1" + ")" * d + ";\n"),
            "Python": ("setup.py", "x = " + "[" * d + "]" * d + "\n"),
        }

    @staticmethod
    def json_cases(d: int) -> dict[str, tuple[str, str]]:
        objects, arrays = '{"a":' * d + "1" + "}" * d, "[" * d + "]" * d
        return {
            "package.json": (
                "package.json",
                f'{{"name":"x","version":"1.0.0","config":{objects}}}',
            ),
            "package.json arrays": (
                "package.json",
                f'{{"name":"x","version":"1.0.0","files":{arrays}}}',
            ),
            "composer.json": ("composer.json", f'{{"name":"a/b","require":{objects}}}'),
            "composer.lock": (
                "composer.lock",
                f'{{"packages":[{{"name":"a/b","version":"1.0.0","x":{objects}}}]}}',
            ),
            "package-lock": (
                "package-lock.json",
                f'{{"lockfileVersion":3,"packages":{{"":{{"name":"x"}},"x":{objects}}}}}',
            ),
            "MCP config": (".mcp.json", f'{{"mcpServers":{objects}}}'),
            "agent settings": (".claude/settings.json", f'{{"hooks":{objects}}}'),
            "SBOM": ("bom.json", f'{{"bomFormat":"CycloneDX","components":{arrays}}}'),
            "tsconfig": ("tsconfig.json", f'{{"compilerOptions":{objects}}}'),
            "data file": ("test/data/deep.json", arrays),
        }

    @staticmethod
    def scan(tmp_path: Path, relative: str, text: str) -> tuple[int, dict[str, Any]]:
        from cordon_scanner.cli.main import CommandLine

        root = tmp_path / "project"
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
        if relative != "package.json":
            (root / "package.json").write_text('{"name":"p","version":"1.0.0"}', encoding="utf-8")
        report = tmp_path / "report.json"
        args = ["scan", str(root), "--offline", "--no-cache", "--no-color", "--quiet"]
        args += ["--format", "json", "--output", str(report), "--fail-on-incomplete"]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = CommandLine.run(args)
        assert report.is_file(), f"{relative}: no report (exit {code})"
        return code, json.loads(report.read_text(encoding="utf-8"))


class TestDeepDocuments:
    @pytest.mark.parametrize("kind", list(Deep.cases()))
    def test_it_gives_a_report_and_never_a_scanner_error(self, kind: str, tmp_path: Path) -> None:
        relative, text = Deep.cases()[kind]
        code, _report = Deep.scan(tmp_path, relative, text)
        assert code != int(ExitCode.SCANNER_ERROR), kind

    @pytest.mark.parametrize("depth", [Deep.CRASHED, Deep.DEEPEST])
    @pytest.mark.parametrize("kind", list(Deep.json_cases(1)))
    def test_json_nested_to_any_depth_is_read_and_the_scan_complete(
        self, kind: str, depth: int, tmp_path: Path
    ) -> None:
        relative, text = Deep.json_cases(depth)[kind]
        code, report = Deep.scan(tmp_path, relative, text)
        operational = [
            (f["rule_id"], f["message"][:120])
            for f in report["findings"]
            if f["rule_id"].startswith("OPERATIONAL.")
            and f["rule_id"] != "OPERATIONAL.ADVISORY.DATABASE_SCOPE"
        ]
        assert report["complete"] is True, (kind, operational)
        assert code != int(ExitCode.INCOMPLETE), (kind, operational)
        assert not operational, (kind, operational)
