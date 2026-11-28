"""`scan --vex`: a statement that cannot be read stops the scan; the count of what it ruled out is said on stderr (`cli/commands/scan/suppression.py`)."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.scan.suppression import ScanSuppression
from cordon_scanner.decide.vex import VexDocuments, VexError
from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.foundation.results import Repository, ScanResult


class _Base:
    @staticmethod
    def result() -> ScanResult:
        return ScanResult(findings=(), repository=Repository(root="."))

    @staticmethod
    def ruled(*approvers: str | None) -> tuple[Any, ...]:
        return tuple(
            SimpleNamespace(
                rule_id="VULNERABLE.DEPENDENCY.001",
                suppressed=None if who is None else SimpleNamespace(approved_by=who),
            )
            for who in approvers
        )


class TestVexOption(_Base):
    def test_without_the_option_the_result_is_returned_unchanged(self) -> None:
        result = self.result()
        assert ScanSuppression.apply_vex(argparse.Namespace(vex=None), result) is result

    def test_an_unreadable_statement_file_is_a_config_error_naming_the_option(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(paths: Any) -> Any:
            raise VexError("not an OpenVEX document")

        monkeypatch.setattr(VexDocuments, "load", staticmethod(fail))
        with pytest.raises(ConfigError, match="--vex: not an OpenVEX document"):
            ScanSuppression.apply_vex(argparse.Namespace(vex=["a.json"]), self.result())

    def test_what_the_statements_ruled_out_is_counted_on_stderr_and_kept_in_the_result(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        marked = self.ruled("vex", "vex", None, "baseline")
        monkeypatch.setattr(VexDocuments, "load", staticmethod(lambda paths: []))
        monkeypatch.setattr(VexDocuments, "apply", staticmethod(lambda findings, st: marked))
        out = ScanSuppression.apply_vex(argparse.Namespace(vex=["a.json"]), self.result())
        assert out.findings == marked
        assert "2 vulnerability finding(s) marked suppressed by VEX" in capsys.readouterr().err

    def test_statements_that_rule_nothing_out_print_nothing(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(VexDocuments, "load", staticmethod(lambda paths: []))
        monkeypatch.setattr(
            VexDocuments, "apply", staticmethod(lambda findings, st: self.ruled(None))
        )
        ScanSuppression.apply_vex(argparse.Namespace(vex=["a.json"]), self.result())
        assert capsys.readouterr().err == ""
