"""Report edges: what each format leaves out, truncates or escapes (`report/*`)."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest
from test_reporters import OPTS, ReportersHelpers

from cordon_scanner.foundation.models import Category, Location, Suppression
from cordon_scanner.foundation.results import ScanResult
from cordon_scanner.report.base import Escape, ReportOptions
from cordon_scanner.report.codeclimate import CodeClimateReporter
from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.report.github import GithubReporter
from cordon_scanner.report.json_ import JsonReporter
from cordon_scanner.report.junit import JunitReporter
from cordon_scanner.report.markdown import MarkdownReporter
from cordon_scanner.report.sarif import SarifReporter
from cordon_scanner.report.text import TextReporter
from cordon_scanner.report.vex import VexReporter

HIDING = ReportOptions(color=False, show_suppressed=False)
SUPPRESSION = Suppression(rule="HID.001", path="a.py", justification="x" * 40, expires="2099-01-01")


class _Base:
    @staticmethod
    def with_one_suppressed() -> ScanResult:
        return ReportersHelpers.result(
            ReportersHelpers.finding("HID.001", suppressed=SUPPRESSION),
            ReportersHelpers.finding("SHOWN.001"),
        )


class TestSuppressedFindingsCanBeLeftOut(_Base):
    def test_every_structured_format_keeps_them_by_default_and_drops_them_on_request(self) -> None:
        result = self.with_one_suppressed()
        for reporter in (CodeClimateReporter(), JunitReporter(), SarifReporter(), JsonReporter()):
            kept = reporter.render_to_string(result, OPTS)
            dropped = reporter.render_to_string(result, HIDING)
            name = type(reporter).__name__
            assert "HID.001" in kept, name
            assert "HID.001" not in dropped, name
            assert "SHOWN.001" in dropped, name


class TestEscapes:
    def test_a_pipe_in_a_code_span_cannot_end_the_table_cell(self) -> None:
        assert Escape.code("a|b") == "a&#124;b"

    def test_an_ampersand_in_prose_is_an_entity_so_a_name_cannot_start_one(self) -> None:
        assert Escape.markdown("a & b") == "a &amp; b"


class TestIncompleteAndTruncated(_Base):
    def test_the_github_format_says_a_partial_scan_is_reduced_coverage(self) -> None:
        text = GithubReporter().render_to_string(
            ReportersHelpers.result(ReportersHelpers.finding(), complete=False), OPTS
        )
        assert "::warning::The scan did not complete" in text

    def test_markdown_lists_thirty_findings_and_counts_the_rest(self) -> None:
        findings = [ReportersHelpers.finding(f"R.{n:03}", path=f"f{n}.py") for n in range(31)]
        text = MarkdownReporter().render_to_string(ReportersHelpers.result(*findings), OPTS)
        assert "_1 further finding(s) not listed._" in text

    def test_text_with_a_limit_says_how_many_it_did_not_show(self) -> None:
        findings = [ReportersHelpers.finding(f"R.{n:03}", path=f"f{n}.py") for n in range(3)]
        text = TextReporter().render_to_string(
            ReportersHelpers.result(*findings), ReportOptions(color=False, max_findings=1)
        )
        assert "2 further finding(s) not shown" in text
        assert "f0.py" in text and "f2.py" not in text


class TestSarifRegion(_Base):
    def test_the_end_line_and_byte_range_of_a_location_reach_the_region(self) -> None:
        located = replace(
            ReportersHelpers.finding(),
            location=Location(
                path="a.py", line=3, column=2, end_line=5, byte_start=10, byte_end=20
            ),
        )
        payload = json.loads(
            SarifReporter().render_to_string(ReportersHelpers.result(located), OPTS)
        )
        region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert (region["startLine"], region["startColumn"], region["endLine"]) == (3, 2, 5)
        assert region["byteOffset"] == 10
        assert region["byteLength"] == 10


class TestFacts(_Base):
    def test_a_scanner_internal_finding_is_not_a_fact(self) -> None:
        internal = ReportersHelpers.finding("INTERNAL.NOTE.001")
        result = replace(
            ReportersHelpers.result(ReportersHelpers.finding("REAL.001")),
            unfiltered=(internal, ReportersHelpers.finding("REAL.001")),
        )
        assert "INTERNAL" not in json.dumps(ScanFacts.of(result), default=str)


VULNERABLE = "VULNERABLE.DEPENDENCY.KNOWN.001"


class _VexKit:
    @staticmethod
    def statement(finding: Any) -> dict[str, Any]:
        payload = json.loads(VexReporter().render_to_string(ReportersHelpers.result(finding), OPTS))
        return payload["vulnerabilities"][0]

    @staticmethod
    def with_metadata(**metadata: str) -> Any:
        base = ReportersHelpers.finding(VULNERABLE, category=Category.VULNERABLE)
        return replace(base, evidence=replace(base.evidence, metadata=tuple(metadata.items())))


class TestVexStatements:
    def test_a_dependency_only_called_from_unreferenced_private_code_is_not_affected(self) -> None:
        analysis = _VexKit.statement(_VexKit.with_metadata(reachability="called_unreached"))[
            "analysis"
        ]
        assert (analysis["state"], analysis["justification"]) == (
            "not_affected",
            "code_not_reachable",
        )

    @pytest.mark.parametrize(
        ("justification", "state"),
        [
            ("VEX fixed per supplier.json", "resolved"),
            ("VEX false_positive per supplier.json", "false_positive"),
            ("VEX not_affected per supplier.json", "not_affected"),
            ("VEX something_else per supplier.json", "not_affected"),
        ],
    )
    def test_a_vex_ruling_carries_the_suppliers_own_status(
        self, justification: str, state: str
    ) -> None:
        base = ReportersHelpers.finding(VULNERABLE, category=Category.VULNERABLE)
        ruled = replace(
            base,
            suppressed=Suppression(
                rule=VULNERABLE,
                path="a.py",
                justification=justification,
                expires="9999-12-31",
                approved_by="vex",
            ),
        )
        assert _VexKit.statement(ruled)["analysis"]["state"] == state

    def test_the_advisory_named_in_the_message_is_the_identifier_when_the_summary_has_none(
        self,
    ) -> None:
        base = ReportersHelpers.finding(VULNERABLE, category=Category.VULNERABLE)
        named = replace(base, explanation=None, message="lodash is affected by CVE-2021-23337.")
        assert _VexKit.statement(named)["id"] == "CVE-2021-23337"

    def test_a_finding_that_names_no_advisory_is_identified_by_its_fingerprint(self) -> None:
        base = ReportersHelpers.finding(VULNERABLE, category=Category.VULNERABLE)
        unnamed = replace(base, explanation=None, message="a vulnerable version")
        assert _VexKit.statement(unnamed)["id"] == f"cordon-{unnamed.fingerprint}"


class TestMoreEscapes:
    @pytest.mark.parametrize(
        ("raw", "escaped"),
        [("`", "&#96;"), ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;")],
    )
    def test_each_character_that_could_break_out_of_a_code_span_is_an_entity(
        self, raw: str, escaped: str
    ) -> None:
        assert Escape.code(f"a{raw}b") == f"a{escaped}b"

    def test_a_newline_in_prose_is_a_space_so_it_cannot_end_the_line_it_sits_in(self) -> None:
        assert Escape.markdown("a\nb\r\nc") == "a b  c"


class TestTextReport:
    def test_a_finding_without_a_line_is_placed_by_a_dash_and_one_naming_its_file_is_not_repeated(
        self,
    ) -> None:
        base = ReportersHelpers.finding(path="setup.py")
        located = replace(
            base,
            location=Location(path="setup.py"),
            message="setup.py: runs a downloaded file",
        )
        text = TextReporter().render_to_string(ReportersHelpers.result(located), OPTS)
        assert "Runs a downloaded file" in text
        assert "setup.py: runs" not in text
        assert " -  " in text or " -" in text


class TestVerboseText:
    def test_the_verbose_block_names_assurance_its_hint_and_who_a_suppression_was_approved_by(
        self,
    ) -> None:
        base = ReportersHelpers.finding(
            "LEARNED.EDGE.001",
            suppressed=Suppression(
                rule="LEARNED.EDGE.001",
                path="setup.py",
                justification="x" * 40,
                expires="2099-01-01",
                approved_by="alice",
            ),
        )
        finding = base
        text = TextReporter().render_to_string(
            ReportersHelpers.result(finding), ReportOptions(color=False, verbose=True)
        )
        assert "· suspected, machine-made · detector manifest" in text
        assert "To hold it: cordon-scanner suppress add LEARNED.EDGE.001" in text
        assert "suppressed until 2099-01-01 by alice" in text

    def test_text_with_no_words_wraps_to_no_lines(self) -> None:
        assert TextReporter._wrap("   ", 80, "  ") == []

    def test_a_finding_with_no_file_is_placed_by_its_location_text(self) -> None:
        base = ReportersHelpers.finding()
        nowhere = replace(base, location=Location(path=""))
        text = TextReporter().render_to_string(ReportersHelpers.result(nowhere), OPTS)
        assert "MALWARE.EXFIL.001" in text
