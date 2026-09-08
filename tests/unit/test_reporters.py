"""Output formats.

Reporters are pure functions from a result to bytes, so they can be driven with
a hand-built result and never need a scan. That is the practical payoff of
keeping them out of the engine.

The SARIF tests carry the most weight. It is easy to emit a technically valid
SARIF file that is useless in practice, and three properties decide which one
you have: whether findings can be ranked, whether alerts survive a reformat, and
whether a rule page exists to click through to.
"""

from __future__ import annotations

import json
from xml.etree import ElementTree

import pytest

from cordon.core.models import (
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskFactor,
    RiskScore,
    ScanResult,
    ScanStats,
    Severity,
    Suppression,
)
from cordon.report.base import ReportOptions
from cordon.report.github import GithubReporter
from cordon.report.json_ import JsonReporter
from cordon.report.junit import JunitReporter
from cordon.report.markdown import MarkdownReporter
from cordon.report.sarif import SarifReporter
from cordon.report.text import TextReporter

SECRET_VALUE = "ghp_" + "A" * 36


def finding(
    rule_id: str = "MALWARE.EXFIL.001",
    *,
    severity: Severity = Severity.CRITICAL,
    category: Category = Category.MALICIOUS,
    confidence: Confidence = Confidence.HIGH,
    path: str = "setup.py",
    line: int = 12,
    risk: int = 92,
    snippet: str | None = "scripts.postinstall = curl x | sh",
    suppressed: Suppression | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        message="An install script transmits credentials.",
        location=Location(path=path, line=line, column=3, byte_start=100, byte_end=140),
        evidence=Evidence(
            kind=EvidenceKind.SNIPPET if snippet else EvidenceKind.HASH,
            match_hash=Evidence.hash_bytes(SECRET_VALUE.encode()),
            redaction=RedactionMode.MASKED if snippet else RedactionMode.HASH_ONLY,
            snippet=snippet,
            span=(100, 140),
        ),
        remediation="Remove the postinstall script.",
        explanation=Explanation(
            summary="Install script transmits credentials",
            matched_rule=rule_id,
            escalations=("runs during install, before any other control",),
        ),
        risk=RiskScore(
            value=risk,
            base=90,
            confidence_multiplier=1.0,
            factors=(RiskFactor("install_time", 15, "runs during install"),),
        ),
        detector="manifest",
        references=("https://example.invalid/rule",),
        capabilities=(Capability.CREDENTIAL, Capability.EGRESS),
        suppressed=suppressed,
    )


def result(*findings: Finding, complete: bool = True) -> ScanResult:
    return ScanResult(
        findings=tuple(findings),
        stats=ScanStats(files_scanned=42, dependencies=7, duration_ms=1234),
        complete=complete,
        engine_version="0.1.0",
        rulepack_version="1.0.0",
        rulepack_hash="deadbeef",
        config_hash="cafebabe",
    ).sorted()


OPTS = ReportOptions(color=False)


# ---------------------------------------------------------------------------
# JSON: the canonical form
# ---------------------------------------------------------------------------


class TestJson:
    def test_is_valid_and_complete(self) -> None:
        payload = json.loads(JsonReporter().render_to_string(result(finding()), OPTS))
        assert payload["schema_version"] >= 1
        assert payload["complete"] is True
        assert payload["rulepack_hash"] == "deadbeef"
        assert len(payload["findings"]) == 1

    def test_is_byte_identical_across_renders(self) -> None:
        """Every other format derives from this one, so its stability is what
        makes the rest comparable."""
        scan = result(finding("A.001"), finding("B.001", severity=Severity.LOW))
        first = JsonReporter().render_to_string(scan, OPTS)
        second = JsonReporter().render_to_string(scan, OPTS)
        assert first == second

    def test_suppressed_findings_are_retained(self) -> None:
        """An auditor's first question is what the tool was told to ignore."""
        suppression = Suppression(
            rule="A.001", path="a.py", justification="x" * 40, expires="2099-01-01"
        )
        payload = json.loads(
            JsonReporter().render_to_string(result(finding("A.001", suppressed=suppression)), OPTS)
        )
        assert "suppressed" in payload["findings"][0]

    def test_truncation_is_declared(self) -> None:
        """A truncated report that does not say so is a report that lies."""
        scan = result(*[finding(f"R.{i:03d}") for i in range(10)])
        payload = json.loads(
            JsonReporter().render_to_string(scan, ReportOptions(color=False, max_findings=3))
        )
        assert payload["truncated"] is True
        assert len(payload["findings"]) == 3


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


class TestSarif:
    def document(self, scan: ScanResult) -> dict:
        return json.loads(SarifReporter().render_to_string(scan, OPTS))

    def test_shape_is_valid(self) -> None:
        doc = self.document(result(finding()))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "Cordon"

    def test_security_severity_is_present_and_scaled(self) -> None:
        """The property platforms actually sort and threshold on. Without it
        every finding renders as equally important, which discards the entire
        ranking the scorer exists to produce."""
        doc = self.document(result(finding(risk=92)))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.2"

    def test_security_tag_is_present(self) -> None:
        """Required for a platform to treat the alert as a security alert
        rather than a quality one, which changes where it appears."""
        doc = self.document(result(finding()))
        assert "security" in doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]

    def test_partial_fingerprints_are_present(self) -> None:
        """Without these, reformatting a file re-raises every alert in it as
        new and users learn to dismiss findings in bulk."""
        doc = self.document(result(finding()))
        prints = doc["runs"][0]["results"][0]["partialFingerprints"]
        assert prints["cordonFingerprint/v1"]

    def test_fingerprint_survives_a_line_move(self) -> None:
        a = self.document(result(finding(line=12)))
        b = self.document(result(finding(line=847)))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]
            == b["runs"][0]["results"][0]["partialFingerprints"]
        )

    def test_rule_index_resolves_for_every_result(self) -> None:
        """Results reference rules by index. A mismatch renders every alert
        against the wrong rule page."""
        scan = result(
            finding("A.001"),
            finding("B.001", severity=Severity.HIGH),
            finding("A.001", path="other.py"),
        )
        doc = self.document(scan)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        for entry in doc["runs"][0]["results"]:
            assert rules[entry["ruleIndex"]]["id"] == entry["ruleId"]

    def test_full_rule_catalogue_is_emitted(self) -> None:
        doc = self.document(result(finding("A.001"), finding("B.001")))
        ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert ids == {"A.001", "B.001"}

    def test_help_text_is_present_for_click_through(self) -> None:
        doc = self.document(result(finding()))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["help"]["markdown"]
        assert "Remediation" in rule["help"]["markdown"]

    def test_severity_maps_to_sarif_levels(self) -> None:
        for severity, level in (
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
        ):
            doc = self.document(result(finding(severity=severity)))
            assert doc["runs"][0]["results"][0]["level"] == level

    def test_incomplete_scan_is_declared(self) -> None:
        """A platform showing zero alerts must be distinguishable from a scan
        that could not finish."""
        doc = self.document(result(finding(), complete=False))
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False

    def test_suppressions_are_emitted_not_dropped(self) -> None:
        suppression = Suppression(
            rule="MALWARE.EXFIL.001",
            path="setup.py",
            justification="x" * 40,
            expires="2099-01-01",
            approved_by="security",
        )
        doc = self.document(result(finding(suppressed=suppression)))
        entry = doc["runs"][0]["results"][0]
        assert entry["suppressions"][0]["justification"]

    def test_risk_factors_survive_into_sarif(self) -> None:
        """Explainability must not be lost at the format boundary."""
        doc = self.document(result(finding()))
        assert doc["runs"][0]["results"][0]["properties"]["riskFactors"]

    def test_operational_findings_are_notifications_not_results(self) -> None:
        """A degraded scan is not a finding about the code."""
        scan = result(
            finding(),
            finding(
                "OPERATIONAL.X",
                category=Category.OPERATIONAL,
                severity=Severity.INFO,
            ),
        )
        doc = self.document(scan)
        assert len(doc["runs"][0]["results"]) == 1
        assert doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]

    def test_repository_provenance_when_supplied(self) -> None:
        doc = json.loads(
            SarifReporter().render_to_string(
                result(finding()),
                ReportOptions(
                    color=False,
                    repository_uri="https://example.invalid/r",
                    revision="abc123",
                ),
            )
        )
        provenance = doc["runs"][0]["versionControlProvenance"][0]
        assert provenance["revisionId"] == "abc123"


# ---------------------------------------------------------------------------
# JUnit
# ---------------------------------------------------------------------------


class TestJunit:
    def test_is_well_formed_xml(self) -> None:
        xml = JunitReporter().render_to_string(result(finding()), OPTS)
        root = ElementTree.fromstring(xml)
        assert root.tag == "testsuites"

    def test_one_case_per_rule_not_per_finding(self) -> None:
        """One case per finding would make the test count change on every run
        and the history unreadable."""
        scan = result(
            finding("A.001", path="a.py"),
            finding("A.001", path="b.py"),
            finding("B.001", path="c.py", severity=Severity.HIGH),
        )
        root = ElementTree.fromstring(JunitReporter().render_to_string(scan, OPTS))
        assert root.get("tests") == "2"

    def test_suppressed_findings_are_skipped_not_failed(self) -> None:
        suppression = Suppression(
            rule="MALWARE.EXFIL.001",
            path="setup.py",
            justification="x" * 40,
            expires="2099-01-01",
        )
        root = ElementTree.fromstring(
            JunitReporter().render_to_string(result(finding(suppressed=suppression)), OPTS)
        )
        assert root.findall(".//skipped")
        assert not root.findall(".//failure")

    def test_incomplete_scan_appears_as_a_failure(self) -> None:
        """A partial run must be visible in the place people actually look."""
        root = ElementTree.fromstring(
            JunitReporter().render_to_string(result(finding(), complete=False), OPTS)
        )
        names = [c.get("name") for c in root.findall(".//testcase")]
        assert "scan.completeness" in names

    def test_special_characters_are_escaped(self) -> None:
        scan = result(finding(path='weird<&>"name.py'))
        xml = JunitReporter().render_to_string(scan, OPTS)
        ElementTree.fromstring(xml)  # raises if escaping is wrong


# ---------------------------------------------------------------------------
# Markdown and GitHub annotations
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_reports_findings(self) -> None:
        out = MarkdownReporter().render_to_string(result(finding()), OPTS)
        assert "MALWARE.EXFIL.001" in out
        assert "setup.py" in out

    def test_clean_result_says_so(self) -> None:
        assert "No findings" in MarkdownReporter().render_to_string(result(), OPTS)

    def test_never_emits_a_snippet(self) -> None:
        """A pull-request comment is more public than a log: visible to everyone
        with read access, emailed, and persisting after the branch is gone."""
        out = MarkdownReporter().render_to_string(
            result(finding(snippet="token = " + SECRET_VALUE)), OPTS
        )
        assert SECRET_VALUE not in out
        assert "sha256:" in out

    def test_incompleteness_is_stated(self) -> None:
        out = MarkdownReporter().render_to_string(result(finding(), complete=False), OPTS)
        assert "INCOMPLETE" in out


class TestGithubAnnotations:
    def test_emits_workflow_commands(self) -> None:
        out = GithubReporter().render_to_string(result(finding()), OPTS)
        assert out.startswith("::error ")
        assert "file=setup.py" in out
        assert "line=12" in out

    def test_newlines_are_encoded(self) -> None:
        """A raw newline ends the command, so the rest becomes ordinary log text
        and the annotation is silently truncated."""
        out = GithubReporter().render_to_string(result(finding()), OPTS)
        for line in out.splitlines():
            if line.startswith("::"):
                assert "\n" not in line[2:]

    def test_annotation_count_is_capped(self) -> None:
        """The platform caps annotations per level, so emitting more is wasted
        output that displaces useful lines."""
        scan = result(*[finding(f"R.{i:03d}", path=f"f{i}.py") for i in range(40)])
        out = GithubReporter().render_to_string(scan, OPTS)
        assert sum(1 for line in out.splitlines() if line.startswith("::error")) <= 10
        assert "further finding" in out

    def test_suppressed_findings_are_not_annotated(self) -> None:
        suppression = Suppression(
            rule="MALWARE.EXFIL.001",
            path="setup.py",
            justification="x" * 40,
            expires="2099-01-01",
        )
        out = GithubReporter().render_to_string(result(finding(suppressed=suppression)), OPTS)
        assert "::error" not in out


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


class TestText:
    def test_contains_what_a_reader_needs(self) -> None:
        out = TextReporter().render_to_string(result(finding()), OPTS)
        for expected in ("CRITICAL", "MALWARE.EXFIL.001", "setup.py:12:3", "risk 92/100"):
            assert expected in out

    def test_score_derivation_is_printed(self) -> None:
        """The explainability requirement made concrete: a reader can check the
        arithmetic."""
        out = TextReporter().render_to_string(result(finding()), OPTS)
        assert "why" in out
        assert "install_time" in out

    def test_escalations_are_labelled_separately(self) -> None:
        """Printed under the score indent they read as further arithmetic."""
        out = TextReporter().render_to_string(result(finding()), OPTS)
        assert "context" in out

    def test_no_ansi_when_colour_is_off(self) -> None:
        out = TextReporter().render_to_string(result(finding()), ReportOptions(color=False))
        assert "\033[" not in out

    def test_completeness_is_always_stated(self) -> None:
        """A reader must never have to infer whether the tool actually looked."""
        assert "scan complete" in TextReporter().render_to_string(result(finding()), OPTS)
        assert "INCOMPLETE" in TextReporter().render_to_string(
            result(finding(), complete=False), OPTS
        )

    def test_withheld_evidence_is_shown_as_withheld(self) -> None:
        out = TextReporter().render_to_string(result(finding(snippet=None)), OPTS)
        assert "withheld" in out


# ---------------------------------------------------------------------------
# Cross-format guarantees
# ---------------------------------------------------------------------------


REPORTERS = [
    JsonReporter(),
    SarifReporter(),
    JunitReporter(),
    MarkdownReporter(),
    GithubReporter(),
    TextReporter(),
]


@pytest.mark.parametrize("reporter", REPORTERS, ids=lambda r: r.id)
class TestEveryReporter:
    def test_handles_an_empty_result(self, reporter) -> None:
        assert reporter.render_to_string(result(), OPTS) is not None

    def test_output_is_stable(self, reporter) -> None:
        scan = result(finding("A.001"), finding("B.001", severity=Severity.LOW))
        assert reporter.render_to_string(scan, OPTS) == reporter.render_to_string(scan, OPTS)

    def test_never_emits_a_raw_secret(self, reporter) -> None:
        """The guarantee that matters most across every format. A finding whose
        evidence is withheld must stay withheld wherever it is rendered."""
        scan = result(finding(snippet=None))
        assert SECRET_VALUE not in reporter.render_to_string(scan, OPTS)

    def test_renders_every_severity(self, reporter) -> None:
        scan = result(*[finding(f"R.{s}", severity=s) for s in Severity])
        assert reporter.render_to_string(scan, OPTS) is not None

    def test_output_is_bytes_chunks(self, reporter) -> None:
        for chunk in reporter.render(result(finding()), OPTS):
            assert isinstance(chunk, bytes)
