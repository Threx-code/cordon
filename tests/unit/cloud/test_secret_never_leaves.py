"""Row BP-16-2: a secret found is reported as its evidence hash and rule id only, never the value.

A file holds a secret in a live format (a GitHub token shape built here, not a real credential). The scan finds it, and the value is
in none of what is stored or sent: the finding and its evidence, every report format, the bytes that are uploaded, the minimal
record, the decision the execution plane makes and queues, or any log line written during the scan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cloud.minimal_record import MinimalRecord
from cordon_scanner.cloud.results import SignedResults
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.json_ import JsonReporter
from cordon_scanner.report.markdown import MarkdownReporter
from cordon_scanner.report.sarif import SarifReporter
from cordon_scanner.report.text import TextReporter

# A token in the live GitHub format, derived here so that no file of the repository holds a literal of that shape.
SECRET = (
    "ghp_"
    + base64.b64encode(
        hashlib.sha256(b"a fixture, not a credential").digest(), altchars=b"AB"
    ).decode()[:36]
)
RULE_PREFIX = "SECRET."


class Scan:
    @staticmethod
    def of(tmp_path: Path):
        (tmp_path / "deploy.sh").write_text(
            f'#!/bin/sh\nexport GITHUB_TOKEN="{SECRET}"\ngit push https://x:{SECRET}@github.com/acme/app.git\n',
            encoding="utf-8",
        )
        (tmp_path / ".env").write_text(f"GITHUB_TOKEN={SECRET}\n", encoding="utf-8")
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

    @staticmethod
    def secret_findings(result) -> list[Any]:
        return [item for item in result.findings if item.rule_id.startswith(RULE_PREFIX)]


class TestTheValueIsInNothingThatIsStoredOrSent:
    @pytest.fixture
    def result(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.DEBUG)
        found = Scan.of(tmp_path)
        self.logs = "\n".join(record.getMessage() for record in caplog.records)
        return found

    def test_the_scan_finds_the_secret_and_keeps_its_hash_and_rule_id(self, result) -> None:
        findings = Scan.secret_findings(result)
        assert findings, "the fixture must be found"
        for finding in findings:
            assert finding.rule_id.startswith(RULE_PREFIX)
            assert len(finding.evidence.match_hash) >= 16
            assert finding.evidence.snippet is None
            assert str(finding.evidence.kind) == "hash"
            assert str(finding.evidence.redaction) == "hash_only"

    def test_the_stored_finding_and_its_evidence(self, result) -> None:
        for finding in Scan.secret_findings(result):
            document = json.dumps(finding.to_dict(), sort_keys=True)
            assert SECRET not in document and SECRET[4:] not in document

    def test_the_whole_result(self, result) -> None:
        assert SECRET not in json.dumps(result.to_dict(), sort_keys=True, default=str)

    @pytest.mark.parametrize(
        "reporter",
        [JsonReporter, TextReporter, MarkdownReporter, SarifReporter],
        ids=lambda cls: cls.__name__,
    )
    def test_every_report_format(self, result, reporter) -> None:
        rendered = b"".join(reporter().render(result, ReportOptions(color=False, verbose=True)))
        assert SECRET.encode() not in rendered and SECRET[4:].encode() not in rendered
        assert any(item.rule_id.encode() in rendered for item in Scan.secret_findings(result))

    def test_the_bytes_that_are_uploaded(self, result) -> None:
        sent = SignedResults.results_bytes(result)
        assert SECRET.encode() not in sent
        assert any(item.rule_id.encode() in sent for item in Scan.secret_findings(result))

    def test_the_minimal_record(self, result) -> None:
        record = MinimalRecord.of(result)
        assert SECRET not in json.dumps(record)
        secret_rows = [row for row in record["findings"] if row["rule_id"].startswith(RULE_PREFIX)]
        assert secret_rows and all(row.get("evidence_hash") for row in secret_rows)

    def test_no_log_line_written_during_the_scan(self, result) -> None:
        assert SECRET not in self.logs and SECRET[4:] not in self.logs
