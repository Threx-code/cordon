"""The decision library's record base and instants: strict JSON in and out."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cordon_scanner.decide.decision.evidence import Context, FindingFact
from cordon_scanner.decide.decision.records import DecisionError, Instants


class TestJsonRecords:
    def test_a_record_round_trips_and_leaves_out_what_is_none(self) -> None:
        finding = FindingFact(
            "MALWARE.DROPPER.001", "high", "medium", "malicious", path="a.js", line=3
        )
        shape = finding.to_json()
        assert "evidence_hash" not in shape and shape["line"] == 3
        assert FindingFact.from_json(shape) == finding

    def test_a_key_the_record_does_not_have_is_an_error_naming_it(self) -> None:
        with pytest.raises(DecisionError, match="unexpected field 'sevrity'"):
            FindingFact.from_json(
                {"rule_id": "X.1", "sevrity": "high", "confidence": "low", "category": "policy"}
            )

    def test_a_missing_required_field_is_an_error_naming_the_record(self) -> None:
        with pytest.raises(DecisionError, match="FindingFact"):
            FindingFact.from_json({"rule_id": "X.1", "severity": "high"})

    def test_lists_become_tuples_and_a_value_of_the_wrong_shape_is_refused(self) -> None:
        context = Context.from_json(
            {"point": "cli", "environment": "dev", "scope_path": ["org", "team"]}
        )
        assert context.scope_path == ("org", "team")
        with pytest.raises(DecisionError):
            Context.from_json({"point": "cli", "environment": "dev", "scope_path": "org"})
        with pytest.raises(DecisionError, match="expected an object"):
            Context.from_json(["cli"])  # type: ignore[arg-type]


class TestInstants:
    def test_text_and_parse_agree_and_a_zone_is_required(self) -> None:
        moment = Instants.parse("2026-11-17T08:00:00Z")
        assert moment == datetime(2026, 11, 17, 8, 0, tzinfo=UTC)
        assert Instants.text(moment) == "2026-11-17T08:00:00Z"
        assert Instants.parse("2026-11-17T09:00:00+01:00") == moment
        with pytest.raises(DecisionError):
            Instants.parse("2026-11-17T08:00:00")
        with pytest.raises(DecisionError):
            Instants.parse("yesterday")

    def test_a_bucket_is_the_start_of_the_window_from_the_epoch(self) -> None:
        moment = datetime(2026, 11, 17, 8, 0, 59, tzinfo=UTC)
        assert Instants.bucket(moment, 60) == datetime(2026, 11, 17, 8, 0, tzinfo=UTC)
        assert Instants.bucket(datetime(2026, 11, 17, 8, 1, 0, tzinfo=UTC), 60) != Instants.bucket(
            moment, 60
        )
        with pytest.raises(DecisionError):
            Instants.bucket(moment, 0)
