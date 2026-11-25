"""The shipped contract schemas (design spec 7.1, 7.2): each is read whole, and a statement of each
predicate type validates, while a malformed one does not."""

from __future__ import annotations

import copy

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.schemas import ContractSchemas, Statements

DIGEST = ArtifactDigests.of_bytes(b"example")
SUBJECT = [{"name": "pkg:npm/left-pad@1.3.0", "digest": {"sha256": DIGEST.removeprefix("sha256:")}}]

PREDICATES = {
    "scan/v1": {
        "findings": [
            {
                "rule_id": "SUSPECT.DROPPER.001",
                "severity": "high",
                "confidence": "medium",
                "category": "suspicious",
                "location": {"path": "package/install.js", "line": 12},
            }
        ],
        "completeness": {"complete": True},
    },
    "decision/v1": {
        "state": "BLOCK",
        "reason_codes": ["R400"],
        "explanation": {
            "summary": "blocked",
            "reasons": [
                {
                    "code": "R400",
                    "text": "an install script downloads and runs a file",
                    "rule_id": "MALWARE.DROPPER.001",
                    "path": "package/install.js",
                    "line": 12,
                }
            ],
        },
        "obligations": [],
        "inputs_digest": DIGEST,
        "policy": {"id": "acme/production", "version": 14, "sha256": DIGEST},
    },
    "intel-match/v1": {
        "kind": "known_malware",
        "id": "MAL-2026-0001",
        "source": "osv",
        "first_seen": "2026-11-17T08:00:00Z",
    },
    "review/v1": {
        "label": "malicious",
        "readers": [
            {"reader": "one", "label": "malicious"},
            {"reader": "two", "label": "malicious"},
        ],
        "reasoning": "an install script fetches and runs a file",
    },
    "approval/v1": {
        "approver": "appsec",
        "scope": "org:acme/env:production",
        "digests": [DIGEST],
        "expires_at": "2027-01-01T00:00:00Z",
    },
    "inventory/v1": {
        "occurrences": [
            {"subject": "pkg:npm/left-pad", "digest": DIGEST, "where": "repo:github/acme/app"}
        ]
    },
}


class Samples:
    @staticmethod
    def statement(kind: str) -> dict:
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": SUBJECT,
            "predicateType": f"https://cordonscan.com/{kind}",
            "predicate": copy.deepcopy(PREDICATES[kind]),
        }


statement = Samples.statement


class TestTheShippedSchemas:
    @pytest.mark.parametrize("name", ContractSchemas.NAMES)
    def test_each_schema_is_read_whole_by_the_checker(self, name: str) -> None:
        assert ContractSchemas.problems() == []
        assert ContractSchemas.load(name)["$id"].endswith(f"{name}.json")

    def test_every_predicate_type_has_a_schema_and_a_sample(self) -> None:
        for kind in PREDICATES:
            assert ContractSchemas.for_predicate(f"https://cordonscan.com/{kind}")
        assert len(PREDICATES) == len(ContractSchemas.NAMES) - 1

    def test_an_unknown_schema_is_an_error(self) -> None:
        with pytest.raises(KeyError):
            ContractSchemas.load("nope")
        with pytest.raises(KeyError):
            ContractSchemas.for_predicate("https://example.com/other/v1")


class TestStatements:
    @pytest.mark.parametrize("kind", PREDICATES)
    def test_a_well_formed_statement_validates(self, kind: str) -> None:
        assert Statements.validate(statement(kind)) == []

    def test_a_decision_with_an_unregistered_shape_fails(self) -> None:
        bad = statement("decision/v1")
        bad["predicate"]["state"] = "MAYBE"
        bad["predicate"]["reason_codes"] = ["X400"]
        errors = Statements.validate(bad)
        assert any("state" in e for e in errors) and any("reason_codes" in e for e in errors)

    def test_an_approval_with_no_digest_fails(self) -> None:
        bad = statement("approval/v1")
        bad["predicate"]["digests"] = []
        assert Statements.validate(bad)

    def test_a_plain_approval_signed_before_the_exception_fields_still_validates(self) -> None:
        old = statement("approval/v1")
        assert set(old["predicate"]) == {"approver", "scope", "digests", "expires_at"}
        assert Statements.validate(old) == []

    @pytest.mark.parametrize(
        ("outcome", "rule_ids", "reason_codes"),
        [
            ("REVIEW", ["SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"], ["R204"]),
            ("ALLOW", None, None),
            ("REVIEW", ["MALWARE.INSTALL.FETCH_EXEC.001", "POLICY.CI.WILDCARD.001"], None),
            ("ALLOW", None, ["R204", "R301"]),
        ],
    )
    def test_an_exception_carries_what_it_speaks_for(
        self, outcome: str, rule_ids: list[str] | None, reason_codes: list[str] | None
    ) -> None:
        exception = statement("approval/v1")
        exception["predicate"].update(
            {"outcome": outcome, "rule_ids": rule_ids, "reason_codes": reason_codes}
        )
        assert Statements.validate(exception) == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("outcome", "BLOCK"),
            ("outcome", "allow"),
            ("outcome", None),
            ("rule_ids", []),
            ("rule_ids", "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"),
            ("rule_ids", ["A.B.001", "A.B.001"]),
            ("rule_ids", ["has space"]),
            ("rule_ids", [""]),
            ("reason_codes", []),
            ("reason_codes", ["X400"]),
            ("reason_codes", ["R204", "R204"]),
            ("reason_codes", "R204"),
        ],
    )
    def test_an_exception_field_that_does_not_say_one_thing_fails(
        self, field: str, value: object
    ) -> None:
        bad = statement("approval/v1")
        bad["predicate"].update({"outcome": "REVIEW", "rule_ids": None, "reason_codes": None})
        bad["predicate"][field] = value
        errors = Statements.validate(bad)
        assert errors and any(field in e for e in errors)

    def test_an_approval_still_refuses_a_key_it_does_not_name(self) -> None:
        bad = statement("approval/v1")
        bad["predicate"]["outcomes"] = "ALLOW"
        assert Statements.validate(bad)

    def test_a_review_needs_two_readers(self) -> None:
        bad = statement("review/v1")
        bad["predicate"]["readers"] = bad["predicate"]["readers"][:1]
        assert Statements.validate(bad)

    def test_the_envelope_is_checked_first(self) -> None:
        bad = statement("scan/v1")
        bad["predicateType"] = "https://cordonscan.com/unknown/v9"
        assert Statements.validate(bad)
