"""The contract registries' own consistency checks and the generated files' writer and refusals, with entries made wrong on purpose (`contracts/*`)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cordon_scanner.contracts.manifest import ContractData
from cordon_scanner.contracts.obligations import Obligations
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.contracts.schema_check import SchemaChecker
from cordon_scanner.contracts.subjects import (
    CanonicalIds,
    InvalidSubject,
    SubjectKind,
    SubjectParts,
)


class TestObligationRegistry:
    def test_the_shipped_registry_is_sound(self) -> None:
        assert Obligations.problems() == []

    def test_a_malformed_duplicated_or_retired_code_is_named(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = Obligations.ALL[0]
        monkeypatch.setattr(
            Obligations,
            "ALL",
            (replace(first, code="not-a-code"), first, first),
        )
        monkeypatch.setattr(Obligations, "RETIRED", frozenset({first.code}))
        found = Obligations.problems()
        assert f"{first.code}: code or name issued twice" in found
        assert "not-a-code: not an obligation code" in found
        assert f"{first.code}: retired and listed" in found


class TestReasonCodeRegistry:
    def test_the_shipped_registry_is_sound(self) -> None:
        assert ReasonCodes.problems() == []

    def test_each_kind_of_mistake_is_named_against_its_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = ReasonCodes.ALL[0]
        hard_stop = next(e for e in ReasonCodes.ALL if e.group == "R1")
        bad = (
            replace(real, code="nope", name="N1"),
            replace(real, code="R800", group="R8", name="N2"),
            replace(real, code="R201", group="R1", name="N3"),
            replace(real, code="R202", severity="catastrophic", name="N4"),
            replace(hard_stop, overridable=True, name="N5"),
            real,
            real,
        )
        monkeypatch.setattr(ReasonCodes, "ALL", bad)
        monkeypatch.setattr(ReasonCodes, "RETIRED", frozenset({real.code}))
        found = ReasonCodes.problems()
        assert "nope: not a reason code" in found
        assert "R201: is not in group R1" in found
        assert "R800: unknown group R8" in found
        assert "R202: unknown severity catastrophic" in found
        assert f"{hard_stop.code}: a hard stop cannot be overridable" in found
        assert f"{real.code}: code or name issued twice" in found
        assert f"{real.code}: retired and listed" in found


class TestGeneratedContractFiles:
    def test_writing_puts_every_generated_file_in_the_folder_but_not_the_hand_written_schemas(
        self, tmp_path: Path
    ) -> None:
        written = ContractData.write(tmp_path)
        assert written
        assert not any(name.startswith("schemas/") for name in written)
        assert all((tmp_path / name).is_file() for name in written)

    def test_a_shipped_file_that_differs_from_the_registries_is_named(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ContractData, "_shipped", classmethod(lambda cls, path: "stale"))
        found = ContractData.problems()
        assert found
        assert all(line.endswith("differs from what the registries generate") for line in found)


class TestSchemaChecker:
    def test_unknown_keywords_are_found_inside_alternatives(self) -> None:
        schema = {"oneOf": [{"type": "string"}, {"frobnicate": 1}]}
        assert SchemaChecker.unknown_keywords(schema) == [
            "$.oneOf[1]: unknown keyword 'frobnicate'"
        ]

    def test_additional_properties_given_as_a_schema_check_each_extra_value(self) -> None:
        schema = {"type": "object", "additionalProperties": {"type": "integer"}}
        assert SchemaChecker.errors(schema, {"a": 1, "b": "x"}) == [
            "$.b: expected integer, got str"
        ]

    def test_an_array_longer_than_its_maximum_is_named(self) -> None:
        schema = {"type": "array", "maxItems": 1}
        assert SchemaChecker.errors(schema, [1, 2]) == ["$: more than 1 items"]

    def test_every_branch_of_all_of_reports_its_own_errors(self) -> None:
        schema = {"allOf": [{"type": "string"}, {"minLength": 5}]}
        assert SchemaChecker.errors(schema, "ab") != []

    def test_a_boolean_is_neither_an_integer_nor_a_number(self) -> None:
        assert SchemaChecker.errors({"type": "number"}, True) == ["$: expected number, got bool"]
        assert SchemaChecker.errors({"type": "integer"}, True) == ["$: expected integer, got bool"]


class TestSubjectRefusals:
    def test_an_ecosystem_that_cannot_be_a_package_type_is_refused(self) -> None:
        with pytest.raises(InvalidSubject, match="is not a package type"):
            CanonicalIds.canonical_id(SubjectKind.PACKAGE, {"ecosystem": "1bad!", "name": "x"})

    def test_a_locator_that_starts_at_the_root_is_not_inside_the_folder(self) -> None:
        with pytest.raises(InvalidSubject, match="not a relative path inside the folder"):
            SubjectParts.relative("/etc/passwd")

    def test_an_agent_product_with_punctuation_is_not_a_name(self) -> None:
        with pytest.raises(InvalidSubject, match="product"):
            CanonicalIds.canonical_id(SubjectKind.AGENT, {"product": "a/b"})
