"""Row BP-14-12: within a major version a schema changes only by addition.

`schema_baseline.json` is the shape of every contract schema as it was last released. Today's schemas must hold all of it: no field removed,
none retyped, no allowed value taken away, none made newly required. A new optional field, a new allowed value or a new schema file passes. The
reason codes are held the same way by `reason_codes.golden.json` (`test_reason_codes.py`: never reused, never renamed). A deliberate break is a
new major (a new `-v2` file), and the baseline is regenerated in that review (`tests/kits/schema_shape.py`).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from kits.schema_shape import SchemaShape
from support import ROOT

SCHEMAS = ROOT / "src" / "cordon_scanner" / "contracts" / "schemas"
BASELINE = json.loads(
    (ROOT / "tests" / "unit" / "contracts" / "schema_baseline.json").read_text(encoding="utf-8")
)
NOW = SchemaShape.folder(SCHEMAS)


class TestToday:
    def test_every_schema_of_the_baseline_is_still_there(self) -> None:
        assert set(BASELINE) <= set(NOW)

    @pytest.mark.parametrize("name", sorted(BASELINE))
    def test_a_schema_only_gained_what_it_was_given(self, name: str) -> None:
        assert SchemaShape.compare(BASELINE[name], NOW[name]) == []


class Doc:
    @staticmethod
    def shape(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return SchemaShape.of(schema)

    OLD: ClassVar[dict[str, Any]] = {
        "type": "object",
        "required": ["a"],
        "properties": {
            "a": {"type": "string", "enum": ["x", "y"]},
            "b": {
                "type": "array",
                "items": {"type": "object", "properties": {"c": {"type": "integer"}}},
            },
        },
    }


class TestTheComparison:
    def test_an_unchanged_schema_is_clean(self) -> None:
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(Doc.OLD)) == []

    def test_a_new_optional_field_a_new_value_and_a_new_definition_are_additions(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        new["properties"]["d"] = {"type": "string"}
        new["properties"]["a"]["enum"].append("z")
        new["$defs"] = {"extra": {"type": "string"}}
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == []

    def test_a_removed_field_is_found_also_inside_an_array_item(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        del new["properties"]["b"]["items"]["properties"]["c"]
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == [".b[].c: removed"]

    def test_a_retyped_field_is_found(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        new["properties"]["b"]["items"]["properties"]["c"]["type"] = "string"
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == [
            ".b[].c: retyped from integer to string"
        ]

    def test_a_value_taken_out_of_an_enum_is_found(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        new["properties"]["a"]["enum"] = ["x"]
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == [
            ".a: an allowed value was removed"
        ]

    def test_an_enum_dropped_altogether_is_found(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        del new["properties"]["a"]["enum"]
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == [
            ".a: an allowed value was removed"
        ]

    def test_a_field_that_became_required_is_found(self) -> None:
        new = json.loads(json.dumps(Doc.OLD))
        new["required"] = ["a", "b"]
        assert SchemaShape.compare(Doc.shape(Doc.OLD), Doc.shape(new)) == [".: newly required: b"]

    def test_a_changed_reference_and_a_changed_fixed_value_are_found(self) -> None:
        old = {"properties": {"p": {"$ref": "#/$defs/one"}, "k": {"const": 1}}}
        new = {"properties": {"p": {"$ref": "#/$defs/two"}, "k": {"const": 2}}}
        assert SchemaShape.compare(Doc.shape(old), Doc.shape(new)) == [
            ".k: the fixed value changed",
            ".p: now points at #/$defs/two, not #/$defs/one",
        ]
