"""`SchemaChecker`: the JSON Schema keywords Cordon's contract schemas use, and no others."""

from __future__ import annotations

import pytest

from cordon_scanner.contracts.schema_check import SchemaChecker

SCHEMA = {
    "$defs": {"digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{4}$"}},
    "type": "object",
    "required": ["name", "digest"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string", "minLength": 2, "maxLength": 5},
        "digest": {"$ref": "#/$defs/digest"},
        "n": {"type": "integer", "minimum": 1, "maximum": 3},
        "tags": {
            "type": "array",
            "uniqueItems": True,
            "minItems": 1,
            "maxItems": 2,
            "items": {"enum": ["a", "b", "c"]},
        },
        "kind": {"oneOf": [{"const": "x"}, {"const": "y"}]},
        "any": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
}


class TestWhatPasses:
    def test_a_conforming_value(self) -> None:
        value = {
            "name": "ab",
            "digest": "sha256:00ff",
            "n": 2,
            "tags": ["a"],
            "kind": "x",
            "any": None,
        }
        assert SchemaChecker.errors(SCHEMA, value) == []


class TestWhatFails:
    @pytest.mark.parametrize(
        ("value", "needle"),
        [
            ({"digest": "sha256:00ff"}, "missing 'name'"),
            ({"name": "a", "digest": "sha256:00ff"}, "shorter"),
            ({"name": "abcdef", "digest": "sha256:00ff"}, "longer"),
            ({"name": "ab", "digest": "nope"}, "does not match"),
            ({"name": "ab", "digest": "sha256:00ff", "n": 0}, "below"),
            ({"name": "ab", "digest": "sha256:00ff", "n": 4}, "above"),
            ({"name": "ab", "digest": "sha256:00ff", "n": True}, "expected integer"),
            ({"name": "ab", "digest": "sha256:00ff", "tags": ["a", "a"]}, "not unique"),
            ({"name": "ab", "digest": "sha256:00ff", "tags": ["z"]}, "is not one of"),
            ({"name": "ab", "digest": "sha256:00ff", "tags": []}, "fewer"),
            ({"name": "ab", "digest": "sha256:00ff", "kind": "z"}, "not exactly one"),
            ({"name": "ab", "digest": "sha256:00ff", "any": 1}, "none of the alternatives"),
            ({"name": "ab", "digest": "sha256:00ff", "extra": 1}, "unexpected"),
        ],
    )
    def test_each_violation_is_reported_with_its_path(self, value, needle: str) -> None:
        errors = SchemaChecker.errors(SCHEMA, value)
        assert any(needle in error and error.startswith("$") for error in errors), errors

    def test_an_unknown_keyword_in_a_schema_is_an_error_not_a_pass(self) -> None:
        schema = {"type": "object", "properties": {"a": {"type": "string", "format": "email"}}}
        assert SchemaChecker.unknown_keywords(schema) == ["$.a: unknown keyword 'format'"]

    def test_a_reference_outside_the_document_is_refused(self) -> None:
        with pytest.raises(ValueError):
            SchemaChecker.errors({"$ref": "http://elsewhere/x.json"}, 1)
