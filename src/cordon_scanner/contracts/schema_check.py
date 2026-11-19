"""A checker for the JSON Schema keywords Cordon's own contract schemas use.

The core has no third-party runtime dependency (constraint C1), so the schemas shipped in
`contracts/schemas/` are checked here, with the keywords they use and no others:

```
  type  enum  const  pattern  minLength  maxLength  minimum  maximum  required  properties
  additionalProperties  items  minItems  maxItems  uniqueItems  oneOf  anyOf  allOf  $ref (#/$defs/...)
```

A keyword this checker does not know in a schema is an error, not a pass: a schema that says more than
the checker reads would validate things it does not constrain. `errors(schema, value)` lists every
violation as `<path>: <what>`; an empty list is a pass.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, ClassVar, Final

_ANNOTATIONS: Final = frozenset(
    ["$schema", "$id", "title", "description", "$comment", "$defs", "default", "examples"]
)
_VALIDATING: Final = frozenset(
    [
        "type", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum", "required",
        "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "oneOf",
        "anyOf", "allOf", "$ref",
    ]
)  # fmt: skip


class SchemaChecker:
    """Check a JSON value against one of Cordon's schemas."""

    TYPES: ClassVar[dict[str, tuple[type, ...]]] = {
        "object": (dict,),
        "array": (list,),
        "string": (str,),
        "integer": (int,),
        "number": (int, float),
        "boolean": (bool,),
        "null": (type(None),),
    }

    @classmethod
    def errors(
        cls, schema: Mapping[str, Any], value: Any, *, root: Mapping[str, Any] | None = None
    ) -> list[str]:
        """Every way `value` violates `schema` (`root` is the document `$ref`s point into)."""
        found: list[str] = []
        cls._check(schema, value, "$", root if root is not None else schema, found)
        return found

    @classmethod
    def unknown_keywords(cls, schema: Any, path: str = "$") -> list[str]:
        """The keywords in a schema this checker does not read: a schema must be wholly understood."""
        if not isinstance(schema, Mapping):
            return []
        found = [
            f"{path}: unknown keyword {key!r}"
            for key in schema
            if key not in _VALIDATING and key not in _ANNOTATIONS
        ]
        for key in ("properties", "$defs"):
            for name, sub in (schema.get(key) or {}).items():
                found += cls.unknown_keywords(sub, f"{path}.{name}")
        for key in ("items", "additionalProperties"):
            found += cls.unknown_keywords(schema.get(key), f"{path}.{key}")
        for key in ("oneOf", "anyOf", "allOf"):
            for index, sub in enumerate(schema.get(key) or ()):
                found += cls.unknown_keywords(sub, f"{path}.{key}[{index}]")
        return found

    # -- the checks ------------------------------------------------------------------------------

    @classmethod
    def _check(
        cls,
        schema: Mapping[str, Any],
        value: Any,
        path: str,
        root: Mapping[str, Any],
        out: list[str],
    ) -> None:
        if "$ref" in schema:
            cls._check(cls._resolve(schema["$ref"], root), value, path, root, out)
        if not cls._type_ok(schema.get("type"), value):
            out.append(f"{path}: expected {schema['type']}, got {type(value).__name__}")
            return
        cls._values(schema, value, path, out)
        if isinstance(value, dict):
            cls._object(schema, value, path, root, out)
        if isinstance(value, list):
            cls._array(schema, value, path, root, out)
        for key in ("allOf", "anyOf", "oneOf"):
            if key in schema:
                cls._combined(key, schema[key], value, path, root, out)

    @classmethod
    def _values(cls, schema: Mapping[str, Any], value: Any, path: str, out: list[str]) -> None:
        if "enum" in schema and value not in schema["enum"]:
            out.append(f"{path}: {value!r} is not one of {schema['enum']}")
        if "const" in schema and value != schema["const"]:
            out.append(f"{path}: expected {schema['const']!r}")
        if isinstance(value, str):
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                out.append(f"{path}: does not match {schema['pattern']}")
            if len(value) < schema.get("minLength", 0):
                out.append(f"{path}: shorter than {schema['minLength']}")
            if len(value) > schema.get("maxLength", len(value)):
                out.append(f"{path}: longer than {schema['maxLength']}")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(f"{path}: below {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                out.append(f"{path}: above {schema['maximum']}")

    @classmethod
    def _object(
        cls,
        schema: Mapping[str, Any],
        value: dict[str, Any],
        path: str,
        root: Mapping[str, Any],
        out: list[str],
    ) -> None:
        for name in schema.get("required", ()):
            if name not in value:
                out.append(f"{path}: missing {name!r}")
        properties = schema.get("properties", {})
        for name, sub in properties.items():
            if name in value:
                cls._check(sub, value[name], f"{path}.{name}", root, out)
        extra = schema.get("additionalProperties", True)
        for name in value:
            if name in properties:
                continue
            if extra is False:
                out.append(f"{path}: unexpected {name!r}")
            elif isinstance(extra, Mapping):
                cls._check(extra, value[name], f"{path}.{name}", root, out)

    @classmethod
    def _array(
        cls,
        schema: Mapping[str, Any],
        value: list[Any],
        path: str,
        root: Mapping[str, Any],
        out: list[str],
    ) -> None:
        if len(value) < schema.get("minItems", 0):
            out.append(f"{path}: fewer than {schema['minItems']} items")
        if len(value) > schema.get("maxItems", len(value)):
            out.append(f"{path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems") and len({repr(item) for item in value}) != len(value):
            out.append(f"{path}: items are not unique")
        if "items" in schema:
            for index, item in enumerate(value):
                cls._check(schema["items"], item, f"{path}[{index}]", root, out)

    @classmethod
    def _combined(
        cls,
        key: str,
        subs: list[Mapping[str, Any]],
        value: Any,
        path: str,
        root: Mapping[str, Any],
        out: list[str],
    ) -> None:
        passing = 0
        for sub in subs:
            trial: list[str] = []
            cls._check(sub, value, path, root, trial)
            if not trial:
                passing += 1
            elif key == "allOf":
                out.extend(trial)
        if key == "anyOf" and passing == 0:
            out.append(f"{path}: matches none of the alternatives")
        if key == "oneOf" and passing != 1:
            out.append(f"{path}: matches {passing} of the alternatives, not exactly one")

    @classmethod
    def _type_ok(cls, expected: Any, value: Any) -> bool:
        if expected is None:
            return True
        names = [expected] if isinstance(expected, str) else list(expected)
        for name in names:
            if name == "integer" and isinstance(value, bool):
                continue
            if name == "number" and isinstance(value, bool):
                continue
            if isinstance(value, cls.TYPES[name]) and not (
                name != "boolean" and isinstance(value, bool)
            ):
                return True
        return False

    @staticmethod
    def _resolve(reference: str, root: Mapping[str, Any]) -> Mapping[str, Any]:
        if not reference.startswith("#/$defs/"):
            raise ValueError(f"{reference!r}: only #/$defs/<name> references are read")
        resolved: Mapping[str, Any] = root["$defs"][reference.removeprefix("#/$defs/")]
        return resolved


__all__ = ["SchemaChecker"]
