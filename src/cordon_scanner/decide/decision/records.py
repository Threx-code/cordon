"""The base of the decision library's frozen records: JSON in, JSON out, and strict about both.

Every type of the library (`ArtifactRef`, `Context`, `EvidenceSet`, `Decision`, ...) has `to_json()` and
`from_json()`; the JSON keys are the field names, so a consumer in another language reads the same shape.
`from_json` refuses a key the type does not have and a missing required field, naming the type: a typo
in a request must not become a default.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
from datetime import UTC, datetime
from typing import Any, ClassVar, Self


class DecisionError(ValueError):
    """A request or a record that is not well formed; the message names the record and the field."""


class PolicyError(DecisionError):
    """A policy source that cannot be compiled, or a compiled policy that was altered; the message names the path."""


class JsonRecord:
    """Mixin for frozen dataclasses: `to_json` and `from_json` over the fields, nested records included."""

    __slots__ = ()

    #: field name -> the record class held there (a tuple field holds a tuple of them).
    NESTED: ClassVar[Mapping[str, type[JsonRecord]]] = {}

    def to_json(self) -> dict[str, Any]:
        """The record as plain JSON values: tuples as lists, nested records as objects, `None` left out."""
        out: dict[str, Any] = {}
        for item in fields(self):  # type: ignore[arg-type]  # a dataclass by use
            value = getattr(self, item.name)
            if value is not None:
                out[item.name] = self._dump(value)
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Self:
        """The record of `data`; unknown keys and missing required fields are errors."""
        if not isinstance(data, Mapping):
            raise DecisionError(f"{cls.__name__}: expected an object, got {type(data).__name__}")
        known = {item.name for item in fields(cls)}  # type: ignore[arg-type]
        extra = sorted(set(data) - known)
        if extra:
            raise DecisionError(f"{cls.__name__}: unexpected field {extra[0]!r}")
        values: dict[str, Any] = {}
        for name, value in data.items():
            nested = cls.NESTED.get(name)
            if nested is not None and value is not None:
                value = (
                    tuple(nested.from_json(item) for item in value)
                    if isinstance(value, (list, tuple))
                    else nested.from_json(value)
                )
            elif isinstance(value, list):
                value = tuple(value)
            values[name] = value
        try:
            return cls(**values)
        except TypeError as problem:
            raise DecisionError(f"{cls.__name__}: {problem}") from problem

    @classmethod
    def _dump(cls, value: Any) -> Any:
        if isinstance(value, JsonRecord):
            return value.to_json()
        if isinstance(value, (tuple, list)):
            return [cls._dump(item) for item in value]
        return value


class Checks:
    """The checks the records share in `__post_init__`."""

    @staticmethod
    def one_of(record: str, field: str, value: object, allowed: tuple[str, ...]) -> None:
        if value not in allowed:
            raise DecisionError(f"{record}.{field}: {value!r} is not one of {', '.join(allowed)}")

    @staticmethod
    def text(record: str, field: str, value: object) -> None:
        if not isinstance(value, str) or not value:
            raise DecisionError(f"{record}.{field}: expected a non-empty string")

    @staticmethod
    def strings(record: str, field: str, value: object) -> None:
        if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
            raise DecisionError(f"{record}.{field}: expected a list of strings")

    @staticmethod
    def whole(
        record: str, field: str, value: object, *, low: int = 0, high: int | None = None
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < low:
            raise DecisionError(f"{record}.{field}: expected a whole number of at least {low}")
        if high is not None and value > high:
            raise DecisionError(f"{record}.{field}: expected at most {high}")


class Instants:
    """Times in the library are UTC; text is ISO 8601 ending in `Z`."""

    @staticmethod
    def parse(text: str) -> datetime:
        """An ISO 8601 instant as an aware UTC datetime; a time without a zone is refused."""
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as problem:
            raise DecisionError(f"{text!r} is not an ISO 8601 time") from problem
        if moment.tzinfo is None:
            raise DecisionError(f"{text!r} has no time zone")
        return moment.astimezone(UTC)

    @staticmethod
    def text(moment: datetime) -> str:
        """`moment` as `2026-11-17T08:00:00Z` (whole seconds, UTC)."""
        if moment.tzinfo is None:
            raise DecisionError("a time without a zone")
        return moment.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def bucket(moment: datetime, seconds: int) -> datetime:
        """`moment` truncated to the start of its `seconds`-long bucket (UTC, from the epoch)."""
        if seconds < 1:
            raise DecisionError("a clock bucket is at least one second")
        stamp = int(moment.astimezone(UTC).timestamp())
        return datetime.fromtimestamp(stamp - stamp % seconds, tz=UTC)


__all__ = ["Checks", "DecisionError", "Instants", "JsonRecord", "PolicyError"]
