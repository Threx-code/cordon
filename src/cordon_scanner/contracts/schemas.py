"""The JSON schemas of Cordon's contracts, shipped with the scanner (design spec 7.2).

One file per predicate type, in `contracts/schemas/`: the in-toto statement that wraps them, and
`scan/v1`, `decision/v1`, `intel-match/v1`, `review/v1`, `approval/v1` and `inventory/v1`. A consumer
(the backend, the console, a customer's pipeline) validates against these files, never against a copy.
`Statements.validate` checks a whole statement: its envelope, then its predicate against the schema its
`predicateType` names.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from typing import Any, ClassVar, Final

from cordon_scanner.contracts.schema_check import SchemaChecker

PREDICATE_PREFIX: Final = "https://cordonscan.com/"


class ContractSchemas:
    """Load the schemas of the contracts."""

    NAMES: ClassVar[tuple[str, ...]] = (
        "statement-v1",
        "scan-v1",
        "decision-v1",
        "intel-match-v1",
        "review-v1",
        "approval-v1",
        "inventory-v1",
    )

    @classmethod
    def load(cls, name: str) -> dict[str, Any]:
        """The schema called `name` (`decision-v1`)."""
        if name not in cls.NAMES:
            raise KeyError(f"{name!r} is not a contract schema")
        text = (
            resources.files("cordon_scanner.contracts")
            .joinpath(f"schemas/{name}.json")
            .read_text("utf-8")
        )
        loaded: dict[str, Any] = json.loads(text)
        return loaded

    @classmethod
    def for_predicate(cls, predicate_type: str) -> dict[str, Any]:
        """The schema of a predicate type URL (`https://cordonscan.com/decision/v1`)."""
        if not predicate_type.startswith(PREDICATE_PREFIX):
            raise KeyError(f"{predicate_type!r} is not a Cordon predicate type")
        return cls.load(predicate_type.removeprefix(PREDICATE_PREFIX).replace("/", "-"))

    @classmethod
    def problems(cls) -> list[str]:
        """What is wrong with the shipped schemas: a keyword the checker does not read."""
        return [
            problem
            for name in cls.NAMES
            for problem in SchemaChecker.unknown_keywords(cls.load(name))
        ]


class Statements:
    """Validate an in-toto statement against the envelope schema and its predicate's schema."""

    @staticmethod
    def validate(statement: Mapping[str, Any]) -> list[str]:
        found = SchemaChecker.errors(ContractSchemas.load("statement-v1"), statement)
        if found:
            return found
        schema = ContractSchemas.for_predicate(statement["predicateType"])
        return SchemaChecker.errors(schema, statement["predicate"], root=schema)


__all__ = ["ContractSchemas", "Statements"]
