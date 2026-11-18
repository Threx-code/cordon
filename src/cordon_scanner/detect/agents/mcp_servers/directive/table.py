"""The table of `detect/data/mcp-directives.json`: the classes of order and trick that no honest MCP
server writes into the text it hands the agent, and the one rule each gives on each surface.

Kept apart from the reader (`directives.py`) because the rule catalogue builds its rules from this
table, and the reader reads the catalogue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths

#: The surfaces a text reaches the agent on (`surfaces.py`), in the order a finding lists them.
SURFACES: Final = (
    "description",
    "schema",
    "result",
    "error",
    "notification",
    "resource",
    "prompt",
)
#: What a rule id calls each surface, where the plain name is not it.
_TOKEN: Final = {"notification": "LOG"}


@dataclass(frozen=True, slots=True)
class DirectiveClass:
    """One class of the table: how it is phrased, what it does, why it matters, whether it blocks
    alone (`block`) or only beside another class in the same text (`signal`), and its role: a `cover`
    hides, excuses or frames (conceal, claim consent, replace the instructions), an `act` makes the model
    do something (call a tool on a key file, send data, write into memory)."""

    id: str
    strength: str
    role: str
    surfaces: tuple[str, ...]
    does: str
    why: str
    patterns: tuple[re.Pattern[str], ...]
    example: str
    control: str


class DirectiveTable:
    @staticmethod
    @OneOff.cache
    def _load() -> tuple[dict[str, str], tuple[DirectiveClass, ...]]:
        data = ScannedJson.loads(
            (PackagePaths.data("detect") / "mcp-directives.json").read_text(encoding="utf-8")
        )
        names = {str(key): str(value) for key, value in data["surfaces"].items()}
        classes = []
        for row in data["classes"]:
            listed = row["surfaces"]
            classes.append(
                DirectiveClass(
                    id=str(row["id"]),
                    strength=str(row["strength"]),
                    role=str(row["role"]),
                    surfaces=SURFACES if listed == "all" else tuple(str(s) for s in listed),
                    does=str(row["does"]),
                    why=str(row["why"]),
                    patterns=tuple(re.compile(str(p), re.IGNORECASE) for p in row["patterns"]),
                    example=str(row["example"]),
                    control=str(row["control"]),
                )
            )
        return names, tuple(classes)

    @staticmethod
    def classes() -> tuple[DirectiveClass, ...]:
        return DirectiveTable._load()[1]

    @staticmethod
    def surface_name(surface: str) -> str:
        """How a surface is said in a sentence: `a tool result`."""
        return DirectiveTable._load()[0][surface]

    @staticmethod
    def rule_id(surface: str, directive: str) -> str:
        """`SUSPECT.MCP.RESULT_OVERRIDE.001`: the rule for one class on one surface."""
        token = _TOKEN.get(surface, surface.upper())
        return f"SUSPECT.MCP.{token}_{directive.upper()}.001"

    @staticmethod
    def rule_ids() -> tuple[str, ...]:
        """Every rule the table gives, class by class."""
        return tuple(
            DirectiveTable.rule_id(surface, directive.id)
            for directive in DirectiveTable.classes()
            for surface in directive.surfaces
        )


__all__ = ["SURFACES", "DirectiveClass", "DirectiveTable"]
