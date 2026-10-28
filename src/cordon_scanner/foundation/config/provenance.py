"""Where each configuration value came from: its layer (built-in, organisation, repository,
command line) and the file, as `config explain` reports them."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class Layer:
    """Where a setting came from. Every effective value records its origin."""

    DEFAULT = "default"
    REPO = "repo"
    ORG = "org"
    CLI = "cli"

    ORDER = (DEFAULT, REPO, ORG, CLI)


@dataclass(frozen=True, slots=True)
class Provenance:
    """One setting's final value and the layer that supplied it.

    Auditability requires that "why is this threshold medium?" be answerable
    without re-deriving the merge by hand.
    """

    key: str
    value: Any
    layer: str
    source: str = ""

    def __str__(self) -> str:
        where = f" ({self.source})" if self.source else ""
        return f"{self.key} = {self.value!r}  [{self.layer}{where}]"


__all__ = ["Layer", "Provenance"]
