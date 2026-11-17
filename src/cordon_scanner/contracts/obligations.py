"""The obligations a decision can carry (design spec 5.1): what the caller must do for an allow to hold.

Registered like the reason codes: stable, documented, never reused (cordon-a0, 2026-11-17). A decision's
`obligations` list holds these codes; a policy rule names the ones its outcome carries.

```
  O001  pin_digest          install only the digest the decision was made for
  O002  log_decision        record the decision and its evidence in the audit log
  O003  notify_owner        tell the owner of the repository or scope
  O004  open_review_ticket  open a review ticket for the allow's conditions
```
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar, Final

_CODE: Final = re.compile(r"O[0-9]{3}")


@dataclass(frozen=True, slots=True)
class Obligation:
    code: str
    name: str
    title: str
    meaning: str


class Obligations:
    """The registry. Never edited in place: a code is added, never changed or removed."""

    ALL: ClassVar[tuple[Obligation, ...]] = (
        Obligation(
            "O001",
            "pin_digest",
            "Pin the digest",
            "install only the digest the decision was made for",
        ),
        Obligation(
            "O002",
            "log_decision",
            "Log the decision",
            "record the decision and its evidence in the audit log",
        ),
        Obligation(
            "O003", "notify_owner", "Notify the owner", "tell the owner of the repository or scope"
        ),
        Obligation(
            "O004",
            "open_review_ticket",
            "Open a review ticket",
            "open a review ticket for the conditions of the allow",
        ),
    )
    RETIRED: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def is_registered(cls, code: str) -> bool:
        return any(entry.code == code for entry in cls.ALL)

    @classmethod
    def lookup(cls, code: str) -> Obligation:
        for entry in cls.ALL:
            if entry.code == code:
                return entry
        raise KeyError(f"{code!r} is not a registered obligation")

    @classmethod
    def problems(cls) -> list[str]:
        """What is wrong with the registry itself; empty when it is sound."""
        found: list[str] = []
        codes: set[str] = set()
        names: set[str] = set()
        for entry in cls.ALL:
            if _CODE.fullmatch(entry.code) is None:
                found.append(f"{entry.code}: not an obligation code")
            if entry.code in codes or entry.name in names:
                found.append(f"{entry.code}: code or name issued twice")
            if entry.code in cls.RETIRED:
                found.append(f"{entry.code}: retired and listed")
            codes.add(entry.code)
            names.add(entry.name)
        return found


__all__ = ["Obligation", "Obligations"]
