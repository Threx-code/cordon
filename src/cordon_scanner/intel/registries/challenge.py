"""A registry's authentication challenge (`WWW-Authenticate: Bearer realm="...",service="..."`), read
by every registry client that answers one. Imports no registry module, so each of them reads it
without importing one another (architecture audit F3)."""

from __future__ import annotations

import re
from typing import ClassVar


class Challenge:
    """The `name="value"` fields of a challenge."""

    #: Anchored at a word's start, so a long word with no `=` after it is not rescanned from every
    #: position: linear, and the same fields as `(\w+)="([^"]*)"`.
    FIELD: ClassVar[re.Pattern[str]] = re.compile(r'(?<!\w)(\w+)="([^"]*)"')

    @staticmethod
    def fields(challenge: str) -> dict[str, str]:
        """The challenge's fields, a later one of a name replacing an earlier."""
        return dict(Challenge.FIELD.findall(challenge))
