"""A delivered pack's warning list: findings of its rules are warnings for one publisher, until a time.

An open appeal holds a rule at warn for the appellant's packages only. The pack's index entry carries `warn`, a list of
`{"ecosystem", "publisher", "until"}` sorted by ecosystem then publisher, and the pack signer's statement carries the same list; the
list is read only when the two are equal (`rules/pack_signatures.py`). For a package of that ecosystem whose publisher key is
listed, until the time, a finding of any rule of the pack is reported as a warning and does not block; for any other publisher the
pack is as before, and after the time the entry has no effect. The publisher key a scanner can compute is the package fallback,
`sha256("package|<ecosystem>|<name>")`; a key it cannot compute cannot match, so the rule stays as it was (towards blocking).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, ClassVar

Warning_ = tuple[str, str, str]
"""`(ecosystem, publisher, until)` as the list carries them."""


class WarnList:
    KEYS: ClassVar[frozenset[str]] = frozenset({"ecosystem", "publisher", "until"})

    @staticmethod
    def publisher_key(ecosystem: str, name: str) -> str:
        return hashlib.sha256(f"package|{ecosystem}|{name}".encode()).hexdigest()

    @staticmethod
    def instant(text: str) -> datetime | None:
        """An ISO 8601 time with an offset, or None when it is not one (no offset is not accepted: a time with no zone is ambiguous)."""
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
        return moment if moment.tzinfo is not None else None

    @classmethod
    def parse(cls, raw: Any) -> tuple[Warning_, ...] | None:
        """The entries of a `warn` list, or None when it is not of the form: a list of exactly the three fields, each a string,
        the time with an offset, sorted by ecosystem then publisher."""
        if not isinstance(raw, list):
            return None
        found: list[Warning_] = []
        for item in raw:
            if not isinstance(item, dict) or set(item) != cls.KEYS:
                return None
            eco, publisher, until = item["ecosystem"], item["publisher"], item["until"]
            if (
                not all(isinstance(v, str) for v in (eco, publisher, until))
                or cls.instant(until) is None
            ):
                return None
            found.append((eco, publisher, until))
        if found != sorted(found, key=lambda e: (e[0], e[1])):
            return None
        return tuple(found)

    @classmethod
    def holds(
        cls, entries: tuple[Warning_, ...], ecosystem: str, name: str, now: datetime | None = None
    ) -> bool:
        """Whether the package of this ecosystem and name is held at warn by one of `entries` at `now`."""
        now = now or datetime.now(UTC)
        key = cls.publisher_key(ecosystem, name)
        for eco, publisher, until in entries:
            moment = cls.instant(until)
            if eco == ecosystem and publisher == key and moment is not None and now < moment:
                return True
        return False


__all__ = ["WarnList"]
