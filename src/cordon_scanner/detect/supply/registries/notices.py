"""Notices a registry attaches to a package -- deprecations, security holds -- read as text a reader
will see: cleaned of control and invisible characters, and dated.
"""

from __future__ import annotations

import re


class RegistryNotices:
    """Publisher-written registry text, made safe to quote, and what it says."""

    MAX_NOTICE = 200
    _CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
    _SECURITY = re.compile(
        r"\b(?:secur\w*|vulnerab\w*|cve-\d{4}-\d+|malicious|malware|compromis\w*|backdoor\w*|exploit\w*)\b",
        re.IGNORECASE,
    )

    @classmethod
    def clean(cls, text: str) -> str:
        """Controls, bidi overrides and zero-width characters out; whitespace collapsed; bounded."""
        flat = " ".join(cls._CONTROL.sub(" ", text).split())
        return flat if len(flat) <= cls.MAX_NOTICE else flat[: cls.MAX_NOTICE - 1] + "\u2026"

    @classmethod
    def cites_security(cls, notice: str) -> bool:
        return bool(cls._SECURITY.search(notice))

    @staticmethod
    def older_than(timestamp: str | None, days: int) -> bool:
        import datetime as _dt

        if not timestamp:
            return False
        try:
            when = _dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.UTC)
        return (_dt.datetime.now(_dt.UTC) - when).days > days


__all__ = ["RegistryNotices"]
