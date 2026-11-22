"""The extension of a file's name: one reading, so the scan that counts files and the facts export that classes them agree."""

from __future__ import annotations

import re
from typing import Final

_EXTENSION: Final = re.compile(r"\.([a-z0-9]{1,8})$")
OTHER: Final = "other"
"""A dotted name whose last part is not a short plain extension (a long one, one with other characters)."""


class FileExtension:
    @staticmethod
    def of(path: str) -> str:
        """The lower-cased extension of the path's last part (after the last `!` of an archive member path and the last `/`):
        empty when the name has no dot or only a leading one (`.env`, `Makefile`), `other` when what follows the last dot is not
        short and plain, else the extension itself."""
        base = path.rsplit("!", 1)[-1].rsplit("/", 1)[-1].lower()
        dot = base.rfind(".")
        if dot <= 0:
            return ""
        match = _EXTENSION.search(base)
        return match.group(1) if match else OTHER
