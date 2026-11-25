"""The package name and the version an install command names, by the rules of the package manager's ecosystem."""

from __future__ import annotations

import re


class InstallSpec:
    """Reads what follows `npm install` or `pip install`."""

    @staticmethod
    def split(ecosystem: str, spec: str) -> tuple[str, str | None]:
        """The package name and the version the install pins, or no version when it names the latest (or a range)."""
        if ecosystem == "npm":
            name, at, version = spec.rpartition("@")
            return (name, version) if at and name else (spec, None)
        name = re.split(r"(==|>=|<=|~=|!=|<|>|\[)", spec, maxsplit=1)[0]
        pinned = re.search(r"==\s*([A-Za-z0-9.!+_-]+)\s*$", spec)
        return name, pinned.group(1) if pinned else None
