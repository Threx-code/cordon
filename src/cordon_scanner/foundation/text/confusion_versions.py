"""Versions chosen to outrank a private registry's: the dependency-confusion probe's version."""

from __future__ import annotations

import re


class ConfusionVersions:
    """Why a version looks chosen to outrank a private registry's, or None."""

    @staticmethod
    def dated(major: str) -> bool:
        """A major that is a date: `YYYYMM` (202606) or `YYYYMMDD` (20261111). 99999999 is not one:
        it is the all-nines a dependency-confusion probe picks so nothing outranks it."""
        if len(major) not in (6, 8) or not 1990 <= int(major[:4]) <= 2100:
            return False
        if not 1 <= int(major[4:6]) <= 12:
            return False
        return len(major) == 6 or 1 <= int(major[6:8]) <= 31

    @staticmethod
    def reason(version: str) -> str | None:
        """Why this version looks chosen to outrank a private registry's, or None.

        A dependency-confusion probe has to win the resolver's comparison against the internal
        package it imitates, whose version it does not know, so it picks one nobody reaches:
        99.0.0, 999.9.9, 1000.0.0, 99999999.0.0, or a run of one digit (7.7.7, 11.11.11). Calendar
        versions (2024.1.0, 202606.4.3555) are high for a different reason and are not counted.
        """
        found = re.match(r"^v?(\d{1,12})\.(\d{1,12})\.(\d{1,12})", version.strip())
        if found is None:
            return None
        major, minor, patch = (int(x) for x in found.groups())
        calendar = 1990 <= major <= 2100 or ConfusionVersions.dated(found.group(1))
        if major >= 90 and not calendar:
            return f"major version {major}"
        if major == minor == patch and major >= 4:
            return f"version {major}.{major}.{major}"
        if major in (9, 99, 999) and minor in (9, 99, 999):
            return f"version {found.group(0)}"
        return None


__all__ = ["ConfusionVersions"]
