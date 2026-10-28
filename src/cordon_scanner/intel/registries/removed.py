"""Malicious package names the registry no longer serves (`scripts/refresh/refresh_removed_names.py`).

A name whose every version is recorded as malicious, and for which the registry, when the list was
last refreshed, served nothing an install could resolve. A range over such a name cannot install
the malware, only fail; what remains is the risk that someone registers the name again. The
advisory detector reports that instead of a known-malicious dependency.

Plain text, one name per line after the provenance header (Source, Threshold, Fetched,
Refreshed), and shipped with the release like the established-names allowlists beside it. Missing is not an error: every such name then blocks as
before, which is the safe direction for a list that can only lower a block to a warning.
"""

from __future__ import annotations

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.intel.registries.real import DATA_DIR


class RemovedNames:
    @staticmethod
    @OneOff.cache
    def removed(ecosystem: str) -> frozenset[str]:
        try:
            text = (DATA_DIR / f"{ecosystem}.removed.txt").read_text(encoding="utf-8")
        except OSError:
            return frozenset()
        return frozenset(
            line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
        )

    @staticmethod
    @OneOff.cache
    def checked(ecosystem: str) -> str:
        """The date the list was refreshed, as its header records it, or empty."""
        try:
            first = (DATA_DIR / f"{ecosystem}.removed.txt").read_text(encoding="utf-8")
        except OSError:
            return ""
        for line in first.splitlines():
            if line.startswith("# Refreshed:"):
                return line.removeprefix("# Refreshed:").strip()
        return ""


__all__ = ["RemovedNames"]
