"""Package names AI coding assistants invent, which someone has registered or could.

An assistant asked for a library suggests a name that sounds right; a share of those names do not
exist, and the same invented names recur across prompts and models. Registering one is
slopsquatting: the package installs for everyone who follows the suggestion. The list is small,
documented case by case, digest-pinned with the other bundled intel, and grows through the signed
intel feed -- a newer copy in the user sync directory takes precedence over the bundled one.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from functools import cache
from typing import Final

from cordon_scanner.intel.advisories import DATA_DIR, AdvisoryFiles

HALLUCINATED_NAME: Final = "hallucinated.json"


@dataclass(frozen=True)
class Hallucination:
    ecosystem: str
    name: str
    intended: str
    note: str


class HallucinatedPackages:
    """Package names language models are known to invent."""

    @staticmethod
    def _normalise(ecosystem: str, name: str) -> str:
        lowered = name.lower()
        return lowered.replace("_", "-").replace(".", "-") if ecosystem == "pypi" else lowered

    @staticmethod
    def _read(path) -> tuple[str, dict[tuple[str, str], Hallucination]] | None:  # type: ignore[no-untyped-def]
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        found: dict[tuple[str, str], Hallucination] = {}
        for ecosystem, names in (document.get("entries") or {}).items():
            for name, entry in (names or {}).items():
                if isinstance(entry, dict):
                    key = (ecosystem, HallucinatedPackages._normalise(ecosystem, name))
                    found[key] = Hallucination(
                        ecosystem, name, str(entry.get("intended", "")), str(entry.get("note", ""))
                    )
        return str(document.get("generated", "")), found

    @staticmethod
    @cache
    def catalogue() -> dict[tuple[str, str], Hallucination]:
        candidates = []
        with contextlib.suppress(OSError):
            trusted = AdvisoryFiles.trusted_user_file(HALLUCINATED_NAME)
            synced = HallucinatedPackages._read(trusted) if trusted is not None else None
            if synced is not None:
                candidates.append(synced)
        if HALLUCINATED_NAME not in AdvisoryFiles.tampered_files():
            bundled = HallucinatedPackages._read(DATA_DIR / HALLUCINATED_NAME)
            if bundled is not None:
                candidates.append(bundled)
        return max(candidates, key=lambda c: c[0])[1] if candidates else {}

    @staticmethod
    def lookup(ecosystem: str, name: str) -> Hallucination | None:
        return HallucinatedPackages.catalogue().get(
            (ecosystem, HallucinatedPackages._normalise(ecosystem, name))
        )

    @staticmethod
    def reset_cache() -> None:
        HallucinatedPackages.catalogue.cache_clear()


__all__ = ["HALLUCINATED_NAME", "HallucinatedPackages", "Hallucination"]
