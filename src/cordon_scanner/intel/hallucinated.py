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

from cordon_scanner.intel.advisories import DATA_DIR, tampered_files, user_sync_dir

HALLUCINATED_NAME: Final = "hallucinated.json"


@dataclass(frozen=True)
class Hallucination:
    ecosystem: str
    name: str
    intended: str
    note: str


def _normalise(ecosystem: str, name: str) -> str:
    lowered = name.lower()
    return lowered.replace("_", "-").replace(".", "-") if ecosystem == "pypi" else lowered


def _read(path) -> tuple[str, dict[tuple[str, str], Hallucination]] | None:  # type: ignore[no-untyped-def]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    found: dict[tuple[str, str], Hallucination] = {}
    for ecosystem, names in (document.get("entries") or {}).items():
        for name, entry in (names or {}).items():
            if isinstance(entry, dict):
                key = (ecosystem, _normalise(ecosystem, name))
                found[key] = Hallucination(
                    ecosystem, name, str(entry.get("intended", "")), str(entry.get("note", ""))
                )
    return str(document.get("generated", "")), found


@cache
def catalogue() -> dict[tuple[str, str], Hallucination]:
    candidates = []
    with contextlib.suppress(OSError):
        synced = _read(user_sync_dir() / HALLUCINATED_NAME)
        if synced is not None:
            candidates.append(synced)
    if HALLUCINATED_NAME not in tampered_files():
        bundled = _read(DATA_DIR / HALLUCINATED_NAME)
        if bundled is not None:
            candidates.append(bundled)
    return max(candidates, key=lambda c: c[0])[1] if candidates else {}


def lookup(ecosystem: str, name: str) -> Hallucination | None:
    return catalogue().get((ecosystem, _normalise(ecosystem, name)))


def reset_cache() -> None:
    catalogue.cache_clear()


__all__ = ["HALLUCINATED_NAME", "Hallucination", "catalogue", "lookup", "reset_cache"]
