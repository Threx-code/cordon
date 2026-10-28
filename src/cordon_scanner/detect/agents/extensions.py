"""Editor extensions: their ids, versions and lookalikes, and the malicious ones OSV records."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    pass


class ExtensionVerdicts:
    """An extension id (and version, when known) against OSV's malicious extension records.

    Shared by every place an extension can be named: a repository's recommendations, a vendored
    .vsix, and the extensions installed on a machine (`cloud.device`). Returns the rule and a
    sentence, or None.
    """

    @staticmethod
    def osv(identifier: str, version: str | None) -> tuple[str, str] | None:
        from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

        database = AdvisoryDatabase.bundled()
        records = [a for a in database.for_package("vscode", identifier) if a.malicious]
        if not records:
            return None
        ids = ", ".join(sorted({a.identifier for a in records if a.identifier})[:3])
        if version:
            if any(a.affects(version) for a in records):
                return (
                    "MALWARE.EXTENSION.KNOWN.001",
                    f"this release is recorded as malicious ({ids}).",
                )
            return None
        # "Every release" only when a record's range takes in the very first version and nothing
        # closes it. Several records are legitimate, widely installed extensions that had specific
        # releases compromised (a publisher's account or pipeline taken over); naming one of those
        # without a version is not naming a malicious release.
        if any(
            a.is_range and a.affects("0.0.0") and not (a.fixed or a.last_affected) for a in records
        ):
            return (
                "MALWARE.EXTENSION.KNOWN.001",
                f"every release is recorded as malicious ({ids}).",
            )
        named = sorted({v for a in records for v in a.versions})[:5]
        return (
            "SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001",
            f"no version is named, and releases {', '.join(named) or 'of it'} are recorded as "
            f"malicious ({ids}).",
        )


class ExtensionNames:
    """Editor extension ids, versions and lookalikes."""

    #: Characters that render as nothing: zero-width, joiners, word joiner, BOM, Tag characters.
    INVISIBLE: ClassVar[re.Pattern[str]] = re.compile(
        "[\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\u00ad\u180e\U000e0000-\U000e007f]"
    )
    #: Letters a publisher name swaps for ones that read the same in a sans-serif font.
    _CONFUSABLE: ClassVar[tuple[tuple[str, str], ...]] = (
        ("rn", "m"),
        ("vv", "w"),
        ("0", "o"),
        ("1", "l"),
        ("i", "l"),
        ("|", "l"),
    )

    @classmethod
    def _folded(cls, text: str) -> str:
        """`text` as a reader sees it: case folded, look-alike letters made one."""
        folded = text.lower()
        for a, b in cls._CONFUSABLE:
            folded = folded.replace(a, b)
        return re.sub(r"[\s_.-]+", "", folded)

    @classmethod
    def imitated(
        cls, identifier: str, display: str, entries: list[str], popular: set[str]
    ) -> tuple[str, str] | None:
        """(popular id, how) when an extension presents itself as a popular one it is not."""
        publisher, _, name = identifier.partition(".")
        by_publisher: dict[str, set[str]] = {}
        for candidate in popular:
            other_publisher, _, _ = candidate.partition(".")
            by_publisher.setdefault(other_publisher, set()).add(candidate)
        if publisher not in by_publisher:
            folded = cls._folded(publisher)
            for other_publisher, ids in sorted(by_publisher.items()):
                if len(other_publisher) >= 5 and cls._folded(other_publisher) == folded:
                    return min(ids), f"its publisher {publisher!r} reads as {other_publisher!r}"
        shown = cls._folded(display)
        # A display name that is the extension's own name ("Git Blame" for `x.git-blame`) is the
        # extension naming itself, whoever else chose the same words (review 98: 3 of 5 benign
        # Open VSX hits); an impersonator shows a name its id does not carry (`soli989`, "solidity").
        if len(shown) >= 5 and shown not in cls._folded(name):
            for candidate in sorted(popular):
                other_publisher, _, other_name = candidate.partition(".")
                if other_publisher != publisher and cls._folded(other_name) == shown:
                    return (
                        candidate,
                        f"its display name {display.strip()!r} is that extension's name",
                    )
        for entry in entries:
            base = re.sub(r"\.(?:bundle|min|web|main)?\.?(?:c|m)?js$", "", entry.rsplit("/", 1)[-1])
            base = re.sub(r"\.(?:bundle|web)$", "", base)
            if len(base) < 6 or base == name:
                continue
            for candidate in sorted(popular):
                other_publisher, _, other_name = candidate.partition(".")
                if other_publisher != publisher and other_name == base.lower():
                    return candidate, f"its entry point {entry!r} is named after that extension"
        return None

    @staticmethod
    def _semver(ref: str) -> tuple[int, int, int] | None:
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", ref)
        return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None

    @staticmethod
    def _extension_lookalike(identifier: str, popular: set[str]) -> str | None:
        """A popular extension this id imitates: the same name under another publisher, or one edit away."""
        publisher, _, name = identifier.partition(".")
        for candidate in sorted(popular):
            other_publisher, _, other_name = candidate.partition(".")
            if (
                len(other_name) >= 5
                and name == other_name
                and publisher != other_publisher
                and ExtensionNames._edit_distance(publisher, other_publisher) <= 2
            ):
                return candidate
            if len(candidate) >= 8 and ExtensionNames._edit_distance(identifier, candidate) == 1:
                return candidate
        return None

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        """Damerau-Levenshtein (adjacent transposition), stopping early past 2."""
        if abs(len(a) - len(b)) > 2:
            return 3
        previous2: list[int] = []
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            current = [i]
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
                if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                    value = min(value, previous2[j - 2] + 1)
                current.append(value)
            if min(current) > 2:
                return 3
            previous2, previous = previous, current
        return previous[-1]


__all__ = ["ExtensionNames", "ExtensionVerdicts"]
