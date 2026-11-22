"""The capability detector's pattern-tier hits, worked out once per distinct whole file.

A package can carry the same file many times -- vendored copies, a bundle under several names --
and the pattern tier's hits depend on a file's bytes, the rules selected for it and its language
alone. They are kept by `analysis.shared.content_memo`, keyed by the bytes' digest, the language
and the selected rules themselves (by identity, held while the entry is kept). A window of a
larger file, or a file cut short, is matched every time: its line numbers are its own.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.analysis.shared.content_memo import ContentMemo, Same

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class CapabilityMemo:
    """`Labelling.match_capabilities`, through the memo."""

    MATCHES: ClassVar[ContentMemo] = ContentMemo()

    @staticmethod
    def hits(
        labelling: Any, content: FileContent, candidates: tuple[Any, ...], language: str | None
    ) -> list[Any]:
        def work() -> list[Any]:
            found: list[Any] = labelling.match_capabilities(content, candidates, language)
            return found

        if content.window_of is not None or content.truncated or content.streamed is not None:
            return work()
        return CapabilityMemo.MATCHES.get(
            ("capabilities", language, Same(candidates)), content.raw, work
        )


__all__ = ["CapabilityMemo"]


class LabelledNames:
    """The capability names the detector's own pass found in the file a worker is inspecting, kept for that worker's
    facts (`engine/isolation/analysis_facts.py`, fact `cap.all`) so every file's names reach the package-scope rules
    and the facts export without labelling the file a second time.

    One entry: a worker inspects one file at a time, and the windows of an oversized file are joined (each window's
    names are added to the file's). `take` empties it, so a name never carries over to the next file."""

    _last: ClassVar[tuple[str, frozenset[str]] | None] = None

    @staticmethod
    def remember(path: str, names: frozenset[str]) -> None:
        last = LabelledNames._last
        if last is not None and last[0] == path:
            names = last[1] | names
        LabelledNames._last = (path, names)

    @staticmethod
    def take(path: str) -> frozenset[str]:
        last, LabelledNames._last = LabelledNames._last, None
        return last[1] if last is not None and last[0] == path else frozenset()


class DestinationHosts:
    """The URL hosts a file names, as salted digests (never the name): what the learning loop's shared-infrastructure
    correlation reads. A host is the authority of an http(s), ws(s) or ftp URL written in the
    file; its domain is its last two labels (an address is its own domain). At most `MAX` of each per file."""

    _URL: ClassVar[re.Pattern[str]] = re.compile(r"(?i)\b(?:https?|wss?|ftp)://([a-z0-9.-]{1,253})")
    _LABEL: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
    SALT: Final = "cordon-host:"
    MAX: Final = 32

    @staticmethod
    def digest(name: str) -> str:
        return hashlib.sha256((DestinationHosts.SALT + name).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def of(text: str) -> tuple[frozenset[str], frozenset[str]]:
        """(host digests, domain digests) of the URLs the text names."""
        hosts: set[str] = set()
        for match in DestinationHosts._URL.finditer(text):
            host = match.group(1).lower().strip(".")
            labels = host.split(".")
            if len(labels) < 2 or not all(
                DestinationHosts._LABEL.fullmatch(label) for label in labels
            ):
                continue
            hosts.add(host)
            if len(hosts) >= DestinationHosts.MAX:
                break
        domains = {
            h if all(label.isdigit() for label in h.split(".")) else ".".join(h.split(".")[-2:])
            for h in hosts
        }
        return frozenset(map(DestinationHosts.digest, hosts)), frozenset(
            map(DestinationHosts.digest, domains)
        )


class LabelledHosts:
    """The destination digests of the file a worker is inspecting, kept for its facts (`net.host`, `net.domain`) the
    way `LabelledNames` keeps capability names: one entry, windows joined, emptied by `take`."""

    _last: ClassVar[tuple[str, frozenset[str], frozenset[str]] | None] = None

    @staticmethod
    def remember(path: str, hosts: frozenset[str], domains: frozenset[str]) -> None:
        last = LabelledHosts._last
        if last is not None and last[0] == path:
            hosts, domains = last[1] | hosts, last[2] | domains
        LabelledHosts._last = (path, hosts, domains)

    @staticmethod
    def take(path: str) -> tuple[frozenset[str], frozenset[str]]:
        last, LabelledHosts._last = LabelledHosts._last, None
        return (
            (last[1], last[2])
            if last is not None and last[0] == path
            else (frozenset(), frozenset())
        )
