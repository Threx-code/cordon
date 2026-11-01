"""A shipped code file that is, apart from whitespace, a file of earlier malware (item 54).

The shipped `ReuseIndex` holds whitespace-insensitive fingerprints of malware code files, by campaign
group. A code unit whose fingerprint is in it is that campaign's file shipped again:

    a code file's fingerprint in the index  ->  MALWARE.CODE.REUSE.001 (high), naming the group

Only code is fingerprinted: not declaration files (`.d.ts`), source maps, JSON or other data, which
are shared interface text, not behaviour (modelling team's review of note 54). Nothing is read
beyond hashing the unit's own bytes: the whole file, from its spill or its path on disk when only a
prefix is held.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, Unit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.intel.malware.reuse_index import BOM, FLOOR, WHITESPACE, ReuseIndex

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.intel.malware.reuse_index import ReuseGroup

REUSE_RULE = "MALWARE.CODE.REUSE.001"
CHUNK = 1 << 20


class CodeReuseDetector(BaseDetector):
    """Reports a code file whose whitespace-insensitive fingerprint is a known malware file's."""

    id = "code-reuse"
    version = "0.1.0"
    categories = frozenset({Category.MALICIOUS})
    requires = DetectorRequirements(content=True)

    #: Languages that are data, never behaviour; and names of shared interface text.
    NOT_CODE: ClassVar[frozenset[str]] = frozenset({"json", "toml", "xml", "yaml"})
    NOT_CODE_SUFFIXES: ClassVar[tuple[str, ...]] = (".d.ts", ".d.mts", ".d.cts", ".map", ".json")

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=REUSE_RULE,
                title="Code file of an earlier malware campaign",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector=CodeReuseDetector.id,
                message=(
                    "This code file is, apart from whitespace, a file shipped by malware recorded "
                    "earlier: the same campaign's code in another package."
                ),
                remediation=(
                    "Do not install it; compare it with the campaign the finding names, and report the "
                    "package to its registry."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit) or not CodeReuseDetector.is_code(unit):
            return ()
        index, _ = ReuseIndex.shipped()
        if index is None:
            return ()
        digest = CodeReuseDetector.fingerprint(unit)
        if digest is None:
            return ()
        group = index.lookup(digest)
        if group is None:
            return ()
        return (self._finding(unit, ctx, group),)

    @staticmethod
    def is_code(unit: FileUnit) -> bool:
        """A shipped code unit: not derived (a lifted or inline program is ours, not shipped), not
        data, not a declaration file or map."""
        path = unit.content.path
        if "#" in path.rpartition("!")[2] or unit.content.is_binary or unit.language is None:
            return False
        if unit.language in CodeReuseDetector.NOT_CODE:
            return False
        return not path.lower().endswith(CodeReuseDetector.NOT_CODE_SUFFIXES)

    @staticmethod
    def fingerprint(unit: FileUnit) -> bytes | None:
        """`ReuseIndex.fingerprint` over the whole file, streamed: the bytes held when they are all
        of it, else its spill or its file on disk."""
        content = unit.content
        if not content.truncated:
            return ReuseIndex.fingerprint(content.raw)
        if content.streamed is not None:
            return ReuseIndex.fingerprint(content.streamed)
        source = content.spill.path if content.spill is not None else unit.opens
        if source is None:
            return None
        digest, kept, first = hashlib.sha256(), 0, True
        try:
            for chunk in CodeReuseDetector._chunks(source):
                if first and chunk.startswith(BOM):
                    chunk = chunk[len(BOM) :]
                first = False
                body = chunk.translate(None, WHITESPACE)
                kept += len(body)
                digest.update(body)
        except OSError:
            return None
        return digest.digest()[:16] if kept >= FLOOR else None

    @staticmethod
    def _chunks(path: str) -> Iterator[bytes]:
        with Path(path).open("rb") as handle:
            while chunk := handle.read(CHUNK):
                yield chunk

    def _finding(self, unit: FileUnit, ctx: ScanContext, group: ReuseGroup) -> Finding:
        return Finding(
            rule_id=REUSE_RULE,
            category=Category.MALICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message=(
                f"This file is, apart from whitespace, a code file of the malware campaign "
                f"'{group.name}' ({group.packages} packages, first recorded "
                f"{CodeReuseDetector._date(group.earliest)})."
            ),
            remediation=(
                "Do not install it; compare it with the campaign named, and report the package to its "
                "registry."
            ),
            location=Location(path=unit.content.path, line=1, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(
                    f"{REUSE_RULE}:{unit.content.path}:{group.id}".encode()
                ),
                redaction=RedactionMode.NONE,
            ),
            explanation=Explanation(
                summary="a known campaign's code file", matched_rule=REUSE_RULE
            ),
            risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
            detector=self.id,
        )

    @staticmethod
    def _date(days: int) -> str:
        import datetime

        return (datetime.date(1970, 1, 1) + datetime.timedelta(days=days)).isoformat()


__all__ = ["REUSE_RULE", "CodeReuseDetector"]
