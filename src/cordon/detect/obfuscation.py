"""Obfuscation detection.

Obfuscation is not itself malicious, and this detector never claims it is. What
it reports is that content was deliberately made unreadable, which is
information regardless of intent: source code has no defensive reason to hide
from the person reviewing it, and an author who wanted a reviewer not to
understand something is worth a moment's attention.

Four signals, each with a distinct false-positive profile, which is why they are
separate rules rather than one score:

**Escape runs.** Long sequences of ``\\xNN`` or ``\\uNNNN`` that spell ordinary
ASCII. There is no reason to write a string that way except to keep it out of a
search.

**Bidirectional and invisible characters.** Source that renders differently from
how it compiles. A reviewer approves what they see; the compiler acts on what is
there.

**Extreme line length.** A payload appended to a file is very often one long
line, because that keeps it off-screen in a diff. This needs calibration against
minified bundles, which are legitimately made of long lines, so entropy and file
type both gate it.

**Packer signatures.** Recognisable output from known obfuscators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon.core.models import (
    Capability,
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
from cordon.core.redact import build_evidence, shannon_entropy
from cordon.core.scoring import ScoringContext
from cordon.core.walker import _path_matches
from cordon.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit

# Bidirectional overrides and zero-width characters, as UTF-8 byte sequences.
# Matched as bytes so no decoding is required and no encoding surprise applies.
#
# These are the "Trojan Source" family: text that renders in one order and
# compiles in another, so a reviewer approves something different from what the
# compiler sees.
BIDI_AND_INVISIBLE = re.compile(
    rb"\xe2\x80[\x8b-\x8f\xaa-\xae]"  # ZWSP, ZWNJ, ZWJ, LRM, RLM, LRO, RLO, PDF
    rb"|\xe2\x81[\xa6-\xa9]"  # LRI, RLI, FSI, PDI
    rb"|\xef\xbb\xbf(?!\A)"  # BOM anywhere but the start
    rb"|\xef\xbf\xb9|\xef\xbf\xba|\xef\xbf\xbb"  # interlinear annotation marks
)

ESCAPE_RUN = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}")

CHAR_CODE_RUN = re.compile(rb"(?:String\.fromCharCode|chr)\s*\(\s*\d+(?:\s*,\s*\d+){7,}")

PACKERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "Dean Edwards packer",
        re.compile(rb"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e"),
    ),
    ("obfuscator.io", re.compile(rb"_0x[0-9a-f]{4,6}\s*[,;=\[]")),
    ("hex identifier obfuscation", re.compile(rb"\b_\$_[0-9a-fA-F]{3,}")),
    ("JSFuck", re.compile(rb"\[\]\[\s*[\"'@]?\s*(?:filter|constructor)")),
    (
        "large encoded blob into a dynamic constructor",
        re.compile(rb"(?:new\s+)?Function\s*\(\s*[\"'][A-Za-z0-9+/=]{200,}"),
    ),
)

# Minified output is legitimately long-lined, so length alone must not fire on
# it. These paths are exempt from the length rule only; every other rule still
# applies, because a payload committed inside a vendored bundle is exactly the
# thing worth finding.
MINIFIED_PATHS = ("**/*.min.js", "**/*.min.css", "**/*.map", "**/*.bundle.js")

LONG_LINE_THRESHOLD = 2000
ENTROPY_THRESHOLD = 4.5


@dataclass(frozen=True, slots=True)
class _Hit:
    rule_id: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    start: int
    end: int


class ObfuscationDetector(BaseDetector):
    """Reports content that was deliberately made unreadable."""

    id = "obfuscation"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        hits: list[_Hit] = []
        hits.extend(self._bidi(content))
        hits.extend(self._escapes(content))
        hits.extend(self._packers(content))
        hits.extend(self._long_lines(content))

        return [self._finding(hit, unit, ctx) for hit in hits]

    # -- Signals ---------------------------------------------------------

    def _bidi(self, content) -> Iterable[_Hit]:
        match = BIDI_AND_INVISIBLE.search(content.raw)
        if not match:
            return
        yield _Hit(
            rule_id="SUSPECT.OBFUSCATION.BIDI.001",
            title="Bidirectional or invisible characters in source",
            message=(
                "This file contains characters that change how text is displayed "
                "without changing what it means to a compiler. Source that renders "
                "differently from how it executes defeats review directly: the "
                "reviewer approves what they see, and the compiler acts on what is "
                "there."
            ),
            remediation=(
                "Remove the control characters. If a right-to-left language is "
                "genuinely required in a string, use explicit escapes so the "
                "characters are visible in review."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            start=match.start(),
            end=match.end(),
        )

    def _escapes(self, content) -> Iterable[_Hit]:
        for pattern, label in (
            (ESCAPE_RUN, "escape sequences"),
            (CHAR_CODE_RUN, "character codes"),
        ):
            match = pattern.search(content.raw)
            if not match:
                continue
            yield _Hit(
                rule_id="SUSPECT.OBFUSCATION.ENCODED.001",
                title=f"String built from a long run of {label}",
                message=(
                    f"A string here is written as a long run of {label} rather than "
                    f"as text. That has no benefit for readability or correctness; "
                    f"its only effect is that the resulting value does not appear in "
                    f"the file and cannot be found by searching for it."
                ),
                remediation=(
                    "Write the string as text. If the value must not be readable in "
                    "source, it is a secret and belongs in a secret store."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                start=match.start(),
                end=match.end(),
            )
            return  # one encoding finding per file is enough to make the point

    def _packers(self, content) -> Iterable[_Hit]:
        for label, pattern in PACKERS:
            match = pattern.search(content.raw)
            if not match:
                continue
            yield _Hit(
                rule_id="SUSPECT.OBFUSCATION.PACKED.001",
                title=f"Output of an obfuscator ({label})",
                message=(
                    f"This file matches the output shape of {label}. Obfuscated code "
                    f"cannot be reviewed, so whatever it does is outside every "
                    f"process that depends on reading it."
                ),
                remediation=(
                    "Obtain the original source and review that. If the file is a "
                    "vendored build artefact, build it from source that is reviewed."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                start=match.start(),
                end=match.end(),
            )
            return

    def _long_lines(self, content) -> Iterable[_Hit]:
        """Report an extremely long line, with the minified case excluded.

        Length alone is a weak signal and a strong irritant: minified bundles
        are entirely made of long lines. So the rule applies to source-shaped
        files only, and requires high entropy as well, since ordinary long lines
        (a data table, a long string) are far more repetitive than a payload.
        """
        if any(_path_matches(content.path, p) for p in MINIFIED_PATHS):
            return
        if content.truncated:
            return  # the longest line cannot be known from a prefix

        if content.longest_line <= LONG_LINE_THRESHOLD:
            return

        index, length = self._longest_line_index(content)
        if index is None:
            return

        text = content.line_text(index)
        if shannon_entropy(text[:4000]) < ENTROPY_THRESHOLD:
            return

        start = content.line_starts[index - 1]
        yield _Hit(
            rule_id="SUSPECT.OBFUSCATION.LONGLINE.001",
            title="Very long high-entropy line in a source file",
            message=(
                f"Line {index} is {length} characters of high-entropy content in a "
                f"file that is not minified output. A payload appended to a source "
                f"file is very often a single long line, because that keeps it "
                f"off-screen in a diff and out of a reviewer's eye."
            ),
            remediation=(
                "Read the line. If it is generated or vendored, move it into a "
                "build artefact so it is not reviewed as source."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            start=start,
            end=min(start + 200, len(content.raw)),
        )

    @staticmethod
    def _longest_line_index(content) -> tuple[int | None, int]:
        longest = 0
        index: int | None = None
        starts = content.line_starts
        for i, start in enumerate(starts, 1):
            end = starts[i] if i < len(starts) else len(content.raw)
            length = end - start
            if length > longest:
                longest, index = length, i
        return index, longest

    # -- Construction ----------------------------------------------------

    def _finding(self, hit: _Hit, unit: FileUnit, ctx: ScanContext) -> Finding:
        content = unit.content
        return Finding(
            rule_id=hit.rule_id,
            category=Category.SUSPICIOUS,
            severity=hit.severity,
            confidence=hit.confidence,
            message=hit.message,
            location=Location(
                path=content.path,
                line=content.line_of(hit.start),
                column=content.column_of(hit.start),
                byte_start=hit.start,
                byte_end=hit.end,
                project=unit.project,
            ),
            evidence=build_evidence(content, hit.start, hit.end, RedactionMode.MASKED)
            if hit.rule_id != "SUSPECT.OBFUSCATION.BIDI.001"
            else Evidence(
                # A bidi snippet would render in the report exactly as it renders
                # in the editor, which is the problem being reported. Only the
                # position and the hash are emitted.
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.slice(hit.start, hit.end)),
                redaction=RedactionMode.HASH_ONLY,
                span=(hit.start, hit.end),
            ),
            remediation=hit.remediation,
            explanation=Explanation(summary=hit.title, matched_rule=hit.rule_id),
            risk=ctx.scorer.score(
                hit.severity,
                hit.confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    is_obfuscated=True,
                    capabilities=frozenset({Capability.DECODE}),
                ),
            ),
            detector=self.id,
            capabilities=(Capability.DECODE,),
        )


__all__ = ["ObfuscationDetector"]
