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
from typing import TYPE_CHECKING

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
from cordon_scanner.detect.code.obfuscation.concealment import (
    DIRECTIONAL_CONTROL,
    NON_DIRECTIONAL_INVISIBLE,
    ConcealmentFindings,
)
from cordon_scanner.detect.code.obfuscation.encoding import EncodingFindings
from cordon_scanner.detect.code.obfuscation.findings import ObfuscationFinding
from cordon_scanner.detect.code.obfuscation.packing import PackingFindings
from cordon_scanner.detect.code.obfuscation.text import Hit

BIDI_AND_INVISIBLE = re.compile(
    DIRECTIONAL_CONTROL.pattern + rb"|" + NON_DIRECTIONAL_INVISIBLE.pattern
)
"""Either kind, for callers that only ask whether a file carries one at all."""


class ObfuscationDetector(BaseDetector):
    """Reports content that was deliberately made unreadable."""

    id = ObfuscationFinding.DETECTOR
    # 0.2.0: a file that names the attack it contains, or carries a lone quoted
    # control character, reports it at LOW; and generated output is ceilinged.
    # 0.5.0: a directional control in a file that is itself right-to-left text is
    # ordering that text, even when the string it sits in holds only placeholders.
    # 0.6.0: a third party's minified library is ceilinged like other material this
    # repository did not write.
    version = "0.6.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.BIDI.001",
                title="Bidirectional or invisible Unicode in source",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "This file contains characters that change how text is displayed without "
                    "changing what is compiled or interpreted. Source that reads one way to a "
                    "reviewer and runs another way is the whole of the attack."
                ),
                references=(references.TROJAN_SOURCE, references.HOMOGLYPH),
                remediation="Remove the control characters. Source should read as it runs.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.TAG_SMUGGLING.001",
                title="Invisible text written in Unicode Tag characters",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "Text written in Unicode Tag characters is invisible to a reader and legible to "
                    "a language model: the ASCII-smuggling form of prompt injection."
                ),
                references=(references.HOMOGLYPH,),
                remediation="Remove the characters, and find out how they were introduced.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.PACKED.001",
                title="Packer or minifier signature in hand-written source",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "A packer's output signature appears in a file that is not build output. "
                    "Packing exists to make code unreadable until it runs, which in a source "
                    "tree removes the review that source is there to receive."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Ship the readable source and generate the packed form at build time.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.ENCODED.001",
                title="Large encoded blob embedded in source",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "A long encoded literal sits inside source. The bytes are not code until "
                    "something decodes them, so they pass through review as a string and become "
                    "whatever they are at runtime."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Store binary data as a file, not as a literal.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.LONGLINE.001",
                title="Line far longer than any hand-written source",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "One line is longer than hand-written source runs to, in a file that does "
                    "not look like build output. A payload appended to a source file is very "
                    "often a single long line, because that keeps it off-screen in a diff."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Exclude generated bundles, or configure scan.minified.",
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        hits: list[Hit] = []
        hits.extend(ConcealmentFindings.bidi(content, unit.language))
        hits.extend(ConcealmentFindings.tag_smuggling(content))
        hits.extend(EncodingFindings.escapes(content))
        hits.extend(PackingFindings.packers(content, unit.language))
        long_lines = list(PackingFindings.long_lines(content, ctx, unit.language))
        # Padding is the stronger reading of the same line: a long line is often a bundle, code
        # after six hundred spaces never is. When both fire the padded one is reported, so the
        # entry-point and install grading see it (review 98: gluestack's `react-native-aria`
        # releases appended their payload after 630 spaces in `lib/commonjs/index.js`, the
        # package's `main`, and were reported LOW as a long line).
        offscreen = list(ConcealmentFindings.offscreen_code(content, unit.language)) or list(
            ConcealmentFindings.below_screen_code(content, unit.language)
        )
        hits.extend(offscreen or long_lines)

        return [ObfuscationFinding.finding(hit, unit, ctx) for hit in hits]

    # -- Signals ---------------------------------------------------------

    # -- Construction ----------------------------------------------------

    """A package description's value, keyword or dict entry: the README a build tool inlined."""


__all__ = ["BIDI_AND_INVISIBLE", "ObfuscationDetector"]
