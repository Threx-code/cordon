"""An install hook that runs a file no content detector can read (review 98 P4-E, shape B).

`metaplex` and `catwrestlinghuman` set `postinstall: node <file>`, and that file is JSFuck, or a
line of kana / `_0x` identifiers -- dense enough that every content detector finds nothing in it.
The hook is then recorded at LOW on the premise that the scanner read the target and graded it
elsewhere; it did not. This detector runs on the target file itself -- it has the content, and
`ScanContext.install_hook_paths` tells it the file runs at install -- and blocks when both hold.
Measured on the npm study half (review 98): 3 of 1,923 malicious units caught by nothing else, and
0 of 11,255 benign npm units.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, Unit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
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

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext

OBFUSCATED_HOOK_RULE = "SUSPECT.INSTALL.OBFUSCATED_HOOK.001"

#: A character a line is "dense with" when it is this far from readable source: outside ASCII
#: (kana and other identifier scripts) or a `_0x`-prefixed hex name (the hex-identifier packers).
_DENSE_IDENTIFIER = re.compile(r"[^\x00-\x7f]|_0x[0-9a-f]{3,}")


class ObfuscatedHookDetector(BaseDetector):
    """An install-hook target whose own bytes are too obfuscated for any content detector to read."""

    id = "obfuscated-hook"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    @staticmethod
    def dense(text: str) -> bool:
        """JSFuck-dense -- at least 60% of the characters in `[]()!+`, over 2,000 of them -- or a
        line over 2,000 characters that is mostly non-ASCII or `_0x` identifiers."""
        if len(text) > 2000 and sum(text.count(c) for c in "[]()!+") / len(text) >= 0.6:
            return True
        return any(
            len(line) > 2000 and len(_DENSE_IDENTIFIER.findall(line)) > len(line) / 50
            for line in text.splitlines()
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.install_hook_paths)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=OBFUSCATED_HOOK_RULE,
                title="An install hook runs a file too obfuscated to read",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscatedHookDetector.id,
                message=(
                    "An install hook in this package runs a file whose content is packed beyond "
                    "reading -- JSFuck, or a line of kana or hex-name identifiers -- so it runs "
                    "code on every install that no reviewer and no content scan can see. A "
                    "legitimate package ships install code that can be read."
                ),
                references=(references.NPM_LIFECYCLE,),
                remediation=(
                    "Do not install it. Obtain the package from a source that ships readable "
                    "install code, or vendor a reviewed build."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        content = unit.content
        # The deobfuscated copies the engine lifts (`#deobfuscated.js`) are skipped: the coverage
        # gap is in the file as it ships, read at the hook target the installer actually runs.
        if (
            content.path not in ctx.install_hook_paths
            or "#" in content.path
            or content.is_binary
            or not self.dense(content.text)
        ):
            return ()
        return (
            Finding(
                rule_id=OBFUSCATED_HOOK_RULE,
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message=(
                    f"{content.path} runs from an install hook and is packed beyond reading "
                    f"(JSFuck, or a line of kana or hex-name identifiers): code runs on every "
                    f"install that no reviewer and no content detector here can read."
                ),
                remediation=(
                    "Do not install it. Obtain the package from a source that ships readable "
                    "install code."
                ),
                location=Location(path=content.path, project=unit.project),
                evidence=Evidence(
                    kind=EvidenceKind.HASH,
                    match_hash=Evidence.hash_bytes(
                        f"{OBFUSCATED_HOOK_RULE}:{content.path}".encode()
                    ),
                    redaction=RedactionMode.NONE,
                ),
                explanation=Explanation(
                    summary="an install hook runs an unreadable file",
                    matched_rule=OBFUSCATED_HOOK_RULE,
                ),
                risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                detector=self.id,
                references=(references.NPM_LIFECYCLE,),
            ),
        )
