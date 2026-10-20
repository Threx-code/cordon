"""Recipes Cordon's feed condemned or holds, matched by the SHA-256 of the recipe file itself.

Homebrew, conan, vcpkg and nix publish a package as a recipe in a git repository -- a formula, a
`conanfile.py`, a `portfile.cmake`, a `.nix` expression -- and their registry "version" is the
commit that changed it. A verdict about one is a verdict about those exact recipe bytes: matched by
name it would condemn every version of `wget`, and by version it would match nothing a project
declares. So the feed pins such a verdict to the analysed file's digest (`digests` on the record),
and this detector hashes each recipe it reads and looks the digest up:

    a confirmed malicious record carries it  ->  MALWARE.RECIPE.KNOWN.001   (critical, blocks)
    a provisional record carries it          ->  SUSPECT.RECIPE.PROVISIONAL.001 (high, paused)

Nothing else is ever matched: a recipe whose bytes differ by one character is another recipe.
Intel, not content -- `.KNOWN` -- so it counts toward the name/provenance bar, never the content bar.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

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

KNOWN_RULE = "MALWARE.RECIPE.KNOWN.001"
PROVISIONAL_RULE = "SUSPECT.RECIPE.PROVISIONAL.001"
MAX_BYTES = 1 << 20


class RecipeDigests:
    """The feed's recipe digests: digest -> (record, provisional)."""

    #: The recipe ecosystems, and the files that are a recipe in each.
    RECIPES: ClassVar[dict[str, re.Pattern[str]]] = {
        "homebrew": re.compile(r"(?:^|/)(?:Formula|Casks|HomebrewFormula)/(?:[^/]+/)?[^/]+\.rb$"),
        "conan": re.compile(r"(?:^|/)conanfile\.py$"),
        "vcpkg": re.compile(r"(?:^|/)ports/[^/]+/(?:portfile\.cmake|vcpkg\.json)$"),
        "nix": re.compile(r"\.nix$"),
        # An MCP bundle: a zip of a server's code, installed by an MCP client from the URL the MCP
        # registry names (`mcpb`). Matched by its bytes, as the backend analysed it.
        "mcp": re.compile(r"\.mcpb$"),
    }

    @staticmethod
    def ecosystem_of(path: str) -> str | None:
        for ecosystem, pattern in RecipeDigests.RECIPES.items():
            if pattern.search(path):
                return ecosystem
        return None

    @staticmethod
    def load(ecosystem: str) -> dict[str, tuple[dict[str, Any], bool]]:
        from cordon_scanner.intel.malware.feed import FeedStore

        index: dict[str, tuple[dict[str, Any], bool]] = {}
        upserts, withdrawn = FeedStore.read_overlay(ecosystem)
        for record in upserts:
            if record.get("malicious") and str(record.get("id")) not in withdrawn:
                for digest in record.get("digests") or ():
                    index[str(digest).lower()] = (record, False)
        for record in FeedStore.read_provisional(ecosystem):
            for digest in record.get("digests") or ():
                index.setdefault(str(digest).lower(), (record, True))
        return index


class RecipeDigestDetector(BaseDetector):
    """Reports a recipe file whose exact bytes Cordon's feed condemned, or holds for review."""

    id = "recipe-digest"
    version = "0.1.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def __init__(self) -> None:
        self._indexes: dict[str, dict[str, tuple[dict[str, Any], bool]]] = {}

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=KNOWN_RULE,
                title="Recipe is a known-malicious release",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.MALICIOUS,
                detector=RecipeDigestDetector.id,
                message=(
                    "This recipe file is byte for byte one Cordon's feed records as malicious: the "
                    "verdict is pinned to the SHA-256 of the analysed recipe, so no other version "
                    "or edit of the package matches it."
                ),
                remediation="Remove the recipe or replace it with a reviewed revision.",
                references=(references.OSV,),
            ),
            DeclaredRule(
                id=PROVISIONAL_RULE,
                title="Recipe is held for review",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=RecipeDigestDetector.id,
                message=(
                    "Cordon's feed holds this exact recipe for review: one signal flagged it and a "
                    "second signal or a person has not yet confirmed or cleared it. It is paused "
                    "until they do; any other revision is unaffected."
                ),
                remediation="Use the previous revision of the recipe until the hold is decided.",
                references=(references.OSV,),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        content = unit.content
        ecosystem = RecipeDigests.ecosystem_of(content.path)
        if ecosystem is None or content.truncated:
            return ()
        # A recipe is text; an MCP bundle is a zip, matched by its bytes whole or not at all.
        if ecosystem == "mcp" and len(content.raw) != content.size:
            return ()
        if ecosystem != "mcp" and (content.is_binary or len(content.raw) > MAX_BYTES):
            return ()
        if ecosystem not in self._indexes:
            try:
                self._indexes[ecosystem] = RecipeDigests.load(ecosystem)
            except (OSError, ValueError):
                self._indexes[ecosystem] = {}
        hit = self._indexes[ecosystem].get(hashlib.sha256(content.raw).hexdigest())
        if hit is None:
            return ()
        record, provisional = hit
        rule = PROVISIONAL_RULE if provisional else KNOWN_RULE
        severity = Severity.HIGH if provisional else Severity.CRITICAL
        confidence = Confidence.HIGH if provisional else Confidence.CONFIRMED
        identifier = str(record.get("id", ""))
        state = "held for review" if provisional else "recorded as malicious"
        return (
            Finding(
                rule_id=rule,
                category=Category.SUSPICIOUS if provisional else Category.MALICIOUS,
                severity=severity,
                confidence=confidence,
                message=(
                    f"{content.path} is the exact {ecosystem} recipe for {record.get('name', '')} that "
                    f"Cordon's feed has {state} ({identifier}). {str(record.get('summary', ''))[:300]}"
                ).strip(),
                remediation=(
                    "Use the previous revision of the recipe until the hold is decided."
                    if provisional
                    else "Remove the recipe or replace it with a reviewed revision."
                ),
                location=Location(path=content.path, project=unit.project),
                evidence=Evidence(
                    kind=EvidenceKind.HASH,
                    match_hash=Evidence.hash_bytes(f"{rule}:{content.path}:{identifier}".encode()),
                    redaction=RedactionMode.NONE,
                ),
                explanation=Explanation(summary=f"a {ecosystem} recipe {state}", matched_rule=rule),
                risk=ctx.scorer.score(severity, confidence),
                detector=self.id,
                references=(references.OSV,),
            ),
        )
