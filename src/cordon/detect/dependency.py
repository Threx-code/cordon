"""Dependency-graph analysis.

This detector reasons about the resolved graph rather than about any file, which
is what makes it able to see the attack nobody else can: a malicious transitive
dependency appears in no diff and in no file the developer wrote.

Typosquat detection is where tools in this space generate most of their false
positives, so the design is deliberately conservative. Three independent
conditions must all hold before a name is flagged:

1. It is close to a popular package under that ecosystem's own name
   normalisation rules.
2. The difference is a plausible *typing* mistake, not merely a short edit
   distance. ``react`` and ``preact`` differ by one character and are unrelated
   projects; ``expres`` and ``express`` differ by one character and one of them
   does not exist for a good reason.
3. The candidate is not itself a known package.

Requiring all three costs some recall. That trade is made knowingly: a
typosquat check that fires on legitimate packages gets the whole detector
disabled, at which point recall is zero.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon.core.models import (
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon.core.scoring import ScoringContext
from cordon.detect.base import BaseDetector, DetectorRequirements, GraphUnit, ScanContext
from cordon.detect.catalogue import DeclaredRule
from cordon.ecosystems.registry import EcosystemRegistry
from cordon.intel.popular import PackageIntel

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit

MAX_EDIT_DISTANCE = 2
MIN_NAME_LENGTH = 4
"""Short names are excluded from typosquat comparison.

Below four characters, edit distance stops carrying information: almost every
short name is within two edits of some other short name, so the check produces
noise rather than signal.
"""

# Keys adjacent on a QWERTY keyboard. A substitution between adjacent keys is a
# typing slip; a substitution between distant keys is more likely a different
# word, which is what separates `expres` from `preact`.
ADJACENT = {
    "q": "wa",
    "w": "qeas",
    "e": "wrsd",
    "r": "etdf",
    "t": "ryfg",
    "y": "tugh",
    "u": "yihj",
    "i": "uojk",
    "o": "ipkl",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
    "-": "_.",
    "_": "-.",
    ".": "-_",
}


class DependencyDetector(BaseDetector):
    """Analyses the resolved dependency graph."""

    @staticmethod
    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.TYPOSQUAT.001",
                title="Dependency name is one edit from a popular package",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=DependencyDetector.id,
                remediation="Confirm the name against the registry before installing.",
            ),
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.SOURCE.001",
                title="Dependency resolved from an unexpected source",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=DependencyDetector.id,
                remediation="Pin the dependency to the registry, or vendor it deliberately.",
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.INTEGRITY.001",
                title="Dependency has no integrity hash",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector=DependencyDetector.id,
                remediation="Regenerate the lockfile with integrity hashes enabled.",
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.SOURCE.001",
                title="Dependency declared from a non-registry source",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector=DependencyDetector.id,
                remediation="Prefer registry releases, which are immutable and auditable.",
            ),
        )

    def _damerau_levenshtein(a: str, b: str, limit: int) -> int:
        """Edit distance including transposition, bounded by ``limit``.

        Transposition is included because it is one of the most common typing
        errors and a plain Levenshtein distance counts it as two edits, which pushes
        real slips such as ``recieve`` for ``receive`` outside the threshold.

        Bounded so a long pair costs no more than the limit allows.
        """
        if abs(len(a) - len(b)) > limit:
            return limit + 1

        previous_previous: list[int] = []
        previous = list(range(len(b) + 1))

        for i, ca in enumerate(a, 1):
            current = [i] + [0] * len(b)
            best = current[0]
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                current[j] = min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + cost,
                )
                if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb and previous_previous:
                    current[j] = min(current[j], previous_previous[j - 2] + 1)
                best = min(best, current[j])
            if best > limit:
                return limit + 1
            previous_previous, previous = previous, current

        return previous[-1]

    @staticmethod
    def _is_plausible_slip(name: str, target: str) -> bool:
        """Whether the difference looks like a typing mistake.

        This is the condition that separates a squat from an unrelated package with
        a similar name. Recognised slips:

        * a doubled or dropped character
        * a transposition of neighbours
        * a substitution between keys adjacent on the keyboard
        * a separator swapped for another separator
        * a well-known homoglyph substitution
        * an added or removed common prefix or suffix

        Anything else is treated as a different word. ``preact`` versus ``react`` is
        an added prefix that is a real, distinct project, so the known-package check
        that runs before this one is what keeps it quiet.
        """
        if name == target:
            return False

        # Separator-only difference: the same name with hyphens and underscores or
        # dots swapped. Registries treat these as distinct while humans do not.
        if DependencyDetector._strip_separators(name) == DependencyDetector._strip_separators(
            target
        ):
            return True

        if len(name) == len(target):
            differences = [i for i, (x, y) in enumerate(zip(name, target, strict=False)) if x != y]
            if len(differences) == 1:
                index = differences[0]
                typed, intended = name[index], target[index]
                if typed in ADJACENT.get(intended, ""):
                    return True
                if DependencyDetector._homoglyph(typed, intended):
                    return True
            if len(differences) == 2:
                i, j = differences
                if j == i + 1 and name[i] == target[j] and name[j] == target[i]:
                    return True  # transposition

        if abs(len(name) - len(target)) == 1:
            longer, shorter = (name, target) if len(name) > len(target) else (target, name)
            for index in range(len(longer)):
                if longer[:index] + longer[index + 1 :] == shorter:
                    # A dropped or doubled character. A doubled one is a slip; a
                    # dropped one that leaves a real word is usually not.
                    if index > 0 and longer[index] == longer[index - 1]:
                        return True
                    return True

        return False

    @staticmethod
    def _homoglyph(a: str, b: str) -> bool:
        return (a, b) in _HOMOGLYPHS

    @staticmethod
    def _strip_separators(name: str) -> str:
        return name.replace("-", "").replace("_", "").replace(".", "")

    @staticmethod
    def _host(url: str) -> str:
        if "://" not in url:
            return url[:60]
        return url.split("://", 1)[1].split("/", 1)[0]

    id = "dependency"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY})
    requires = DetectorRequirements(content=False, dependencies=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies)

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()

        findings: list[Finding] = []
        for dependency in unit.dependencies:
            findings.extend(self._check(dependency, unit, ctx))
        return findings

    def _check(self, dep: Dependency, unit: GraphUnit, ctx: ScanContext) -> Iterable[Finding]:
        ecosystem = EcosystemRegistry.get(dep.ecosystem)
        if ecosystem is None:
            return

        normalized = ecosystem.normalize_name(dep.name)

        # A package that exists in the known set is not a typosquat of itself.
        if PackageIntel.is_known_package(dep.ecosystem, normalized):
            return

        target = self._typosquat_target(dep.ecosystem, normalized)
        if target:
            yield self._finding(
                rule_id="SUSPECT.DEPENDENCY.TYPOSQUAT.001",
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="Dependency name closely resembles a popular package",
                message=(
                    f"{dep.name!r} is one plausible typing slip away from {target!r}, "
                    f"a widely used {dep.ecosystem} package, and is not itself a known "
                    f"package. Registering a near-miss name and waiting for the "
                    f"mistyped install is one of the cheapest ways to get code onto "
                    f"developer machines."
                ),
                remediation=(
                    f"Confirm {dep.name!r} is the package that was intended. If it is "
                    f"a typo, correct it and treat any machine that installed it as "
                    f"having run untrusted code."
                ),
                dep=dep,
                ctx=ctx,
                detail=f"{dep.name} ~ {target}",
            )

        if dep.resolved_from and not ecosystem.is_registry_host(dep.resolved_from):
            yield self._finding(
                rule_id="SUSPECT.DEPENDENCY.SOURCE.001",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="Dependency resolved from outside the registry",
                message=(
                    f"{dep.name}@{dep.version} resolves from {DependencyDetector._host(dep.resolved_from)} "
                    f"rather than the {dep.ecosystem} registry, so advisory matching "
                    f"and release-age policy do not apply to it."
                ),
                remediation=(
                    "Confirm the host is one the organisation controls, or mirror the "
                    "package into an internal registry."
                ),
                dep=dep,
                ctx=ctx,
                detail=dep.resolved_from,
            )

        # Same reasoning as the lockfile detector: a dependency resolved from
        # outside the registry has no registry hash to carry, and is already
        # reported by the provenance rule above.
        if not dep.integrity and dep.version and ecosystem.is_registry_host(dep.resolved_from):
            yield self._finding(
                rule_id="POLICY.DEPENDENCY.INTEGRITY.001",
                category=Category.POLICY,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                title="Resolved dependency has no integrity hash",
                message=(
                    f"{dep.name}@{dep.version} is pinned by version but carries no "
                    f"hash, so nothing verifies that the content served for that "
                    f"version is the content that was reviewed."
                ),
                remediation="Regenerate the lockfile so every entry carries a hash.",
                dep=dep,
                ctx=ctx,
                detail=f"{dep.name}@{dep.version}",
            )

    # -- Typosquatting ---------------------------------------------------

    def _typosquat_target(self, ecosystem: str, name: str) -> str | None:
        """The popular package this name might be a slip for, if any.

        All three conditions must hold. Returning None is the common and correct
        outcome, and the function is written to reach it quickly.
        """
        if len(name) < MIN_NAME_LENGTH:
            return None

        popular = PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
        if not popular or name in popular:
            return None

        for candidate in popular:
            if abs(len(candidate) - len(name)) > MAX_EDIT_DISTANCE:
                continue
            distance = DependencyDetector._damerau_levenshtein(name, candidate, MAX_EDIT_DISTANCE)
            if distance == 0 or distance > MAX_EDIT_DISTANCE:
                continue
            if DependencyDetector._is_plausible_slip(name, candidate):
                return candidate
        return None

    # -- Construction ----------------------------------------------------

    def _finding(
        self,
        *,
        rule_id: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: str,
        message: str,
        remediation: str,
        dep: Dependency,
        ctx: ScanContext,
        detail: str,
    ) -> Finding:
        risk = ctx.scorer.score(
            severity,
            confidence,
            ScoringContext(
                dependency_depth=dep.depth,
                is_direct_dependency=dep.direct,
                scope=dep.scope,
            ),
        )
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(
                # The lockfile that declared it, then the project directory.
                # Never empty: an empty URI is dropped by GitHub code scanning,
                # which made the entire dependency layer invisible there.
                path=dep.declared_in or dep.project or ".",
                package=dep.purl,
                project=dep.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(dep.purl.encode()),
                redaction=RedactionMode.NONE,
                metadata=(
                    ("purl", dep.purl),
                    ("depth", str(dep.depth)),
                    ("scope", str(dep.scope)),
                    ("detail", detail),
                ),
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=title,
                matched_rule=rule_id,
                escalations=(
                    ("declared directly in this project's manifest",)
                    if dep.direct
                    else (f"reached transitively, {dep.depth} hop(s) deep",)
                ),
            ),
            risk=risk,
            detector=self.id,
        )


# ---------------------------------------------------------------------------
# Name-similarity helpers
# ---------------------------------------------------------------------------


_HOMOGLYPHS = frozenset({("l", "1"), ("1", "l"), ("o", "0"), ("0", "o"), ("i", "l"), ("l", "i")})


__all__ = ["DependencyDetector"]
