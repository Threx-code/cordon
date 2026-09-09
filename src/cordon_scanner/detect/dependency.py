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

from collections import Counter
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.models import (
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
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.popular import PackageIntel

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.ecosystems.base import Ecosystem

MAX_EDIT_DISTANCE = 2
# Combosquatting -- a name that wraps a popular one, like `python-requests-oauth`
# -- was implemented here and has been removed. It cannot be made precise
# offline. `fast-glob`, `is-glob`, `neo-async`, `typescript-eslint` and
# `click-plugins` are all legitimate and structurally identical to a squat, and
# the rule produced a hundred and ninety-three findings against Vue's lockfile
# alone. Separating the two needs to know who publishes each package and how
# widely it is installed, which is registry data a scan does not have and must
# not fetch by default.
#
# Left as data because the affix list still documents the convention that made
# the rule unworkable.
CONVENTIONAL_AFFIXES = (
    "@types/",
    "types-",
    "eslint-plugin-",
    "eslint-config-",
    "babel-plugin-",
    "babel-preset-",
    "rollup-plugin-",
    "vite-plugin-",
    "webpack-plugin-",
    "postcss-",
    "stylelint-config-",
    "gatsby-plugin-",
    "pytest-",
    "django-",
    "flask-",
    "sphinx-",
    "setuptools-",
    "jupyter-",
    "opentelemetry-",
)
"""Prefixes that are an ecosystem's own naming standard.

`eslint-plugin-react` wraps a popular name because that is what the plugin is
*for*, and the convention is what tells a user where to look for one. Flagging
these would report a large fraction of every JavaScript and Python project and
teach the reader that this rule means nothing."""

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


MIN_LENGTH_FOR_SUFFIX_SLIP = 6
"""Below this length, a name with one extra trailing character is treated as a
different package rather than a typo of a shorter one.

Short names are where companion packages live: `vue`/`vuex`, `debug`/`debugs`,
`react`/`reacts`. Above it, a trailing character is far more often a squat --
`requestss` is nobody's companion library."""


class DependencyDetector(BaseDetector):
    """Analyses the resolved dependency graph."""

    _NORMALISED_CACHE: ClassVar[dict[str, frozenset[str]]] = {}
    """Popular sets under each ecosystem's own normalisation, built on demand."""

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
                id="SUSPECT.DEPENDENCY.CONFUSION.001",
                title="Internal package name resolved from a public registry",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=DependencyDetector.id,
                remediation=(
                    "Pin the package to the internal registry, or publish a "
                    "placeholder on the public one to hold the name."
                ),
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

    @staticmethod
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
                if longer[:index] + longer[index + 1 :] != shorter:
                    continue

                # A doubled character is a slip: `expresss`, `reactt`. The
                # keyboard produced it.
                if index > 0 and longer[index] == longer[index - 1]:
                    return True

                # A single character appended to a short, established name is
                # not a slip -- it is how ecosystems name companion packages.
                # `vuex` is the official Vue state library and `debugs`,
                # `reacts`, `axioss` sit in the same shape. Both branches here
                # used to `return True`, so the comment described a distinction
                # the code did not make, and 5 of 19 well-known npm packages
                # tested were flagged as squats of their neighbours.
                trailing_on_short_name = (
                    index == len(longer) - 1 and len(shorter) <= MIN_LENGTH_FOR_SUFFIX_SLIP
                )
                return not trailing_on_short_name

        return False

    @staticmethod
    def _homoglyph(a: str, b: str) -> bool:
        return (a, b) in _HOMOGLYPHS

    @staticmethod
    def _strip_separators(name: str) -> str:
        return name.replace("-", "").replace("_", "").replace(".", "")

    @staticmethod
    def fold_confusables(name: str) -> str:
        """Map non-ASCII look-alikes to the Latin letters they resemble.

        A package named with a Cyrillic `a` is a different package from one
        named with an ASCII `a`, and no reader can tell them apart. Folding
        before comparison means the two collapse to the same string, so the
        substituted name is measured against what it is pretending to be.
        """
        if name.isascii():
            return name
        return "".join(_CONFUSABLES.get(ch, ch) for ch in name)

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

        mirrors = self._configured_mirrors(unit.dependencies)
        findings: list[Finding] = []
        for dependency in unit.dependencies:
            findings.extend(self._check(dependency, unit, ctx, mirrors))
        return findings

    @staticmethod
    def _configured_mirrors(dependencies: tuple[Dependency, ...]) -> frozenset[str]:
        """Hosts that serve most of the graph, and are therefore the registry.

        A dependency resolved from an unexpected host is worth reporting. Every
        dependency resolved from the *same* unexpected host is a configured
        mirror or an internal feed, which is a deployment fact rather than an
        anomaly -- .NET's runtime repository resolves 219 packages through one
        Azure Artifacts feed, and reporting each of them says the same thing 219
        times.

        The interesting case survives: one package from somewhere else, among
        many from the registry, still stands out. That is the shape of a
        substituted dependency, and it is exactly what a per-host majority does
        not absorb.
        """
        MIRROR_SHARE = 0.5
        MIN_TO_JUDGE = 8

        hosts = Counter(
            DependencyDetector._host(dependency.resolved_from or "")
            for dependency in dependencies
            if dependency.resolved_from
        )
        total = sum(hosts.values())
        if total < MIN_TO_JUDGE:
            return frozenset()
        return frozenset(host for host, count in hosts.items() if count >= total * MIRROR_SHARE)

    def _check(
        self,
        dep: Dependency,
        unit: GraphUnit,
        ctx: ScanContext,
        mirrors: frozenset[str] = frozenset(),
    ) -> Iterable[Finding]:
        ecosystem = EcosystemRegistry.get(dep.ecosystem)
        if ecosystem is None:
            return

        normalized = ecosystem.normalize_name(dep.name)

        # A package that exists in the known set is not a typosquat of itself.
        if PackageIntel.is_known_package(dep.ecosystem, normalized):
            return

        yield from self._confusion_finding(dep, ecosystem, ctx)

        target = self._typosquat_target(dep.ecosystem, normalized)
        if target:
            yield self._finding(
                rule_id="SUSPECT.DEPENDENCY.TYPOSQUAT.001",
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
                # A confusable substitution is not a near miss and is not
                # deniable: a Cyrillic character is not adjacent to anything on
                # a keyboard, so it was chosen. Reported at high confidence and
                # with a message that says what actually happened, because
                # calling it a typing slip would understate it to the reader who
                # has to decide.
                confidence=(Confidence.HIGH if not dep.name.isascii() else Confidence.MEDIUM),
                title=(
                    "Dependency name uses look-alike characters"
                    if not dep.name.isascii()
                    else "Dependency name closely resembles a popular package"
                ),
                message=(
                    (
                        f"{dep.name!r} renders like {target!r}, a widely used "
                        f"{dep.ecosystem} package, but is spelled with non-ASCII "
                        f"look-alike characters. No reader can tell the two apart, "
                        f"and no keyboard produces this by accident."
                    )
                    if not dep.name.isascii()
                    else (
                        f"{dep.name!r} is one plausible typing slip away from "
                        f"{target!r}, a widely used {dep.ecosystem} package, and is "
                        f"not itself a known package. Registering a near-miss name "
                        f"and waiting for the mistyped install is one of the cheapest "
                        f"ways to get code onto developer machines."
                    )
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

        if (
            dep.resolved_from
            and not ecosystem.is_registry_host(dep.resolved_from)
            and DependencyDetector._host(dep.resolved_from) not in mirrors
        ):
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

    # -- Dependency confusion --------------------------------------------

    def _confusion_finding(
        self, dep: Dependency, ecosystem: Ecosystem, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A name reserved for an internal package, served from a public one.

        The attack needs no typo and no social engineering. A resolver asked
        for `@acme/utils` consults every configured registry and takes the
        highest version, so publishing `@acme/utils` publicly at version 99.0.0
        wins against an internal 1.2.3 without anybody making a mistake.

        This is the one check here that cannot be derived from the repository.
        Whether `@acme/utils` is supposed to come from somewhere private is a
        fact about the organisation, not about the code, so it is configured --
        and until it is, the check stays off rather than guessing.
        """
        namespaces = ctx.config.internal_namespaces
        if not namespaces:
            return

        if not any(dep.name.startswith(prefix) for prefix in namespaces):
            return

        # Resolved from somewhere private is the whole point of declaring the
        # namespace, so that case is correct and silent.
        host = DependencyDetector._host(dep.resolved_from or "")
        from_public = bool(dep.resolved_from) and ecosystem.is_registry_host(dep.resolved_from)

        if dep.resolved_from and not from_public:
            return

        where = (
            f"the public {dep.ecosystem} registry"
            if from_public
            else "no internal registry this lockfile records"
        )
        yield self._finding(
            rule_id="SUSPECT.DEPENDENCY.CONFUSION.001",
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Internal package name resolved from a public registry",
            message=(
                f"{dep.name!r} is in a namespace this project declares internal, "
                f"but resolves from {where}. A resolver asked for this name takes "
                f"the highest version any configured registry offers, so a public "
                f"package under an internal name is installed in preference to the "
                f"real one without anybody making a mistake."
            ),
            remediation=(
                f"Pin {dep.name!r} to the internal registry explicitly, and publish a "
                f"placeholder under the same name on the public registry so nobody "
                f"else can claim it."
            ),
            dep=dep,
            ctx=ctx,
            detail=f"{dep.name} <- {host or 'unpinned'}",
        )

    # -- Typosquatting ---------------------------------------------------

    @staticmethod
    def _popular_normalised(ecosystem: str) -> frozenset[str]:
        """The popular set under the ecosystem's own name normalisation.

        Both sides of a name comparison have to be normalised the same way, and
        one of them was not. The set is written as each project spells itself --
        `serde_json` with an underscore -- while a dependency arrives
        normalised, which for Cargo folds underscore to hyphen. So `serde-json`
        was compared against `serde_json`, and since this detector treats `-`
        and `_` as adjacent keys, the result was that `serde_json` is one
        plausible typing slip away from `serde_json`.

        Cached per ecosystem: the sets are small and fixed, and normalising them
        on every dependency would repeat the same work for every entry in a
        lockfile.
        """
        cached = DependencyDetector._NORMALISED_CACHE.get(ecosystem)
        if cached is not None:
            return cached

        popular = PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
        implementation = EcosystemRegistry.get(ecosystem)
        if implementation is None:
            normalised = frozenset(popular)
        else:
            normalised = frozenset(implementation.normalize_name(name) for name in popular)
        DependencyDetector._NORMALISED_CACHE[ecosystem] = normalised
        return normalised

    def _typosquat_target(self, ecosystem: str, name: str) -> str | None:
        """The popular package this name might be a slip for, if any.

        All three conditions must hold. Returning None is the common and correct
        outcome, and the function is written to reach it quickly.
        """
        if len(name) < MIN_NAME_LENGTH:
            return None

        popular = self._popular_normalised(ecosystem)
        if not popular or name in popular:
            return None

        # A name that is not ASCII, and that becomes a popular package once its
        # look-alike characters are folded to Latin, is not a typing slip. A
        # Cyrillic `a` is not next to anything on a keyboard; it was chosen. So
        # this is checked before the distance comparison and reported whatever
        # the edit distance says, including zero -- which is the usual case and
        # the one the slip check rejects, because after folding the two strings
        # are identical.
        if not name.isascii():
            folded = DependencyDetector.fold_confusables(name)
            if folded != name and folded in popular:
                return folded

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


_ASCII_HOMOGLYPHS = (("l", "1"), ("o", "0"), ("i", "l"), ("rn", "m"), ("vv", "w"))
"""Pairs that look alike in most fonts, within ASCII."""

_CONFUSABLES = {
    # Cyrillic
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j",
    "\u04bb": "h",
    "\u0455": "s",
    "\u04cf": "l",
    "\u0491": "r",
    # Greek
    "\u03bf": "o",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03c1": "p",
    "\u03c5": "u",
    "\u03bd": "v",
    "\u03ba": "k",
    "\u0399": "i",
    "\u039f": "o",
    # Fullwidth Latin
    **{chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)},
}
"""Non-ASCII characters that render as a Latin letter.

The other half of the Trojan Source paper, and a live npm technique: a package
named with a Cyrillic `\u0430` is a different package from one named with an
ASCII `a`, and no reader can tell them apart. `BIDI_AND_INVISIBLE` in the
obfuscation detector covers reordering controls well; this covers substitution.
"""

_HOMOGLYPHS = frozenset(
    {pair for a, b in _ASCII_HOMOGLYPHS for pair in ((a, b), (b, a))}
    | set(_CONFUSABLES.items())
    | {(latin, glyph) for glyph, latin in _CONFUSABLES.items()}
)


__all__ = ["DependencyDetector"]
