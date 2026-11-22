"""Package-scope composite rules: a conjunction of facts about the whole scanned package (learning loop LL-3).

A file-scope composite asks what one file does. A package-scope composite asks what the package is: "a file nothing
the package runs reaches, which both spawns a process and reaches the network", "an install entry that reads a
credential, in a package with a preinstall hook". Its terms are `rules/fact_terms.py`'s, the same the learning
loop's distiller learns in, so a detector it makes can ship as an ordinary rule in a signed pack.

```
  match:
    kind: composite
    scope: package
    all:    [ {file: {where: unreached, capabilities: [spawn, egress]}} ]
    any:    [ ... ]          at least one, when present
    unless: [ ... ]          none
```

It runs once per scan, after the verdict, over what the rules and the verdict left: each file's capabilities (from
its findings), the places the scan computed (`ScanContext.places`), the package-level findings and the lifecycle
hooks. It adds findings and never lowers, holds or removes one. A suppressed finding is no fact."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from cordon_scanner.foundation.capabilities import MatchKind
from cordon_scanner.foundation.models import (
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
)
from cordon_scanner.foundation.results import NO_RISK
from cordon_scanner.rules.fact_terms import UNREACHED, FactTerms, Term

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.rules.loader import RuleSet
    from cordon_scanner.rules.pack import CompiledRule

PACKAGE_SCOPE = "."
DETECTOR = "package_rules"


class PackageFacts:
    """The terms one scan's package satisfies, each with the files that satisfy it."""

    def __init__(
        self,
        findings: Sequence[Finding],
        ctx: ScanContext,
        names: Mapping[str, Iterable[str]],
        reach: Mapping[str, tuple[str, int]] | None = None,
    ) -> None:
        places: dict[str, set[str]] = defaultdict(set)
        for place, paths in ctx.places().items():
            for path in paths:
                places[path].add(place)
        capabilities: dict[str, set[str]] = defaultdict(set)
        for path, held in names.items():
            capabilities[path].update(held)
        package_rules: set[str] = set()
        for f in findings:
            if f.is_suppressed:
                continue
            path = f.location.path
            if not path or path == PACKAGE_SCOPE:
                package_rules.add(f.rule_id)
            elif f.capabilities:
                capabilities[path].update(str(c) for c in f.capabilities)
        self._places = places
        self._reach = reach or {}
        self._capabilities = capabilities
        self._paths = sorted(set(capabilities) | set(places))
        self._matched: dict[Term, list[str]] = {}
        hooks = (h.kind for h in (ctx.repository.hooks if ctx.repository is not None else ()))
        self.package = FactTerms.of_package(package_rules, hooks)

    def _files(self, term: Term) -> list[str]:
        """The files that satisfy a file term, in path order; worked out once per term asked."""
        if term not in self._matched:
            self._matched[term] = [
                p
                for p in self._paths
                if FactTerms.file_satisfies(
                    bool(self._places.get(p)),
                    self._places.get(p, ()),
                    self._capabilities.get(p, ()),
                    term,
                    self._reach.get(p, ("", 0))[0],
                )
            ]
        return self._matched[term]

    def has(self, term: Term) -> bool:
        if term[0] == "file":
            return bool(self._files(term))
        return term in self.package

    def where(self, term: Term) -> str:
        """The first file (in path order) that satisfies a file term; the package for any other term."""
        paths = self._files(term) if term[0] == "file" else []
        return paths[0] if paths else PACKAGE_SCOPE


class PackageRules:
    """`decide(rules, findings, ctx)`: the findings of every package-scope composite the package satisfies."""

    @staticmethod
    def selected(rules: RuleSet) -> tuple[CompiledRule, ...]:
        return tuple(r for r in rules.by_kind(MatchKind.COMPOSITE) if r.match.scope == "package")

    @staticmethod
    def decide(
        rules: RuleSet,
        findings: Sequence[Finding],
        ctx: ScanContext,
        facts: Mapping[str, Mapping[str, Sequence[object]]],
        reach: Mapping[str, tuple[str, int]] | None = None,
    ) -> list[Finding]:
        selected = PackageRules.selected(rules)
        if not selected:
            return []
        names = {path: [str(n) for n in held.get("cap.all", ())] for path, held in facts.items()}
        known = PackageFacts(findings, ctx, names, reach)
        out = []
        for compiled in selected:
            all_of = [FactTerms.of_spec(t) for t in compiled.match.all_of]
            any_of = [FactTerms.of_spec(t) for t in compiled.match.any_of]
            unless = [FactTerms.of_spec(t) for t in compiled.match.unless]
            if not all(known.has(t) for t in all_of):
                continue
            if any_of and not any(known.has(t) for t in any_of):
                continue
            if any(known.has(t) for t in unless):
                continue
            satisfied = [t for t in (*all_of, *any_of) if known.has(t)]
            file_terms = [t for t in satisfied if t[0] == "file"]
            path = known.where(file_terms[0]) if file_terms else PACKAGE_SCOPE
            out.append(PackageRules.finding(compiled, path, satisfied))
        return out

    @staticmethod
    def finding(compiled: CompiledRule, path: str, satisfied: Sequence[Term]) -> Finding:
        rule = compiled.rule
        said = "; ".join(" ".join(t) for t in satisfied)
        unreached = any(t[0] == "file" and t[1] == UNREACHED for t in satisfied)
        return Finding(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            confidence=rule.confidence,
            message=rule.message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(
                    f"{rule.id}:{compiled.predicate_digest()}:{path}:{said}".encode()
                ),
                redaction=RedactionMode.NONE,
                metadata=(("facts", said), ("unreached", "yes" if unreached else "no")),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.id),
            risk=NO_RISK,
            detector=DETECTOR,
            rule_version=rule.version,
            rulepack=rule.rulepack,
            references=rule.references,
        )


__all__ = ["PackageFacts", "PackageRules"]
