"""Capability detection and composite reasoning.

This is where the language-agnostic detection model becomes real.

The detector does two distinct jobs, and separating them is the whole design.

**Labelling.** It runs the capability rules over a file's bytes and records what
that file can do: decode, execute, spawn, read credentials, reach the network,
persist. On their own these are observations, not accusations. Every one has
legitimate uses, and reporting them individually would drown a user in noise.

**Reasoning.** It then evaluates composite rules over those labels. A file that
decodes a string *and* executes it is a second-stage loader. A file that reads
credentials *and* reaches the network *and* spawns a process is an exfiltrator.
Neither conclusion is available from any single pattern, which is why signature
matching alone plateaus so quickly.

The reason this generalises across languages is that the primitives are forced
by the attacker's objective rather than chosen by them. To exfiltrate data, code
must read something sensitive and send it somewhere. To run a second stage, it
must decode a payload and execute it. Those constraints hold in every language,
so a new language supplies pattern data for six names and inherits the entire
composite rule set unchanged.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon.core.models import (
    Capability,
    Category,
    Explanation,
    Finding,
    Location,
    MatchKind,
    Severity,
)
from cordon.core.redact import Redactor
from cordon.core.scoring import ScoringContext, apply_category_floor
from cordon.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    ScanContext,
    select_rules,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit
    from cordon.rules.loader import CompiledRule


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One capability observed in a file, with where it was seen."""

    capability: Capability
    rule_id: str
    byte_start: int
    byte_end: int
    line: int


class CapabilityDetector(BaseDetector):
    """Labels files with capabilities and evaluates composite rules over them."""

    id = "capability"
    version = "0.1.0"
    categories = frozenset(
        {Category.SUSPICIOUS, Category.MALICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        """Runs whenever any capability or composite rule is loaded."""
        return any(
            r.rule.capability is not None or r.match.kind is MatchKind.COMPOSITE for r in ctx.rules
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content

        # Binary files are excluded from content rules. A byte sequence in a PNG
        # that happens to spell a pattern is a false positive with no upside,
        # and the file was never source to begin with.
        if content.is_binary:
            return ()

        candidates = select_rules(ctx.rules, language=unit.language, path=content.path)
        if not candidates:
            return ()

        hits = self._match_capabilities(content, candidates)
        findings: list[Finding] = list(self._composite_findings(unit, ctx, hits, candidates))

        # A truncated file was only partly examined, so say so. Claiming a clean
        # result for content that was never read is the failure this project
        # treats as unacceptable.
        if content.truncated:
            findings.append(
                self.operational(
                    path=content.path,
                    message=(
                        f"Only the first {len(content.raw)} bytes of this "
                        f"{content.size}-byte file were examined."
                    ),
                    detail="max_file_bytes",
                    rule_id="OPERATIONAL.FILE.TRUNCATED",
                )
            )

        return findings

    # -- Labelling -------------------------------------------------------

    def _match_capabilities(
        self, content, candidates: tuple[CompiledRule, ...]
    ) -> list[CapabilityHit]:
        """Run capability rules over the file's bytes.

        Matching happens against ``bytes``, never decoded text. Most files match
        nothing, and decoding them all would be the single largest waste in the
        scan. It also means attacker-controlled bytes are only decoded once
        something has already indicated it is worth doing.
        """
        raw = content.raw
        hits: list[CapabilityHit] = []

        for compiled in candidates:
            capability = compiled.rule.capability
            if capability is None or compiled.match.regex is None:
                continue

            # The prefilter is what makes this affordable. A cheap substring scan
            # rejects the large majority of files before any regex runs, turning
            # cost proportional to files times rules into something a commit-time
            # hook can pay.
            prefilter = compiled.match.prefilter
            if prefilter and not any(literal in raw for literal in prefilter):
                continue

            for match in compiled.match.regex.finditer(raw):
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id=compiled.id,
                        byte_start=match.start(),
                        byte_end=match.end(),
                        line=content.line_of(match.start()),
                    )
                )
                # One hit per rule per file is enough to establish the label.
                # Reporting every occurrence would inflate the evidence without
                # changing any conclusion.
                break

        return hits

    # -- Reasoning -------------------------------------------------------

    def _composite_findings(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        hits: list[CapabilityHit],
        candidates: tuple[CompiledRule, ...],
    ) -> Iterable[Finding]:
        if not hits:
            return

        present = {hit.capability for hit in hits}
        by_capability = {hit.capability: hit for hit in hits}
        in_hook = ctx.in_install_hook(unit.path)

        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            if not self._evaluate(compiled, present, unit.path, in_hook):
                continue

            matched = self._capabilities_of(compiled)
            anchor = self._anchor(matched, by_capability, hits)

            yield self._composite_finding(compiled, unit, ctx, anchor, matched, hits)

    def _evaluate(
        self,
        compiled: CompiledRule,
        present: set[Capability],
        path: str,
        in_hook: bool = False,
    ) -> bool:
        """Evaluate a composite expression against the capabilities present.

        Supports ``all``, ``any``, nested combinations, and ``unless``. Kept
        deliberately small: a composite rule is read by somebody deciding whether
        a security finding is justified, and an expression language rich enough
        to be clever is one nobody can review.
        """
        match = compiled.match

        if match.all_of and not all(
            self._term(term, present, path=path, in_hook=in_hook) for term in match.all_of
        ):
            return False
        if match.any_of and not any(
            self._term(term, present, path=path, in_hook=in_hook) for term in match.any_of
        ):
            return False
        return not any(
            self._term(term, present, path=path, in_hook=in_hook) for term in match.unless
        )

    def _term(
        self,
        term: object,
        present: set[Capability],
        *,
        path: str | None = None,
        in_hook: bool = False,
    ) -> bool:
        if not isinstance(term, dict):
            return False

        if "capability" in term:
            try:
                return Capability(str(term["capability"])) in present
            except ValueError:
                return False

        if "any" in term:
            return any(
                self._term(t, present, path=path, in_hook=in_hook) for t in term["any"] or ()
            )

        if "all" in term:
            return all(
                self._term(t, present, path=path, in_hook=in_hook) for t in term["all"] or ()
            )

        if "path_glob" in term and path is not None:
            from cordon.core.walker import PathGlob

            return PathGlob.matches(path, str(term["path_glob"]))

        # Execution context as a first-class term.
        #
        # This is what lets a rule say "credential access plus network egress,
        # in an install hook" without also requiring an execution primitive. In
        # application code that pairing needs a third signal to be meaningful,
        # because reading configuration and calling an API is what an
        # application does all day. In an install hook it does not: the hook IS
        # the execution, so the pair alone is already the whole attack.
        if "context" in term:
            return str(term["context"]) == "install_hook" and in_hook

        return False

    @staticmethod
    def _capabilities_of(compiled: CompiledRule) -> tuple[Capability, ...]:
        """Every capability named anywhere in a composite expression."""
        found: list[Capability] = []

        def walk(term: object) -> None:
            if not isinstance(term, dict):
                return
            if "capability" in term:
                with suppress(ValueError):
                    found.append(Capability(str(term["capability"])))
            for key in ("all", "any"):
                for nested in term.get(key) or ():
                    walk(nested)

        for term in (*compiled.match.all_of, *compiled.match.any_of):
            walk(term)
        return tuple(dict.fromkeys(found))

    @staticmethod
    def _anchor(
        matched: tuple[Capability, ...],
        by_capability: dict[Capability, CapabilityHit],
        hits: list[CapabilityHit],
    ) -> CapabilityHit:
        """Where to point the finding.

        The earliest hit among the capabilities the rule named. Pointing at the
        first contributing line puts the reader at the start of the construct
        rather than in the middle of it.
        """
        relevant = [by_capability[c] for c in matched if c in by_capability]
        return min(relevant or hits, key=lambda h: h.byte_start)

    def _composite_finding(
        self,
        compiled: CompiledRule,
        unit: FileUnit,
        ctx: ScanContext,
        anchor: CapabilityHit,
        matched: tuple[Capability, ...],
        hits: list[CapabilityHit],
    ) -> Finding:
        rule = compiled.rule
        content = unit.content

        mode = Redactor.effective_mode(rule.evidence_policy, ctx.config.evidence)
        evidence = Redactor.build_evidence(content, anchor.byte_start, anchor.byte_end, mode)

        present = {h.capability for h in hits}
        in_hook = ctx.in_install_hook(content.path)

        severity = apply_category_floor(rule.category, rule.severity)
        category = rule.category
        escalations: list[str] = []

        if in_hook:
            # This is the escalation that matters most in the whole engine. The
            # identical capability pair is ordinary in application code and is a
            # credential harvester in an install hook, because install-time code
            # runs unprompted, as the developer, with the developer's full
            # environment, before any test, review, container boundary or network
            # policy applies.
            escalations.append(
                "runs during install or build, as the user, before any other control"
            )
            severity = Severity.CRITICAL
            if (
                category is Category.SUSPICIOUS
                and {
                    Capability.CREDENTIAL,
                    Capability.EGRESS,
                }
                <= present
            ):
                category = Category.MALICIOUS
                escalations.append("reads credentials and reaches the network from an install hook")

        is_obfuscated = Capability.DECODE in present

        risk = ctx.scorer.score(
            severity,
            rule.confidence,
            ScoringContext(
                in_install_hook=in_hook,
                capabilities=frozenset(present),
                is_obfuscated=is_obfuscated,
            ),
        )

        contributing = tuple(
            f"{h.rule_id}@{h.line}"
            for h in sorted(hits, key=lambda h: h.byte_start)
            if h.capability in matched
        )

        return Finding(
            rule_id=rule.id,
            category=category,
            severity=severity,
            confidence=rule.confidence,
            message=rule.message,
            location=Location(
                path=content.path,
                line=anchor.line,
                column=content.column_of(anchor.byte_start),
                byte_start=anchor.byte_start,
                byte_end=anchor.byte_end,
                project=unit.project,
            ),
            evidence=evidence,
            remediation=rule.remediation,
            explanation=Explanation(
                summary=rule.title,
                matched_rule=rule.id,
                contributing=contributing,
                escalations=tuple(escalations),
            ),
            risk=risk,
            detector=self.id,
            rule_version=rule.version,
            rulepack=rule.rulepack,
            references=rule.references,
            capabilities=tuple(sorted(matched, key=lambda c: c.value)),
        )


__all__ = ["CapabilityDetector", "CapabilityHit"]
