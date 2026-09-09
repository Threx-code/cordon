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

from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Capability,
    Category,
    Explanation,
    Finding,
    Location,
    MatchKind,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect import embedded
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit
    from cordon_scanner.detect.embedded import Command
    from cordon_scanner.rules.loader import CompiledRule


MAX_VARIANTS = 8
"""Distinct operations counted per rule before the count stops mattering.

Depth beyond a handful changes no conclusion, and the cap is what keeps a
generated file with a thousand matches from being scanned in full."""

MAX_MATCHES_EXAMINED = 64
"""Occurrences examined per rule while counting distinct operations."""


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One capability observed in a file, with where it was seen."""

    capability: Capability
    rule_id: str
    byte_start: int
    byte_end: int
    line: int
    variants: int = 1
    """How many distinct operations of this capability the rule matched.

    A decode rule covering base64, hex and decompression matches all three
    with one pattern, so the number of rules that fired cannot express how many
    decoding steps a file performs. This can: one call site repeated ten times
    is still one operation, and base64 followed by decompression is two."""


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

        candidates = RuleSelector.select_rules(ctx.rules, language=unit.language, path=content.path)
        if not candidates:
            return ()

        hits = self._match_capabilities(content, candidates)
        resolved, commands = self._resolved_capabilities(unit, content)
        if not commands and unit.language != "python":
            commands = embedded.extract(content.text, unit.language)
        hits.extend(resolved)
        hits.extend(self._embedded_capabilities(ctx, content, commands))
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
        self, content: FileContent, candidates: tuple[CompiledRule, ...]
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

            first = None
            distinct: set[bytes] = set()

            for index, match in enumerate(compiled.match.regex.finditer(raw)):
                if first is None:
                    first = match
                # Distinct *operations*, not distinct occurrences. Ten calls to
                # the same decoder are one decoding step repeated; base64 and
                # then decompression are two, and that difference is what
                # separates an ordinary decode from a chain built to survive
                # each layer of inspection.
                distinct.add(b" ".join(match.group(0).split()))
                if len(distinct) >= MAX_VARIANTS or index >= MAX_MATCHES_EXAMINED:
                    break

            if first is None:
                continue

            # One hit per rule per file. Reporting every occurrence would
            # inflate the evidence without changing any conclusion; the count
            # of distinct operations rides along on the hit instead.
            hits.append(
                CapabilityHit(
                    capability=capability,
                    rule_id=compiled.id,
                    byte_start=first.start(),
                    byte_end=first.end(),
                    line=content.line_of(first.start()),
                    variants=len(distinct),
                )
            )

        return hits

    def _resolved_capabilities(
        self, unit: FileUnit, content: FileContent
    ) -> tuple[list[CapabilityHit], list[Command]]:
        """Capabilities the patterns cannot see, resolved from the parsed tree.

        Added to the regex hits rather than replacing them. The patterns stay
        the fast path and the answer for every language this cannot parse; this
        catches what a byte pattern structurally cannot -- an aliased import, a
        bound name, a spliced string -- because those are the same primitive
        written so that no literal appears.

        Returns the commands found at spawn sites alongside the capabilities,
        since those are what the shell rules are then run against.

        Python only. `ast` is in the standard library, so this costs nothing
        against the zero-runtime-dependency constraint. JavaScript needs a
        parser that is not, which is a decision about that constraint rather
        than a line of code, and it is not taken here.
        """
        if unit.language != "python":
            return [], []

        from cordon_scanner.detect.pyast import PythonAnalyzer

        resolved = PythonAnalyzer.analyse(content.text)
        return (
            [
                CapabilityHit(
                    capability=hit.capability,
                    rule_id=f"AST.PY.{hit.capability.name}",
                    byte_start=0,
                    byte_end=0,
                    line=hit.line,
                )
                for hit in resolved
            ],
            [embedded.Command(text=hit.command, line=hit.line) for hit in resolved if hit.command],
        )

    def _embedded_capabilities(
        self, ctx: ScanContext, content: FileContent, commands: list[Command]
    ) -> list[CapabilityHit]:
        """Shell rules, applied to shell commands written inside other languages.

        A command handed to a spawn primitive is shell, whatever the file
        extension says. Without this it is examined by the rules for the host
        language, which see a string literal, and never by the rules that know
        what the string means -- so `os.system("curl -d $(env) https://...")`
        reads as one unremarkable spawn rather than as exfiltration.

        Only the command text is matched, never the surrounding file, so this
        cannot pick up a URL from a comment or an example from a docstring. The
        hit is attributed to the line the call is on, which is where a reader
        needs to look.
        """
        if not commands:
            return []

        if content.path.endswith((".sh", ".bash", ".zsh", ".ps1")):
            # Already matched directly; running them twice would double the
            # evidence without adding anything to it.
            return []

        # Paired with their capability here so the match loop has nothing
        # optional left to unwrap.
        shell_rules = [
            (compiled, compiled.rule.capability)
            for compiled in ctx.rules.for_language("shell")
            if compiled.rule.capability is not None and compiled.match.regex is not None
        ]
        if not shell_rules:
            return []

        hits: list[CapabilityHit] = []
        seen: set[str] = set()

        for command in commands:
            payload = command.text.encode("utf-8", "surrogatepass")
            for compiled, capability in shell_rules:
                if compiled.id in seen or compiled.match.regex is None:
                    continue
                prefilter = compiled.match.prefilter
                if prefilter and not any(literal in payload for literal in prefilter):
                    continue
                if compiled.match.regex.search(payload) is None:
                    continue
                seen.add(compiled.id)
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id=compiled.id,
                        byte_start=0,
                        byte_end=0,
                        line=command.line,
                    )
                )

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
        # Depth, summed over distinct operations rather than over rules. One
        # decode rule covers base64, hex and decompression, so counting rules
        # cannot tell one decoding step from three.
        #
        # The AST tier is excluded. It is a second view of the same call --
        # resolving what a pattern could not see, not finding another decode --
        # so counting it too would make every parsed Python file appear to
        # decode twice, which is exactly what it did before this line said so.
        counts: Counter[Capability] = Counter()
        for hit in hits:
            if hit.rule_id.startswith("AST."):
                continue
            counts[hit.capability] += hit.variants
        by_capability = {hit.capability: hit for hit in hits}
        in_hook = ctx.in_install_hook(unit.path)

        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            if not self._evaluate(compiled, present, unit.path, in_hook, counts):
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
        counts: Counter[Capability] | None = None,
    ) -> bool:
        """Evaluate a composite expression against the capabilities present.

        Supports ``all``, ``any``, nested combinations, and ``unless``. Kept
        deliberately small: a composite rule is read by somebody deciding whether
        a security finding is justified, and an expression language rich enough
        to be clever is one nobody can review.
        """
        match = compiled.match
        counts = counts if counts is not None else Counter(present)

        if match.all_of and not all(
            self._term(term, present, path=path, in_hook=in_hook, counts=counts)
            for term in match.all_of
        ):
            return False
        if match.any_of and not any(
            self._term(term, present, path=path, in_hook=in_hook, counts=counts)
            for term in match.any_of
        ):
            return False
        return not any(
            self._term(term, present, path=path, in_hook=in_hook, counts=counts)
            for term in match.unless
        )

    def _term(
        self,
        term: object,
        present: set[Capability],
        *,
        path: str | None = None,
        in_hook: bool = False,
        counts: Counter[Capability] | None = None,
    ) -> bool:
        if not isinstance(term, dict):
            return False

        if "capability" in term:
            try:
                capability = Capability(str(term["capability"]))
            except ValueError:
                return False
            required = term.get("at_least")
            if required is None:
                return capability in present
            # Depth, not presence. `decode` twice in one file is a decode
            # chain -- base64 into decompress into execute -- and that is a
            # stronger claim than decoding once, because a single decode has
            # ordinary uses and stacking them has none.
            observed = (counts or Counter(present))[capability]
            return observed >= int(required)

        if "any" in term:
            return any(
                self._term(t, present, path=path, in_hook=in_hook, counts=counts)
                for t in term["any"] or ()
            )

        if "all" in term:
            return all(
                self._term(t, present, path=path, in_hook=in_hook, counts=counts)
                for t in term["all"] or ()
            )

        if "path_glob" in term and path is not None:
            from cordon_scanner.core.walker import PathGlob

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

        severity = RiskScorer.apply_category_floor(rule.category, rule.severity)
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
