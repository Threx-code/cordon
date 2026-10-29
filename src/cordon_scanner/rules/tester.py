"""A rule pack's own tests, run at load: each rule's sample inputs matched and not matched, and the failures reported by rule."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.foundation.capabilities import MatchKind
from cordon_scanner.rules.pack import CompiledRule, RulePack

if TYPE_CHECKING:
    pass


@dataclass(frozen=True, slots=True)
class RuleTestFailure:
    rule_id: str
    kind: str
    sample: str
    detail: str


class RuleTester:
    """Executes the samples a rule declares about itself.

    Separate from the loader because loading answers "is this pack well
    formed?" and this answers "does it match anything?". A rule that parses,
    compiles, loads and matches nothing is the failure a detection tool cannot
    see from the inside: the scan runs, the pack is present, the output is
    empty, and everything looks healthy.

    This is what `cordon rules test` runs and what CI runs on every commit,
    which is what makes an inert rule impossible to ship unnoticed.
    """

    @staticmethod
    def run(pack: RulePack) -> tuple[RuleTestFailure, ...]:
        """Execute every rule's declared samples.

        This is what ``cordon rules test`` runs, and what the project's own CI runs
        on every commit. It is the mechanism that makes an inert rule impossible to
        ship unnoticed.

        Only directly-matchable kinds are executed here. Composite and graph rules
        are exercised by the corpus tests, because their inputs are other findings
        rather than text.
        """

        failures: list[RuleTestFailure] = []

        for compiled in pack.rules:
            rule = compiled.rule
            if compiled.match.kind not in {MatchKind.REGEX, MatchKind.LITERAL, MatchKind.AST}:
                continue

            for sample in rule.tests.positive:
                result = RuleTester._sample_matches(compiled, sample)
                if result is False:
                    failures.append(
                        RuleTestFailure(rule.id, "positive", sample, "expected a match, got none")
                    )
            for sample in rule.tests.negative:
                result = RuleTester._sample_matches(compiled, sample)
                if result is True:
                    failures.append(
                        RuleTestFailure(
                            rule.id, "negative", sample, "expected no match, but it matched"
                        )
                    )

        return tuple(failures)

    @staticmethod
    def _sample_matches(compiled: CompiledRule, sample: str) -> bool | None:
        r"""Decide a sample exactly the way the detector decides a file.

        Returns None for a sample that cannot be evaluated here -- an `ast` rule
        for a language whose provider is an uninstalled optional extra -- so the
        caller skips it rather than failing it. The provider-bearing extra is
        installed in the test environment, so a skipped sample there is a setup
        gap, not a rule that ships unchecked.

        The prefilter is applied here for the same reason it is applied there:
        without it, a rule whose prefilter is wrong passes all of its own
        positive samples while matching nothing in production. That happened.
        `secret\w{4,9}token` extracted the prefilter `4,9}token`, a literal that
        appears in no file the rule is meant to match, so the rule was skipped
        everywhere and its tests stayed green -- precisely the silent failure the
        sample runner exists to prevent.

        Running the same path turns that class of bug into a load-time failure
        naming the rule.
        """

        if compiled.match.kind is MatchKind.AST:
            # Parsed, not scanned. Running the sample through the same resolver
            # the detector uses is the only way a sample can demonstrate what
            # this kind claims -- that `f = os.system; f(x)` is the same call as
            # `os.system(x)`. A byte comparison here would pass on the first
            # spelling and prove nothing about the second.
            from cordon_scanner.analysis.shared.ast_providers import AstProviders

            language = compiled.rule.languages[0] if compiled.rule.languages else "python"
            provider = AstProviders.ast_provider_for(language)
            if provider is None:
                return None
            return bool(compiled.match.ast_query.matching(provider.resolve_calls(sample)))

        data = sample.encode("utf-8")

        if not compiled.match.admits(data):
            return False

        if compiled.match.regex is not None:
            regex = compiled.match.regex_for(data)
            return regex is not None and regex.search(data) is not None
        if compiled.match.literals:
            return any(lit in data for lit in compiled.match.literals)
        return False


__all__ = ["RuleTestFailure", "RuleTester"]
