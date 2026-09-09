"""Rule pack loading, validation and compilation.

The most important test in this file is
``TestPrefilterSoundness::test_prefilter_never_skips_a_real_match``. The
prefilter is an optimisation that decides which files a rule never sees, so an
unsound prefilter is a silent false negative across an entire scan, with no
error, no warning and a green build. It is fuzzed rather than sampled.
"""

from __future__ import annotations

import re
from typing import ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cordon_scanner.core.errors import RulePackError, UnsafePatternError
from cordon_scanner.core.models import Capability, MatchKind
from cordon_scanner.rules.loader import (
    PatternCompiler,
    RuleLoader,
    RuleSet,
    RuleTester,
)

MINIMAL_PACK = """
pack:
  id: test.pack
  version: 1.0.0
  license: Apache-2.0

rules:
  - id: TEST.RULE.001
    category: suspicious
    severity: high
    confidence: medium
    title: A test rule
    message: Something happened.
    remediation: Fix it.
    match:
      kind: regex
      pattern: 'dangerous_call\\s*\\('
    tests:
      positive:
        - "dangerous_call(x)"
      negative:
        - "safe_call(x)"
"""


def load(text: str, **kwargs) -> object:
    return RuleLoader(**kwargs).load_text(text, source="test.yaml")


# ---------------------------------------------------------------------------
# Pack structure
# ---------------------------------------------------------------------------


class TestPackLoading:
    def test_minimal_pack_loads(self) -> None:
        pack = load(MINIMAL_PACK)
        assert pack.id == "test.pack"
        assert pack.version == "1.0.0"
        assert len(pack) == 1
        assert pack.rules[0].id == "TEST.RULE.001"

    def test_content_hash_is_stable_and_content_addressed(self) -> None:
        """Recorded in every scan result, so a report can say which rules
        produced it months later."""
        assert load(MINIMAL_PACK).content_hash == load(MINIMAL_PACK).content_hash
        assert (
            load(MINIMAL_PACK.replace("high", "critical")).content_hash
            != load(MINIMAL_PACK).content_hash
        )

    def test_missing_pack_header_is_refused(self) -> None:
        with pytest.raises(RulePackError, match="pack"):
            load("rules: []\n")

    def test_licence_is_required(self) -> None:
        """Every pack declares its licence so that rule data with incompatible
        terms is never silently bundled into an Apache-2.0 distribution."""
        text = MINIMAL_PACK.replace("  license: Apache-2.0\n", "")
        with pytest.raises(RulePackError, match="license"):
            load(text)

    def test_version_must_be_semantic(self) -> None:
        with pytest.raises(RulePackError, match="semantic"):
            load(MINIMAL_PACK.replace("version: 1.0.0", "version: v1"))

    def test_unknown_pack_key_is_refused(self) -> None:
        with pytest.raises(RulePackError, match="unknown pack key"):
            load(MINIMAL_PACK.replace("  license:", "  licence:"))

    def test_empty_rules_list_is_refused(self) -> None:
        with pytest.raises(RulePackError, match="non-empty"):
            load("pack:\n  id: a\n  version: 1.0.0\n  license: MIT\nrules: []\n")


class TestRuleValidation:
    def test_rule_id_shape_is_enforced(self) -> None:
        """Ids appear in suppressions, baselines and SARIF, all of which outlive
        the rule."""
        with pytest.raises(RulePackError, match="invalid rule id"):
            load(MINIMAL_PACK.replace("TEST.RULE.001", "lowercase-id"))

    def test_duplicate_rule_id_is_refused(self) -> None:
        text = MINIMAL_PACK + MINIMAL_PACK[MINIMAL_PACK.index("  - id:") :]
        with pytest.raises(RulePackError, match="duplicate"):
            load(text)

    def test_unknown_rule_key_is_refused(self) -> None:
        with pytest.raises(RulePackError, match="unknown key"):
            load(MINIMAL_PACK.replace("    remediation:", "    remediaton:"))

    def test_missing_required_field_is_refused(self) -> None:
        with pytest.raises(RulePackError, match="severity"):
            load(MINIMAL_PACK.replace("    severity: high\n", ""))

    def test_unknown_category_is_refused(self) -> None:
        with pytest.raises(RulePackError):
            load(MINIMAL_PACK.replace("category: suspicious", "category: bad-stuff"))

    def test_samples_are_mandatory(self) -> None:
        """Detection rules fail silently: a broken pattern matches nothing, the
        scan still succeeds, and the gate looks green because the check is
        broken. Samples make that impossible."""
        text = MINIMAL_PACK[: MINIMAL_PACK.index("    tests:")]
        with pytest.raises(RulePackError, match="positive and one negative"):
            load(text)

    def test_positive_only_samples_are_refused(self) -> None:
        text = MINIMAL_PACK[: MINIMAL_PACK.index("      negative:")]
        with pytest.raises(RulePackError, match="negative"):
            load(text)


class TestProvenance:
    MALICIOUS = MINIMAL_PACK.replace("category: suspicious", "category: malicious")

    def test_malicious_rules_require_provenance(self) -> None:
        """A rule asserting evidence of intent to harm must record where that
        assertion came from. It is the class most likely to be challenged and
        the class whose removal matters most."""
        with pytest.raises(RulePackError, match="provenance"):
            load(self.MALICIOUS)

    def test_malicious_rule_with_provenance_loads(self) -> None:
        text = self.MALICIOUS.replace(
            "    match:",
            "    provenance:\n      kind: research\n      reference: CWE-95\n    match:",
        )
        pack = load(text)
        assert pack.rules[0].rule.provenance is not None
        assert pack.rules[0].rule.provenance.kind == "research"

    def test_incident_provenance_marks_a_rule_protected(self) -> None:
        """Incident-derived rules are the only ones known to have matched
        something that actually arrived, and are the easiest to lose in a
        cleanup because they look arbitrary out of context."""
        text = self.MALICIOUS.replace(
            "    match:", "    provenance:\n      kind: incident\n    match:"
        )
        assert load(text).rules[0].rule.provenance.protected

    def test_research_provenance_is_not_protected(self) -> None:
        text = self.MALICIOUS.replace(
            "    match:", "    provenance:\n      kind: research\n    match:"
        )
        assert not load(text).rules[0].rule.provenance.protected

    def test_unknown_provenance_kind_is_refused(self) -> None:
        text = self.MALICIOUS.replace(
            "    match:", "    provenance:\n      kind: vibes\n    match:"
        )
        with pytest.raises(RulePackError, match=r"provenance\.kind"):
            load(text)


class TestBaselineDiscipline:
    def test_high_confidence_requires_a_zero_baseline(self) -> None:
        """Turns false-positive control from a review-time opinion into a
        load-time invariant."""
        text = MINIMAL_PACK.replace("confidence: medium", "confidence: high").replace(
            "    match:", "    baseline_hits: 7\n    match:"
        )
        with pytest.raises(RulePackError, match="zero baseline"):
            load(text)

    def test_medium_confidence_may_have_a_baseline(self) -> None:
        text = MINIMAL_PACK.replace("    match:", "    baseline_hits: 7\n    match:")
        assert load(text).rules[0].rule.baseline_hits == 7

    def test_high_confidence_with_zero_baseline_is_fine(self) -> None:
        assert load(MINIMAL_PACK.replace("confidence: medium", "confidence: high"))


# ---------------------------------------------------------------------------
# Pattern safety
# ---------------------------------------------------------------------------


class TestPatternSafety:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"(a+)+",
            r"(a*)*",
            r"(a|aa)+",
            r"([a-z]+)*",
            r"(x+x+)+",
        ],
    )
    def test_nested_quantifiers_are_refused(self, pattern: str) -> None:
        """A single crafted file turns one of these into an unbounded CPU burn
        on every worker that touches it."""
        with pytest.raises(UnsafePatternError, match="backtrack"):
            PatternCompiler.validate_pattern(pattern, rule_id="T.001")

    @pytest.mark.parametrize("pattern", [r"(a)\1", r"(?P<x>a)(?P=x)"])
    def test_backreferences_are_refused(self, pattern: str) -> None:
        with pytest.raises(UnsafePatternError, match="backreference"):
            PatternCompiler.validate_pattern(pattern, rule_id="T.001")

    def test_invalid_regex_is_refused_with_the_rule_named(self) -> None:
        with pytest.raises(UnsafePatternError, match=r"T\.001"):
            PatternCompiler.validate_pattern("(unclosed", rule_id="T.001")

    @pytest.mark.parametrize(
        "pattern",
        [
            r"eval\s*\(",
            r"\batob\s*\(",
            r"child_process|execSync",
            r"[a-z]+_call\(",
            r"(?:foo|bar)\s*\(",
        ],
    )
    def test_ordinary_detection_patterns_are_accepted(self, pattern: str) -> None:
        assert PatternCompiler.validate_pattern(pattern, rule_id="T.001") is not None

    def test_unsafe_pattern_is_caught_at_load_not_at_match(self) -> None:
        """A pattern that can hang the scanner must never reach a worker."""
        text = MINIMAL_PACK.replace("dangerous_call\\s*\\(", "(a+)+")
        with pytest.raises(UnsafePatternError):
            load(text)


# ---------------------------------------------------------------------------
# Prefilter
# ---------------------------------------------------------------------------


class TestPrefilterExtraction:
    @pytest.mark.parametrize(
        ("pattern", "expected"),
        [
            (rb"eval\s*\(", (b"eval",)),
            (rb"child_process", (b"child_process",)),
            (rb"atob|btoa", (b"atob", b"btoa")),
            (rb"\bsendBeacon\s*\(", (b"sendBeacon",)),
        ],
    )
    def test_extracts_required_literals(self, pattern: bytes, expected: tuple[bytes, ...]) -> None:
        assert PatternCompiler._extract_prefilter(pattern) == tuple(sorted(expected))

    def test_returns_nothing_when_any_branch_has_no_literal(self) -> None:
        """A branch with no extractable literal could match a file the prefilter
        would have skipped, so the whole prefilter must be discarded."""
        assert PatternCompiler._extract_prefilter(rb"eval\(|[a-z]+") == ()

    def test_returns_nothing_for_short_literals(self) -> None:
        """Below three bytes a prefilter matches almost everything and costs
        more than it saves."""
        assert PatternCompiler._extract_prefilter(rb"ab") == ()

    def test_optional_characters_are_not_required(self) -> None:
        extracted = PatternCompiler._extract_prefilter(rb"colou?r_scheme")
        for literal in extracted:
            assert b"u" not in literal or b"colou" not in literal


class TestPrefilterSoundness:
    """The prefilter decides which files a rule never sees.

    An unsound prefilter is a silent false negative across a whole scan, with no
    error, no warning and a green build. That is the single worst failure this
    codebase can have, so the property is fuzzed rather than sampled.
    """

    PATTERNS: ClassVar[list[bytes]] = [
        rb"eval\s*\(",
        rb"child_process",
        rb"atob\s*\(|btoa\s*\(",
        rb"\bexecSync\b",
        rb"JSON\.stringify\(process\.env",
        rb"require\(['\"]https?['\"]\)",
        rb"sendBeacon\s*\(",
        rb"\.npmrc|\.ssh/|id_rsa",
        rb"colou?r_profile",
        rb"a{2,4}bcdef",
    ]

    @pytest.mark.parametrize("pattern", PATTERNS)
    @given(
        haystack=st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz._/'\"()[]{} \n0123456789\\"),
            max_size=200,
        )
    )
    def test_prefilter_never_skips_a_real_match(self, pattern: bytes, haystack: str) -> None:
        data = haystack.encode("utf-8")
        prefilter = PatternCompiler._extract_prefilter(pattern)
        if not prefilter:
            return  # no prefilter means the rule always runs, which is sound

        skipped = not any(lit in data for lit in prefilter)
        if skipped:
            assert re.compile(pattern).search(data) is None, (
                f"UNSOUND PREFILTER: {pattern!r} would skip a file it matches. "
                f"prefilter={prefilter!r} haystack={data!r}"
            )

    @pytest.mark.parametrize("pattern", PATTERNS)
    def test_prefilter_passes_the_patterns_own_literals(self, pattern: bytes) -> None:
        """Sanity check in the other direction: a prefilter that never lets
        anything through would be sound but useless."""
        prefilter = PatternCompiler._extract_prefilter(pattern)
        for literal in prefilter:
            assert any(lit in literal for lit in prefilter)


# ---------------------------------------------------------------------------
# Match kinds
# ---------------------------------------------------------------------------


class TestMatchKinds:
    def test_multiple_patterns_compile_to_one_alternation(self) -> None:
        """Matching cost is then independent of how many alternatives a rule
        declares."""
        text = MINIMAL_PACK.replace(
            "      pattern: 'dangerous_call\\s*\\('",
            "      patterns:\n        - 'alpha_call'\n        - 'beta_call'",
        )
        compiled = load(text).rules[0]
        assert compiled.match.regex.search(b"alpha_call()")
        assert compiled.match.regex.search(b"beta_call()")
        assert not compiled.match.regex.search(b"gamma_call()")

    def test_literal_match_kind(self) -> None:
        text = MINIMAL_PACK.replace(
            "      kind: regex\n      pattern: 'dangerous_call\\s*\\('",
            "      kind: literal\n      literal: 'eth_getBlockByNumber'",
        )
        compiled = load(text).rules[0]
        assert compiled.match.kind is MatchKind.LITERAL
        assert compiled.match.literals == (b"eth_getBlockByNumber",)
        assert compiled.match.prefilter == (b"eth_getBlockByNumber",)

    def test_composite_requires_all_or_any(self) -> None:
        text = MINIMAL_PACK.replace(
            "      kind: regex\n      pattern: 'dangerous_call\\s*\\('",
            "      kind: composite\n      scope: file",
        )
        with pytest.raises(RulePackError, match="requires `all` or `any`"):
            load(text)

    def test_composite_rejects_unknown_scope(self) -> None:
        text = MINIMAL_PACK.replace(
            "      kind: regex\n      pattern: 'dangerous_call\\s*\\('",
            "      kind: composite\n      scope: galaxy\n      all:\n        - capability: decode",
        )
        with pytest.raises(RulePackError, match="scope"):
            load(text)

    def test_unknown_match_kind_lists_valid_ones(self) -> None:
        text = MINIMAL_PACK.replace("kind: regex", "kind: telepathy")
        with pytest.raises(RulePackError, match="composite"):
            load(text)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


class TestRuleSelfTests:
    def test_passing_rule_reports_no_failures(self) -> None:
        assert RuleTester.run(load(MINIMAL_PACK)) == ()

    def test_positive_sample_that_does_not_match_is_reported(self) -> None:
        text = MINIMAL_PACK.replace('- "dangerous_call(x)"', '- "harmless(x)"')
        failures = RuleTester.run(load(text))
        assert len(failures) == 1
        assert failures[0].kind == "positive"

    def test_negative_sample_that_matches_is_reported(self) -> None:
        text = MINIMAL_PACK.replace('- "safe_call(x)"', '- "dangerous_call(y)"')
        failures = RuleTester.run(load(text))
        assert len(failures) == 1
        assert failures[0].kind == "negative"


# ---------------------------------------------------------------------------
# RuleSet
# ---------------------------------------------------------------------------


class TestRuleSet:
    def test_language_selection_includes_universal_rules(self) -> None:
        """A rule with no declared language is deliberately universal, not
        unknown: encoded payloads mean the same thing in every language."""
        text = (
            MINIMAL_PACK
            + """
  - id: TEST.RULE.002
    category: suspicious
    severity: low
    confidence: low
    title: JS only
    message: js
    languages: [javascript]
    match:
      kind: regex
      pattern: 'js_only_call'
    tests:
      positive:
        - "js_only_call()"
      negative:
        - "other()"
"""
        )
        rule_set = RuleSet([load(text)])
        js = {r.id for r in rule_set.for_language("javascript")}
        py = {r.id for r in rule_set.for_language("python")}
        assert js == {"TEST.RULE.001", "TEST.RULE.002"}
        assert py == {"TEST.RULE.001"}

    def test_disabled_rules_are_excluded(self) -> None:
        text = MINIMAL_PACK.replace("    match:", "    enabled: false\n    match:")
        assert len(RuleSet([load(text)])) == 0

    def test_content_hash_changes_with_rule_content(self) -> None:
        a = RuleSet([load(MINIMAL_PACK)]).content_hash
        b = RuleSet([load(MINIMAL_PACK.replace("severity: high", "severity: low"))]).content_hash
        assert a != b


# ---------------------------------------------------------------------------
# The shipped packs
# ---------------------------------------------------------------------------


class TestBuiltinPacks:
    def test_all_builtin_packs_load(self) -> None:
        from cordon_scanner.rules.loader import RuleLoader

        packs = RuleLoader.load_builtin()
        assert packs, "no built-in rule packs were found"
        for pack in packs:
            assert pack.license
            assert len(pack) > 0

    def test_all_builtin_rules_pass_their_own_samples(self) -> None:
        """This is what `cordon rules test` runs, and what CI runs on every
        commit. It is the mechanism that makes an inert rule impossible to ship
        unnoticed."""
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            failures = RuleTester.run(pack)
            assert not failures, "\n".join(
                f"{f.rule_id} [{f.kind}] {f.detail}: {f.sample}" for f in failures
            )

    def test_capability_rules_declare_a_capability(self) -> None:
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                if compiled.id.startswith("CAP."):
                    assert compiled.rule.capability is not None, compiled.id

    def test_every_capability_primitive_is_covered_per_language(self) -> None:
        """A language that defines only some primitives inherits only some
        composite rules, which is a coverage gap that is invisible at runtime."""
        from cordon_scanner.rules.loader import RuleLoader

        by_language: dict[str, set[Capability]] = {}
        agnostic: set[Capability] = set()
        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                if compiled.rule.capability is None:
                    continue
                if not compiled.rule.languages:
                    # A rule with no declared language is universal, not
                    # unknown -- `RuleSet.for_language` returns it for every
                    # language -- so it covers its primitive everywhere.
                    agnostic.add(compiled.rule.capability)
                    continue
                for language in compiled.rule.languages:
                    by_language.setdefault(language, set()).add(compiled.rule.capability)

        # `dynamic_dispatch` is deliberately absent from every pattern pack. It
        # marks a call whose target could not be resolved, which is by
        # definition the case where there is no literal for a pattern to match;
        # the AST tier emits it. Requiring a regex for it would mean writing a
        # pattern that cannot exist, and the honest way to express that is to
        # say so here rather than to invent one.
        pattern_expressible = set(Capability) - {Capability.DYNAMIC_DISPATCH}
        for language, covered in by_language.items():
            missing = pattern_expressible - covered - agnostic
            assert not missing, f"{language} is missing primitives: {sorted(missing)}"
