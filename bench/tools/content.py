"""Which findings measure the scanned content, and which come from knowledge outside it.

Content recall -- "would Cordon have caught this from the package alone?" -- counts only findings
a detector derived from the package's own bytes. Everything that reads something else (an advisory
or malware feed, a registry record, release history, a known-sample signature database, the names
of popular packages) is intel: it is counted in the recall with intel, never in content recall.

```
  finding ──► detector in CONTENT_DETECTORS? ──no──► intel
                     │ yes
                     ▼
              rule in INTEL_RULES of a mixed detector, or a known-sample marker? ──yes──► intel
                     │ no
                     ▼
                  content
```

An allowlist, not a name match: a detector or rule nobody has classified is intel until someone
does, so a new intel source can never quietly raise content recall. Every detector the engine
registers is in exactly one of the two sets (`tests/unit/bench/test_bench_content.py`).
"""

from __future__ import annotations

CONTENT_DETECTORS = frozenset(
    {
        "agent-judge",
        "agents",
        "binary",
        "capability",
        "config",
        "formats",
        "iac",
        "manifest",
        "mcp-packages",
        "model",
        "obfuscated-hook",
        "obfuscation",
        "secrets",
        "vcs",
        # The rule pack and pinned GuardDog source rules: pattern logic over the bytes.
        "yara",
        # Added by the engine after the detectors: the intent layer reads facts it computed from
        # the content, and refuses registry facts by construction (IntentFacts.EXTERNAL).
        "intent",
        # The package verdict's own block (`Verdict.RULE`): the combination of the package's
        # content findings and what kind of package it is, scored over its line -- content-derived,
        # so a block it adds counts as a content catch (G4). It never reads registry facts.
        "verdict",
    }
)

INTEL_DETECTORS = frozenset(
    {
        "advisory",
        "attestation",
        # Matches a package's campaign fingerprints against releases already condemned: known samples.
        "campaign-sibling",
        # Its signature database is largely known samples' signatures and hashes: known malware.
        "clamav",
        "dependency",
        # Emitted by the engine itself: its operational notes, the policy layer, the reviewed
        # registry facts and the release-history comparison.
        "engine",
        "license",
        "lockfile",
        "mcp-live",
        "os-packages",
        "package-policy",
        "policy",
        "provenance",
        # Matches recipe files against the feed's condemned digests: known samples.
        "recipe-digest",
        "registry",
        "registry-review",
        "release-history",
        "sbom",
        "slopsquat",
    }
)

#: Rules a content detector emits from outside knowledge: the package's release history, its
#: registry record, the names of popular packages.
INTEL_RULE_PREFIXES = (
    "SUSPECT.RELEASE.",
    "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.",
    "MALWARE.PACKAGE.PLACEHOLDER_RELEASE.",
    "SUSPECT.TYPOSQUAT.PACKAGE_NAME.",
)

#: A known-sample match in any rule id (`VerdictFeatures.INTEL`).
INTEL_MARKERS = (".KNOWN", ".EXTENSION.REMOVED.")


class Content:
    @staticmethod
    def fails(rule_id: str, severity: str, confidence: str, category: str) -> bool:
        """Whether a finding as emitted trips the default failure gate (`PolicyGate`): the same
        test the scan's exit status made, per finding, so a block can be attributed to the
        findings that caused it."""
        from cordon_scanner.foundation.config import Config
        from cordon_scanner.foundation.models import Category, Confidence, Severity
        from cordon_scanner.foundation.taxonomy import Taxonomy

        policy = Config.default().policy
        if Category(category) in policy.fail_on_categories:
            return True
        if Taxonomy.domain_of(rule_id) in policy.advisory_domains:
            return False
        if Confidence[confidence.upper()] < policy.min_confidence_to_fail:
            return False
        return policy.fail_on_severity is not None and Severity[severity.upper()] >= (
            policy.fail_on_severity
        )

    @staticmethod
    def is_content(rule_id: str, detector: str) -> bool:
        """Whether a finding measures the package's own content."""
        if detector not in CONTENT_DETECTORS:
            return False
        if any(marker in rule_id for marker in INTEL_MARKERS):
            return False
        return not rule_id.startswith(INTEL_RULE_PREFIXES)


__all__ = [
    "CONTENT_DETECTORS",
    "INTEL_DETECTORS",
    "INTEL_MARKERS",
    "INTEL_RULE_PREFIXES",
    "Content",
]
