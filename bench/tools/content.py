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
        # Item 47's learned code model: it reads only the package's own reached files; its weights are
        # shipped data fitted offline, not a feed of known samples.
        "code-model",
        "config",
        "formats",
        "iac",
        "manifest",
        "mcp-packages",
        "model",
        "obfuscated-hook",
        "obfuscation",
        # A pack's own reporting rules: pattern logic over the bytes, as `rule-file` below. Measurement
        # scans run offline with no `--rules`, so no feed-delivered pack is in a content number.
        "pack-rules",
        "secrets",
        "vcs",
        # The rule pack and pinned GuardDog source rules: pattern logic over the bytes.
        "rule-file",
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
        # Matches code files and install-hook shapes against an index built from earlier malware
        # (intel/malware/reuse_index.py): known samples, so items 54 and 65 count in the intel bar.
        "code-reuse",
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
        from cordon_scanner.foundation.config.settings import Config
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

    @staticmethod
    def gap_blocked(row: dict) -> bool:
        """Whether a scan row was blocked as unreadable or incomplete by the package's own bytes: its
        content is incomplete and one of `CONTENT_GAPS` says why. A harness or infrastructure
        failure (an error, a timeout, a memory limit, a detector crash) never counts. Reported as its
        own line beside "caught by a content finding", never folded into it (cordon-47, 2026-11-07)."""
        if row.get("error") or str(row.get("exit")) in ("timeout", "None"):
            return False
        if row.get("content_complete") is not False:
            return False
        return any(f[0] in CONTENT_GAPS for f in row.get("findings") or ())


#: The gaps the package's own bytes cause, which count as blocked in the unknown bar ("blocked as
#: unreadable/incomplete"): source it runs that does not parse, code its install runs that it does
#: not ship, and archive members refused by its bombs, padding or nesting. Not here, so never
#: counted on the malware side: formats or readers we lack, memory limits, timeouts, crashes.
CONTENT_GAPS = frozenset(
    {
        "OPERATIONAL.SOURCE.UNPARSED",
        "OPERATIONAL.MANIFEST.UNPARSED",
        "OPERATIONAL.INSTALL.CODE_NOT_SHIPPED",
        "OPERATIONAL.ARCHIVE.MEMBER_REJECTED",
        "OPERATIONAL.ARCHIVE.REJECTED",
    }
)


__all__ = [
    "CONTENT_DETECTORS",
    "CONTENT_GAPS",
    "INTEL_DETECTORS",
    "INTEL_MARKERS",
    "INTEL_RULE_PREFIXES",
    "Content",
]
