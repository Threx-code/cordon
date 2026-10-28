"""The rules the advisory detector declares: what each reports, at what severity, and what to do."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.supply.advisories.findings import (
    EXPLOITED_RULE,
    MALICIOUS_RULE,
    PLACEHOLDER_RULE,
    PROVISIONAL_RULE,
    REMOVED_RULE,
    VULNERABLE_RULE,
    AdvisoryFinding,
)
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)
from cordon_scanner.intel.advisories import exploited

if TYPE_CHECKING:
    pass

DECLARED_RULES: tuple[DeclaredRule, ...] = (
    DeclaredRule(
        id=MALICIOUS_RULE,
        title="Dependency is a known-malicious release",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=Category.MALICIOUS,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "A version in this project's dependency graph is named by an advisory as "
            "malicious rather than merely vulnerable. The distinction is what the "
            "advisory asserts: not that the code has a flaw, but that it was published "
            "to do harm. Installing it ran whatever it carried, as the installing user."
        ),
        references=(references.OSV,),
        remediation=(
            "Remove the version and treat every machine that installed it as compromised."
        ),
    ),
    DeclaredRule(
        id=PROVISIONAL_RULE,
        title="Dependency version is held for review",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "Cordon's feed holds this exact version for review: it was flagged as "
            "malicious by one signal and a second signal or a person has not yet "
            "confirmed or cleared it. Installs of it are paused until they do. Other "
            "versions of the package are not affected."
        ),
        remediation=(
            "Pin the previous version until the hold is decided, usually within the hour; "
            "the hold lifts by itself if the verdict is cleared."
        ),
        references=(references.OSV,),
    ),
    DeclaredRule(
        id=REMOVED_RULE,
        title="Dependency names a removed malicious package",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "A declared range names a package whose every version is recorded as "
            "malicious, and which its registry no longer serves. An install fails "
            "rather than installing the malware; whoever registers the name again "
            "would have their code installed by this project."
        ),
        remediation=(
            "Remove the dependency, or replace it with the package it was meant to be "
            "(a removed malicious name is usually a squat of a real one)."
        ),
        references=(references.OSV,),
    ),
    DeclaredRule(
        id=PLACEHOLDER_RULE,
        title="Dependency pins npm's security placeholder",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=Category.POLICY,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "The package name was used to publish malware and npm's security "
            "team took it over, replacing every release with an empty package "
            "at a `-security` version. Pinning that placeholder is what "
            "remediation leaves behind: nothing malicious installs, and the "
            "dependency does nothing at all."
        ),
        remediation=(
            "Remove the dependency, or replace it with the package that "
            "provides what it was there for."
        ),
        references=(references.OSV,),
    ),
    DeclaredRule(
        id=VULNERABLE_RULE,
        title="Dependency has a known vulnerability",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category=Category.VULNERABLE,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "A version in the dependency graph is named by a published advisory. The "
            "match is on the resolved version rather than the declared range, so it "
            "describes what would actually install."
        ),
        references=(references.OSV,),
        remediation="Upgrade to a version the advisory does not name.",
    ),
    DeclaredRule(
        id=EXPLOITED_RULE,
        title="Dependency has a vulnerability that is exploited in the wild",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=Category.VULNERABLE,
        detector=AdvisoryFinding.DETECTOR,
        message=(
            "A version in the dependency graph is named by an advisory whose CVE is on "
            "CISA's Known Exploited Vulnerabilities catalogue or ENISA's EUVD exploited "
            "list: attackers are using it, not merely able to."
        ),
        references=(references.OSV, exploited.KEV_PAGE, exploited.EUVD_PAGE),
        remediation=(
            "Upgrade now, ahead of other advisories. Under the EU Cyber Resilience Act an "
            "actively exploited vulnerability in a product you ship is reportable within "
            "24 hours of becoming aware of it."
        ),
    ),
)

__all__ = ["DECLARED_RULES"]
