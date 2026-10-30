"""The rules the dependency detector declares: what each reports, at what severity, and what to do.

The detector id they carry is named here, once: the detector reads it from here.
"""

from __future__ import annotations

from typing import Final

from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)

ABANDONED_RULE = "POLICY.DEPENDENCY.ABANDONED.001"

#: The id every dependency finding carries.
DETECTOR: Final = "dependency"

SOURCE_BUNDLED_RULE: Final = "SUSPECT.DEPENDENCY.SOURCE.BUNDLED.001"
"""A record installing the package does not install (`Dependency.installed`) resolved from outside its
registry: info, never gating, never feeding the verdict -- the record itself carries the risk, so it
stays visible, while the install-set rule (SUSPECT.DEPENDENCY.SOURCE.001) reads installed records only."""

DECLARED_RULES: tuple[DeclaredRule, ...] = (
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.TYPOSQUAT.001",
        title="Dependency name is one edit from a popular package",
        # The declared ceiling. A look-alike spelling reaches HIGH; a
        # plain ASCII near-miss is reported at MEDIUM, because offline
        # name distance cannot support more than that.
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "This dependency's name differs by a single character from a widely used "
            "package. That is what a typo produces and what a typosquat is built to "
            "collect, and the two are indistinguishable from the name alone."
        ),
        references=(references.DEPENDENCY_CONFUSION,),
        remediation="Confirm the name against the registry before installing.",
    ),
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.SOURCE.001",
        title="Dependency resolved from outside the registry",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The dependency resolves from a host that is not its ecosystem's "
            "registry and is not a configured mirror, so advisory matching and "
            "release-age policy do not reach it. Where a package came from "
            "decides what installed, whatever the name and version say."
        ),
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        remediation="Pin the dependency to the registry, or vendor it deliberately.",
    ),
    DeclaredRule(
        id=SOURCE_BUNDLED_RULE,
        title="A dependency the package bundles but does not install resolves from outside the registry",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "Only a nested or vendored file in this package records the dependency -- a lockfile of "
            "its maintainers' environment, a bundled UI's own lockfile -- and it resolves from a "
            "host that is not its ecosystem's registry. Installing the package does not resolve it."
        ),
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        remediation="If the bundled files are built or served, check where that source comes from.",
    ),
    DeclaredRule(
        id=ABANDONED_RULE,
        title="Dependency is abandoned by its maintainer",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "The lockfile records the package as abandoned (Composer writes what Packagist "
            "says). Nothing will be fixed in it, security fixes included."
        ),
        references=(references.INSECURE_DEFAULT,),
        remediation="Move to the replacement the maintainer names, or a maintained alternative.",
    ),
    DeclaredRule(
        id="POLICY.DEPENDENCY.INTEGRITY.001",
        title="Dependency has no integrity hash",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "This dependency is recorded without a hash, so nothing checks that what "
            "arrives is what was resolved. A version number says what was asked for and "
            "nothing about what was served."
        ),
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        remediation="Regenerate the lockfile with integrity hashes enabled.",
    ),
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.CONFUSION.001",
        title="Internal package name resolved from a public registry",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "A name this project treats as internal resolves from a public registry. "
            "Whoever registered it there decides what installs, which is the whole of "
            "the dependency-confusion attack -- no compromise of the private registry "
            "is needed."
        ),
        references=(references.DEPENDENCY_CONFUSION,),
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
        detector=DETECTOR,
        message=(
            "The dependency is declared as a URL, a git reference or a local path "
            "rather than a registry package. Lockfile integrity hashes, advisory "
            "matching and any release-age delay all apply to registry packages and none "
            "of them applies here."
        ),
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        remediation="Prefer registry releases, which are immutable and auditable.",
    ),
)

__all__ = ["ABANDONED_RULE", "DECLARED_RULES", "DETECTOR"]
