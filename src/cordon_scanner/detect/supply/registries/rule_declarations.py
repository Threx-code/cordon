"""The rules the registry detector declares: what each reports, at what severity, and what to do.

The detector id they carry is named here, once: the detector and its findings read it from here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)

if TYPE_CHECKING:
    pass

#: The id every registry finding carries.
DETECTOR: Final = "registry"

DECLARED_RULES: tuple[DeclaredRule, ...] = (
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.YANKED.001",
        title="Dependency pins a version its publisher withdrew",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The publisher withdrew this version. A yank is the strongest signal a "
            "registry offers short of deletion, and it usually means the release was "
            "broken, mis-published or compromised."
        ),
        references=(references.PYPI_YANK,),
        remediation=(
            "Move off the withdrawn version. A release is yanked because "
            "its publisher decided nobody should be installing it."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.PACKAGE.STARJACKING.001",
        title="A new package claims a popular project's repository",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "A package published in the last ninety days names, as its source, the repository of "
            "a different and popular package. The registry shows that repository's stars and "
            "history beside it, which is the trust a squat borrows (starjacking)."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation=(
            "Check that the package is really published by that project; if it is not, remove it "
            "and install the package the repository actually publishes."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001",
        title="Dependency pins a version its publisher deprecated for a security reason",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The publisher deprecated this version and the notice names a vulnerability, a "
            "compromise or malicious code. Publishers deprecate rather than unpublish when "
            "npm will not let them remove a release, so this is often the only warning."
        ),
        references=(references.INSECURE_DEFAULT,),
        remediation="Move to the version the notice names, and check whether the deprecated one ran anywhere.",
    ),
    DeclaredRule(
        id="POLICY.DEPENDENCY.DEPRECATED.001",
        title="Dependency pins a version its publisher deprecated",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "The publisher marked this version deprecated, or the project declares itself "
            "inactive. Nothing will be fixed in it, security fixes included."
        ),
        references=(references.INSECURE_DEFAULT,),
        remediation="Move to the replacement the notice names, or a maintained alternative.",
    ),
    DeclaredRule(
        id="POLICY.DEPENDENCY.UNMAINTAINED.001",
        title="Dependency has had no release in five years",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "The package's last release is more than five years old. Finished is not the "
            "same as abandoned, and an abandoned package is one whose next vulnerability "
            "will not be fixed, and whose name is the one a takeover would target."
        ),
        references=(references.INSECURE_DEFAULT,),
        remediation="Confirm it is finished rather than abandoned, or plan a maintained replacement.",
    ),
    DeclaredRule(
        id="POLICY.DEPENDENCY.DOWNGRADE.001",
        references=(references.INSECURE_DEFAULT,),
        title="Dependency pins a version far behind the current release",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "The pinned version trails the current release by a wide margin. Old is not "
            "the same as vulnerable, and it does mean fixes published since have not "
            "been taken."
        ),
        remediation=(
            "Confirm the pin is deliberate. A distant pin is ordinary in a "
            "conservative project and is also what a downgrade attack "
            "produces."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.PROVENANCE.MISMATCH.001",
        title="Lockfile hash disagrees with the registry",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The hash in the lockfile is not the hash the registry serves for that "
            "version. One of the two changed after the other was recorded, and until it "
            "is known which, the artefact that installs is not the one that was "
            "reviewed."
        ),
        references=(
            references.INSUFFICIENT_VERIFICATION,
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
        ),
        remediation=(
            "Do not install. One of the two records is not describing the "
            "artefact that will arrive, and until that is resolved neither "
            "can be trusted."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.PACKAGE.REPOSITORY.001",
        title="Package claims a source repository the registry does not record",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The package's stated source repository disagrees with what the registry "
            "holds. Whoever reads the source to decide whether to trust the package may "
            "not be reading the source the package was built from."
        ),
        references=(references.INSUFFICIENT_VERIFICATION,),
        remediation=(
            "Establish which repository the published artefact was "
            "actually built from. Reading the linked source proves "
            "nothing about the package while the two disagree."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.PACKAGE.PROVENANCE.001",
        title="Version published without the provenance its package normally carries",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "Earlier releases of this package carry build provenance and this one does "
            "not. A publishing pipeline that stops attesting for one version is worth "
            "understanding before that version is trusted."
        ),
        references=(references.SLSA_PROVENANCE,),
        remediation=(
            "Establish where this release was built. Its siblings can "
            "be traced to a commit and a workflow and this one cannot, "
            "which is the difference a compromised publishing token "
            "produces."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.UNVETTED.001",
        title="A dependency is new, sourceless and unknown: the shape of a slopsquatted package",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The registry says this package is under three months old and records no source "
            "repository, and it is either barely downloaded or named by adding a generic word "
            "to an established package. AI coding assistants suggest names like these, and "
            "attackers register them."
        ),
        references=(references.PACKAGE_HALLUCINATION,),
        remediation=(
            "Confirm the package is the one you meant: check its publisher and code, or replace "
            "it with the established package it was named after."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.DEPENDENCY.UNREGISTERED.001",
        title="A dependency does not exist on its public registry",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The public registry has no package by this name. Either it is private, and "
            "anyone who registers the name publicly can have their package installed in its "
            "place (dependency confusion), or the name was invented -- AI coding assistants "
            "suggest plausible package names that do not exist, and attackers register them "
            "(slopsquatting)."
        ),
        references=(references.DEPENDENCY_CONFUSION, references.PACKAGE_HALLUCINATION),
        remediation=(
            "If the package is private, resolve it only from your private registry (a scoped "
            "registry for npm, `--index-url` without `--extra-index-url` for pip) and register "
            "the name publicly as a placeholder. If nobody can say where it came from, remove it."
        ),
    ),
    DeclaredRule(
        id="OPERATIONAL.REGISTRY.UNREACHABLE.001",
        title="Registry could not be asked about a dependency",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        category=Category.OPERATIONAL,
        detector=DETECTOR,
        message=(
            "A registry lookup failed. The package is neither confirmed good nor "
            "confirmed bad, and reporting that is the only honest outcome."
        ),
        remediation=(
            "Rerun when the registry is reachable, or accept that these checks did not run."
        ),
    ),
    DeclaredRule(
        id="OPERATIONAL.REGISTRY.NO_SOURCE.001",
        title="No registry is configured for part of the dependency graph",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        category=Category.OPERATIONAL,
        detector=DETECTOR,
        message=(
            "Some of the graph belongs to an ecosystem no registry was configured for, "
            "so nothing could be asked about those packages at all."
        ),
        remediation=(
            "None needed if the ecosystem is not one you gate on. The online "
            "checks cover npm, PyPI, crates.io, RubyGems, NuGet, Go, Maven "
            "Central, Packagist, pub.dev and Hex; for anything else the offline "
            "rules are the whole answer."
        ),
    ),
    DeclaredRule(
        id="OPERATIONAL.REGISTRY.NOT_ASKED.001",
        title="Dependencies past the query ceiling or time budget were never asked about",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        category=Category.OPERATIONAL,
        detector=DETECTOR,
        message=(
            "The scan stopped asking the registry before the graph ran out. Everything "
            "past that point is unexamined rather than clean, and this finding is what "
            "keeps the two distinguishable."
        ),
        remediation=(
            "Raise --timeout, or narrow the scan so the budget covers the graph. "
            "A package nobody asked about is not a package that came back clean."
        ),
    ),
)

__all__ = ["DECLARED_RULES", "DETECTOR"]
