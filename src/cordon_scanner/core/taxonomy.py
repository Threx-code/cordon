"""The threat taxonomy every finding is placed in.

A report that lists "critical" thirty times says less than it appears to. A
leaked credential, a vulnerable dependency, a public security group and a
package that runs a downloader at install time are four different problems with
four different owners, four different response times, and only the word
"critical" in common. Without a classification the reader has to rebuild that
distinction from rule names every time, and a policy cannot express "block
malware, ticket the misconfigurations" at all.

Two axes, because they answer different questions:

**Threat domain** -- *where in the supply chain the attack lives*. The fourteen
domains are the coverage taxonomy: source and VCS identity, dependencies,
registries, build systems, CI/CD, install-time malware, obfuscation,
credentials, exfiltration, containers, infrastructure as code, binaries,
provenance, and the scanner itself. This is what a coverage matrix has rows for,
and what tells a reader which part of their pipeline a finding is about.

**Attack category** -- *what is being done*. Typosquatting and dependency
confusion are both dependency-domain problems and entirely different attacks;
grouping them by domain alone loses that, and grouping by attack alone loses
where to look.

**Derived from the rule id, not supplied at each call site.** Every detector
would otherwise have to remember two more arguments, and the ones that forgot
would emit unclassified findings that no filter matches and no matrix counts --
a silent hole, and this project treats silent holes as the failure mode to
design against. Rule ids are already structured, so the mapping is a table, and
a test asserts every declared rule resolves through it. Detectors may still pass
the fields explicitly where the id is not specific enough.
"""

from __future__ import annotations

import enum


class ThreatDomain(enum.StrEnum):
    """Where in the supply chain a finding lives.

    Values are the stable identifiers used in reports, the coverage matrix and
    policy files, so they are written out rather than derived from the member
    name.
    """

    SOURCE = "source"
    """Domain 1. The repository and its history: VCS identity, submodules,
    polyglot files, anything about the code's own provenance."""

    DEPENDENCY = "dependency"
    """Domain 2. What the project pulls in: typosquats, confusion, downgrades,
    known-vulnerable versions."""

    REGISTRY = "registry"
    """Domain 3. The distribution point: package-versus-repository mismatch,
    maintainer changes, publication anomalies."""

    BUILD = "build"
    """Domain 4. Build systems that execute: Make, Gradle, Maven, Cargo,
    MSBuild, CMake."""

    CICD = "cicd"
    """Domain 5. Pipelines: workflow definitions, secret exposure, expression
    injection, artifact and cache poisoning."""

    MALWARE = "malware"
    """Domain 6. Code whose purpose is harm: install hooks, droppers,
    cryptominers, credential stealers."""

    OBFUSCATION = "obfuscation"
    """Domain 7. Hiding what the code does: encoding, packing, bidirectional
    text, dynamic dispatch, anti-analysis."""

    CREDENTIAL = "credential"
    """Domain 8. Secrets: committed credentials and access to credential
    stores."""

    EXFILTRATION = "exfiltration"
    """Domain 9. Getting data out: HTTP, DNS, webhooks, mail, sockets."""

    CONTAINER = "container"
    """Domain 10. Images and orchestration: Dockerfiles, Kubernetes, Helm."""

    INFRASTRUCTURE = "infrastructure"
    """Domain 11. Infrastructure as code: Terraform, CloudFormation, Ansible,
    Pulumi, Compose."""

    BINARY = "binary"
    """Domain 12. Compiled artefacts committed to a source tree."""

    PROVENANCE = "provenance"
    """Domain 13. Whether an artefact is what it claims to be: integrity
    hashes, attestations, SBOM reconciliation."""

    SCANNER = "scanner"
    """Domain 14. Attacks on the analysis itself, and the scan's own integrity:
    coverage, parser failures, policy weakening."""

    UNSPECIFIED = "unspecified"
    """No domain claimed. Reserved for findings that genuinely have none, and
    asserted against for every declared rule."""


class AttackCategory(enum.StrEnum):
    """What is being attempted, independent of where."""

    MALICIOUS_CODE = "malicious_code"
    """Code that acts against the developer running it."""

    INSTALL_HOOK = "install_hook"
    """Execution at install or build time, before any other control applies."""

    DROPPER = "dropper"
    """Fetching a payload and running it."""

    EXFILTRATION = "exfiltration"
    """Moving data to somewhere the owner did not choose."""

    CRYPTOMINING = "cryptomining"
    """Spending someone else's compute."""

    PERSISTENCE = "persistence"
    """Arranging to run again."""

    OBFUSCATION = "obfuscation"
    """Concealing the above."""

    ANTI_ANALYSIS = "anti_analysis"
    """Behaving differently when observed."""

    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105  (a category name, not a credential)
    """A credential where it can be read."""

    TYPOSQUAT = "typosquat"
    """A name chosen to be mistaken for another."""

    DEPENDENCY_CONFUSION = "dependency_confusion"
    """A public name shadowing a private one."""

    VULNERABILITY = "vulnerability"
    """A known weakness in something depended on. Not an attack -- a
    liability -- and kept distinct because the response is different."""

    MISCONFIGURATION = "misconfiguration"
    """A setting that exposes or over-permits. Also not an attack."""

    INTEGRITY = "integrity"
    """An artefact that cannot be shown to be what it claims."""

    COVERAGE = "coverage"
    """Something the scan did not examine. The category that must never be
    silent."""

    POLICY = "policy"
    """A configured decision, or a departure from one."""

    UNSPECIFIED = "unspecified"


_DOMAIN_BY_PREFIX: tuple[tuple[str, ThreatDomain], ...] = (
    # Longest prefix wins, so the table is ordered most specific first and
    # matched in order. A shorter prefix appearing earlier would swallow every
    # rule beneath it.
    ("SECRET.", ThreatDomain.CREDENTIAL),
    ("VULNERABLE.", ThreatDomain.DEPENDENCY),
    ("MALWARE.CI.", ThreatDomain.CICD),
    ("SUSPECT.CI.", ThreatDomain.CICD),
    ("POLICY.CI.", ThreatDomain.CICD),
    ("SUSPECT.CONTAINER.", ThreatDomain.CONTAINER),
    ("SUSPECT.K8S.", ThreatDomain.CONTAINER),
    ("POLICY.K8S.", ThreatDomain.CONTAINER),
    ("SUSPECT.HELM.", ThreatDomain.CONTAINER),
    ("SUSPECT.IAC.", ThreatDomain.INFRASTRUCTURE),
    ("POLICY.IAC.", ThreatDomain.INFRASTRUCTURE),
    ("SUSPECT.DEPENDENCY.", ThreatDomain.DEPENDENCY),
    ("POLICY.DEPENDENCY.", ThreatDomain.DEPENDENCY),
    ("SUSPECT.TYPOSQUAT.", ThreatDomain.DEPENDENCY),
    ("SUSPECT.PACKAGE.", ThreatDomain.REGISTRY),
    ("SUSPECT.BUILD.", ThreatDomain.BUILD),
    ("MALWARE.BUILD.", ThreatDomain.BUILD),
    ("SUSPECT.BINARY.", ThreatDomain.BINARY),
    ("SUSPECT.VCS.", ThreatDomain.SOURCE),
    ("SUSPECT.SUBMODULE.", ThreatDomain.SOURCE),
    ("SUSPECT.POLYGLOT.", ThreatDomain.SOURCE),
    ("SUSPECT.PROVENANCE.", ThreatDomain.PROVENANCE),
    ("POLICY.PROVENANCE.", ThreatDomain.PROVENANCE),
    ("SUSPECT.SBOM.", ThreatDomain.PROVENANCE),
    ("SUSPECT.OBFUSCATION.", ThreatDomain.OBFUSCATION),
    ("SUSPECT.DYNAMIC_DISPATCH.", ThreatDomain.OBFUSCATION),
    ("MALWARE.DYNAMIC_DISPATCH.", ThreatDomain.OBFUSCATION),
    ("SUSPECT.ANTI_ANALYSIS.", ThreatDomain.OBFUSCATION),
    ("SUSPECT.EXFIL.", ThreatDomain.EXFILTRATION),
    ("MALWARE.EXFIL.", ThreatDomain.EXFILTRATION),
    ("SUSPECT.INSTALL.", ThreatDomain.MALWARE),
    ("MALWARE.INSTALL.", ThreatDomain.MALWARE),
    ("SUSPECT.DROPPER.", ThreatDomain.MALWARE),
    ("MALWARE.DROPPER.", ThreatDomain.MALWARE),
    ("SUSPECT.DECODE_EXEC.", ThreatDomain.OBFUSCATION),
    ("MALWARE.DECODE_EXEC.", ThreatDomain.OBFUSCATION),
    ("SUSPECT.CRYPTOMINER.", ThreatDomain.MALWARE),
    ("MALWARE.CRYPTOMINER.", ThreatDomain.MALWARE),
    ("SUSPECT.PERSIST.", ThreatDomain.MALWARE),
    ("MALWARE.PERSIST.", ThreatDomain.MALWARE),
    ("OPERATIONAL.", ThreatDomain.SCANNER),
    ("POLICY.COVERAGE.", ThreatDomain.SCANNER),
    ("POLICY.PLUGIN.", ThreatDomain.SCANNER),
    ("POLICY.CONFIG.", ThreatDomain.SCANNER),
    ("POLICY.SUPPRESSION.", ThreatDomain.SCANNER),
    ("CAP.", ThreatDomain.OBFUSCATION),
    ("AST.", ThreatDomain.OBFUSCATION),
    ("INTEL.", ThreatDomain.EXFILTRATION),
    # Broadest last: a malicious or suspicious rule with no more specific
    # prefix is about code that acts against the developer.
    ("MALWARE.", ThreatDomain.MALWARE),
    ("SUSPECT.", ThreatDomain.MALWARE),
    ("POLICY.", ThreatDomain.SCANNER),
)

_CATEGORY_BY_PREFIX: tuple[tuple[str, AttackCategory], ...] = (
    ("SECRET.", AttackCategory.SECRET_EXPOSURE),
    ("VULNERABLE.", AttackCategory.VULNERABILITY),
    ("SUSPECT.TYPOSQUAT.", AttackCategory.TYPOSQUAT),
    ("SUSPECT.DEPENDENCY.CONFUSION.", AttackCategory.DEPENDENCY_CONFUSION),
    ("SUSPECT.DEPENDENCY.", AttackCategory.POLICY),
    ("POLICY.DEPENDENCY.", AttackCategory.POLICY),
    ("SUSPECT.INSTALL.", AttackCategory.INSTALL_HOOK),
    ("MALWARE.INSTALL.", AttackCategory.INSTALL_HOOK),
    ("SUSPECT.DROPPER.", AttackCategory.DROPPER),
    ("MALWARE.DROPPER.", AttackCategory.DROPPER),
    ("SUSPECT.EXFIL.", AttackCategory.EXFILTRATION),
    ("MALWARE.EXFIL.", AttackCategory.EXFILTRATION),
    ("MALWARE.CI.SECRET_EXFIL.", AttackCategory.EXFILTRATION),
    ("SUSPECT.CRYPTOMINER.", AttackCategory.CRYPTOMINING),
    ("MALWARE.CRYPTOMINER.", AttackCategory.CRYPTOMINING),
    ("SUSPECT.PERSIST.", AttackCategory.PERSISTENCE),
    ("MALWARE.PERSIST.", AttackCategory.PERSISTENCE),
    ("SUSPECT.ANTI_ANALYSIS.", AttackCategory.ANTI_ANALYSIS),
    ("SUSPECT.OBFUSCATION.", AttackCategory.OBFUSCATION),
    ("SUSPECT.DYNAMIC_DISPATCH.", AttackCategory.OBFUSCATION),
    ("MALWARE.DYNAMIC_DISPATCH.", AttackCategory.OBFUSCATION),
    ("SUSPECT.DECODE_EXEC.", AttackCategory.OBFUSCATION),
    ("MALWARE.DECODE_EXEC.", AttackCategory.OBFUSCATION),
    ("SUSPECT.PROVENANCE.", AttackCategory.INTEGRITY),
    ("POLICY.PROVENANCE.", AttackCategory.INTEGRITY),
    ("SUSPECT.SBOM.", AttackCategory.INTEGRITY),
    ("SUSPECT.BINARY.", AttackCategory.INTEGRITY),
    ("SUSPECT.POLYGLOT.", AttackCategory.OBFUSCATION),
    ("SUSPECT.VCS.", AttackCategory.INTEGRITY),
    ("SUSPECT.SUBMODULE.", AttackCategory.INTEGRITY),
    ("SUSPECT.PACKAGE.", AttackCategory.INTEGRITY),
    ("OPERATIONAL.", AttackCategory.COVERAGE),
    ("POLICY.COVERAGE.", AttackCategory.COVERAGE),
    ("POLICY.", AttackCategory.POLICY),
    ("SUSPECT.CI.", AttackCategory.MISCONFIGURATION),
    ("SUSPECT.CONTAINER.", AttackCategory.MISCONFIGURATION),
    ("SUSPECT.K8S.", AttackCategory.MISCONFIGURATION),
    ("SUSPECT.HELM.", AttackCategory.MISCONFIGURATION),
    ("SUSPECT.IAC.", AttackCategory.MISCONFIGURATION),
    ("SUSPECT.BUILD.", AttackCategory.MALICIOUS_CODE),
    ("MALWARE.BUILD.", AttackCategory.MALICIOUS_CODE),
    ("CAP.", AttackCategory.UNSPECIFIED),
    ("AST.", AttackCategory.UNSPECIFIED),
    ("INTEL.", AttackCategory.UNSPECIFIED),
    ("MALWARE.", AttackCategory.MALICIOUS_CODE),
    ("SUSPECT.", AttackCategory.MALICIOUS_CODE),
)


def domain_of(rule_id: str) -> ThreatDomain:
    """Which part of the supply chain a rule is about."""
    for prefix, domain in _DOMAIN_BY_PREFIX:
        if rule_id.startswith(prefix):
            return domain
    return ThreatDomain.UNSPECIFIED


def category_of(rule_id: str) -> AttackCategory:
    """What a rule says is being attempted."""
    for prefix, category in _CATEGORY_BY_PREFIX:
        if rule_id.startswith(prefix):
            return category
    return AttackCategory.UNSPECIFIED


__all__ = ["AttackCategory", "ThreatDomain", "category_of", "domain_of"]
