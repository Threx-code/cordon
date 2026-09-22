"""Verifies the build provenance a dependency advertises.

The registry detector reports whether a release *carries* an attestation. This
one asks whether that attestation is real: it fetches the sigstore bundle the
registry points at, verifies it against the digest the lockfile pinned, and
requires the signing certificate's identity to match the source repository the
package declares. The two together are what a stolen-token attack cannot fake --
the malicious upload still names the honest repository, but it was not built by
that repository's workflow and cannot produce a certificate that says it was.

The heavy verification is delegated to `intel.attest` (the `[attest]` extra). A
release that cannot be verified -- the extra is absent, the digest is not
pinned, the registry serves no usable bundle, or the declared repository is on a
forge the identity policy does not cover -- is reported as unverified, never as
a failure and never silently: "we did not check" and "we checked and it failed"
are opposite facts, and only the second is a finding to act on.

Network, so it runs only when the scan is taken online, exactly like the
registry detector it complements.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.registry import NETWORK_CAVEAT, repository_identity
from cordon_scanner.intel import attest

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import Unit

INVALID_RULE = "VULNERABLE.PROVENANCE.INVALID.001"
UNVERIFIED_RULE = "POLICY.PROVENANCE.UNVERIFIED.001"
UNCHECKED_RULE = "OPERATIONAL.PROVENANCE.NOT_CHECKED.001"

#: Ecosystems whose attestation format this can fetch and convert. Others carry
#: no publish-time attestation to verify yet, so the detector stays silent for
#: them rather than reporting an absence that means nothing.
SUPPORTED_ECOSYSTEMS = frozenset({"npm", "pypi"})

_GITHUB_OWNER_REPO = re.compile(r"github\.com[:/]+([^/]+)/([^/#?]+)", re.IGNORECASE)


class ProvenanceDetector(BaseDetector):
    """Verifies, rather than merely observes, a dependency's attestation."""

    id = "provenance"
    version = "0.1.0"
    categories = frozenset({Category.VULNERABLE, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=False, dependencies=True, network=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies) and not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=INVALID_RULE,
                title="Dependency's build attestation fails verification",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.VULNERABLE,
                detector=ProvenanceDetector.id,
                remediation=(
                    "Do not install. The attestation does not verify against the "
                    "pinned artefact, or it was signed by an identity other than "
                    "the repository the package claims -- which is what a build "
                    "published from a stolen token looks like."
                ),
            ),
            DeclaredRule(
                id=UNVERIFIED_RULE,
                title="Dependency advertises an attestation that could not be verified",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=ProvenanceDetector.id,
                remediation=(
                    "Install the [attest] extra and pin the dependency's digest so "
                    "the attestation can be checked, or accept that its provenance "
                    "is asserted rather than proven."
                ),
            ),
            DeclaredRule(
                id=UNCHECKED_RULE,
                title="Build provenance was not checked for part of the graph",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=ProvenanceDetector.id,
                remediation=(
                    "Raise --timeout, or narrow the scan so the budget covers the "
                    "graph. A package whose provenance nobody looked at has not been "
                    "shown to have any."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.offline or not isinstance(unit, GraphUnit):
            return ()

        # Bounded the same way the registry detector is, and for a sharper
        # reason: verifying one dependency costs a packument, an attestation
        # fetch and a trust-root check, so an unbounded pass over a large
        # lockfile is the slowest thing the scanner can be asked to do. Direct
        # dependencies first, so a truncated pass spends the budget where
        # provenance is most likely to be claimed.
        from cordon_scanner.detect.registry import MAX_QUERIES, RegistryDetector

        candidates = [
            d
            for d in RegistryDetector._order(unit.dependencies)
            if d.ecosystem in SUPPORTED_ECOSYSTEMS and d.version
        ]
        findings: list[Finding] = []
        for index, dependency in enumerate(candidates[:MAX_QUERIES]):
            if ctx.out_of_time():
                findings.append(
                    self._not_checked(
                        ctx,
                        len(candidates) - index,
                        len(candidates),
                        "the scan's time budget ran out",
                    )
                )
                return findings
            findings.extend(self._verify(dependency, ctx))

        if len(candidates) > MAX_QUERIES:
            findings.append(
                self._not_checked(
                    ctx,
                    len(candidates) - MAX_QUERIES,
                    len(candidates),
                    f"they are past the {MAX_QUERIES}-query ceiling for one scan",
                )
            )
        return findings

    def _not_checked(self, ctx: ScanContext, skipped: int, total: int, why: str) -> Finding:
        """Report the dependencies whose provenance was never looked at."""
        return self._finding(
            UNCHECKED_RULE,
            ctx,
            dependency=None,
            detail=(
                f"{skipped} of {total} package(s) had their build provenance left "
                f"unchecked because {why}. Provenance was not verified for them, "
                f"which is not the same as their provenance being sound."
            ),
            degrades_coverage=True,
        )

    def _verify(self, dependency: Dependency, ctx: ScanContext) -> Iterable[Finding]:
        from cordon_scanner.intel.registry_client import RegistryError, attestation_payload, facts

        try:
            observed = facts(dependency.ecosystem, dependency.name, dependency.version)
        except RegistryError:
            # The registry detector already reports the unreachable case. A
            # second finding here would only double the noise for one outage.
            return
        if not observed.attested:
            # No attestation to verify. Its absence, where siblings have one, is
            # the registry detector's SUSPECT.PACKAGE.PROVENANCE finding.
            return

        digest = attest.parse_integrity(dependency.integrity)
        if digest is None:
            # Two different situations, and telling a reader the wrong one sends
            # them to fix the wrong thing: a lockfile with no hash at all needs
            # one added, while a lockfile whose hash is not an artefact digest
            # (Yarn Berry records a cache checksum) has nothing to add.
            why = (
                "no artefact digest is pinned for it"
                if not (dependency.integrity or "").strip()
                else "the hash recorded for it is not an artefact digest"
            )
            yield self._finding(
                UNVERIFIED_RULE,
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{dependency.version} advertises a build attestation, "
                    f"but {why}, so there is nothing to bind the attestation to"
                ),
            )
            return

        payload = attestation_payload(dependency.ecosystem, dependency.name, dependency.version)
        bundles = attest.extract_bundles(dependency.ecosystem, payload)
        if not bundles:
            reason = (
                "the [attest] extra is not installed"
                if not attest.available()
                else "the registry served no verifiable attestation bundle"
            )
            yield self._finding(
                UNVERIFIED_RULE,
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{dependency.version} advertises a build attestation "
                    f"that could not be verified: {reason}"
                ),
            )
            return

        source = self._source_identity(observed.repository)
        algorithm, digest_hex = digest

        # Every bundle is tried before anything is reported. A registry serves
        # several -- npm publishes the SLSA provenance and its own publish
        # attestation, in two bundle media types -- and one that this verifier's
        # sigstore version cannot read is one fewer answer, not a rejection.
        # Stopping at the first failure let an unreadable bundle decide the
        # verdict for a package whose next bundle verified.
        results = [
            attest.verify(
                bundle,
                digest_hex=digest_hex,
                algorithm=algorithm,
                source_repo=source,
                offline=False,
            )
            for bundle in bundles
        ]
        if any(r.outcome is attest.Outcome.VERIFIED for r in results):
            return  # A verified attestation is the clean case: no finding.

        # A rejection outranks an inability to check: one bundle that verified
        # cryptographically and then failed on identity or subject is the
        # actionable fact, whatever the others could not answer.
        last = next(
            (r for r in results if r.outcome is attest.Outcome.INVALID),
            results[-1] if results else None,
        )

        if last is not None and last.outcome is attest.Outcome.INVALID:
            yield self._finding(
                INVALID_RULE,
                ctx,
                dependency=dependency,
                detail=(
                    f"the build attestation for {dependency.name}@{dependency.version} "
                    f"did not verify: {last.detail}"
                ),
            )
        else:
            yield self._finding(
                UNVERIFIED_RULE,
                ctx,
                dependency=dependency,
                detail=(
                    f"the build attestation for {dependency.name}@{dependency.version} "
                    f"could not be verified: {last.detail if last else 'no result'}"
                ),
            )

    @staticmethod
    def _source_identity(repository: str | None) -> tuple[str, str, str] | None:
        """The declared source repo as `(forge, owner, name)`, GitHub case kept.

        `repository_identity` lowercases for its own comparison, but the OIDC
        `repository` claim on the signing certificate keeps the repository's
        stored case, so an exact identity match must too. Recover the original
        case from the raw URL where the forge is GitHub, which is the only forge
        the identity policy covers.
        """
        identity = repository_identity(repository)
        if identity is None or identity[0] != "github.com":
            return None
        match = _GITHUB_OWNER_REPO.search(repository or "")
        if not match:
            return identity
        owner, name = match.group(1), match.group(2)
        if name.endswith(".git"):
            name = name[:-4]
        return ("github.com", owner, name)

    def _finding(
        self,
        rule_id: str,
        ctx: ScanContext,
        *,
        dependency: Dependency | None,
        detail: str,
        degrades_coverage: bool = False,
    ) -> Finding:
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        path = (dependency.declared_in or dependency.project or "") if dependency else ""
        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=path, line=1),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("source", "registry"),),
            ),
            remediation=declared.remediation,
            explanation=Explanation(
                summary=detail,
                matched_rule=rule_id,
                escalations=(NETWORK_CAVEAT,),
            ),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=self.id,
            always_report=declared.category is Category.OPERATIONAL,
            degrades_coverage=degrades_coverage,
        )


__all__ = [
    "INVALID_RULE",
    "SUPPORTED_ECOSYSTEMS",
    "UNCHECKED_RULE",
    "UNVERIFIED_RULE",
    "ProvenanceDetector",
]
