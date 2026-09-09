"""Questions about dependencies that only a registry can answer.

Three facts have no local source, and each closes a gap the offline detectors
cannot reach:

**Withdrawal.** A version yanked from PyPI or unpublished from npm was
withdrawn by somebody -- often because it was malicious, often because it was
broken. A lockfile pins it happily either way, and nothing in the repository
records that the pin now points at something its own publisher retracted.

**Distance from what is published.** A pin far behind the current release is
ordinary in a conservative project and is also what a downgrade attack produces.
This reports the distance and says nothing about the cause, because the
difference between the two is a decision the reader makes with context this tool
does not have.

**Integrity.** A lockfile records a hash. The registry records a hash. If they
disagree, one of them is not describing the artefact that will be installed, and
that is worth interrupting a build over.

Every finding from here is marked as depending on a network answer, because it
does: rerun the same scan offline and it disappears, rerun it next week and it
may differ. That is a property of the question, not a defect, and a report that
did not say so would be claiming a reproducibility it does not have.

The detector requires `network`, so the engine skips it entirely unless the scan
was explicitly taken online. Failures are reported rather than swallowed -- an
unreachable registry means the questions went unanswered, which is not the same
as answering "no".

**Not done, and why.** Package-versus-repository mismatch -- the registry says a
package is built from one repository and the package claims another -- belongs
here and is not implemented. It needs the *local* claim to compare against, and
`Dependency` carries no repository field: adding one means every ecosystem
parser learning to extract it, which is a change to the dependency model rather
than to this detector. Declaring the rule and never emitting it would be worse
than its absence, because a rule that cannot fire is indistinguishable from one
that found nothing.
"""

from __future__ import annotations

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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import Unit

MAX_QUERIES = 200
"""How many packages one scan will ask about.

A large graph would otherwise mean thousands of requests, which is slow enough
that people stop passing the flag, and impolite enough to the registry that it
deserves a ceiling. Direct dependencies are asked about first, because those are
the ones somebody chose."""

NETWORK_CAVEAT = (
    "This finding came from a live registry query. It is not reproducible from "
    "the repository alone, and rerunning the scan offline will not produce it."
)


class RegistryDetector(BaseDetector):
    """Enriches the dependency graph with what the registry says."""

    id = "registry"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=False, dependencies=True, network=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies) and not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.YANKED.001",
                title="Dependency pins a version its publisher withdrew",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                remediation=(
                    "Move off the withdrawn version. A release is yanked because "
                    "its publisher decided nobody should be installing it."
                ),
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.DOWNGRADE.001",
                title="Dependency pins a version far behind the current release",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=RegistryDetector.id,
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
                detector=RegistryDetector.id,
                remediation=(
                    "Do not install. One of the two records is not describing the "
                    "artefact that will arrive, and until that is resolved neither "
                    "can be trusted."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.REGISTRY.UNREACHABLE.001",
                title="Registry could not be asked about a dependency",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=RegistryDetector.id,
                remediation=(
                    "Rerun when the registry is reachable, or accept that these checks did not run."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit) or ctx.offline:
            return ()

        from cordon_scanner.intel.registry_client import RegistryError, facts

        findings: list[Finding] = []
        unanswered: list[str] = []

        for dependency in self._to_ask(unit.dependencies):
            try:
                observed = facts(dependency.ecosystem, dependency.name, dependency.version)
            except RegistryError as exc:
                unanswered.append(f"{dependency.name}: {exc}")
                continue
            findings.extend(self._compare(dependency, observed, ctx))

        if unanswered:
            # One aggregated report rather than one per package: an offline
            # runner would otherwise produce a finding for every dependency in
            # the graph, and a report nobody reads is the same as no report.
            # It is still reported, because "we could not ask" and "the answer
            # was no" are different facts.
            findings.append(
                self._finding(
                    "OPERATIONAL.REGISTRY.UNREACHABLE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{len(unanswered)} package(s) could not be checked against "
                        f"their registry, so withdrawal, distance and hash "
                        f"verification did not run for them. First: {unanswered[0]}"
                    ),
                )
            )
        return findings

    @staticmethod
    def _to_ask(dependencies: tuple[Dependency, ...]) -> list[Dependency]:
        """Which packages to spend a request on, direct ones first."""
        ordered = sorted(dependencies, key=lambda d: (not d.direct, d.depth, d.purl))
        return [d for d in ordered if d.version][:MAX_QUERIES]

    def _compare(
        self, dependency: Dependency, observed: object, ctx: ScanContext
    ) -> Iterable[Finding]:
        from cordon_scanner.intel.registry_client import PackageFacts

        if not isinstance(observed, PackageFacts):  # pragma: no cover - defensive
            return

        if observed.yanked:
            reason = f" ({observed.yanked_reason})" if observed.yanked_reason else ""
            yield self._finding(
                "SUSPECT.DEPENDENCY.YANKED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{dependency.version} was withdrawn by its "
                    f"publisher{reason}, and this lockfile still pins it"
                ),
            )

        if self._digest_conflict(dependency, observed.digests):
            yield self._finding(
                "SUSPECT.PROVENANCE.MISMATCH.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"the hash recorded for {dependency.name}@{dependency.version} "
                    f"is not among the hashes the registry publishes for that version"
                ),
            )

        if observed.latest and dependency.version and observed.latest != dependency.version:
            behind = self._major_distance(dependency.version, observed.latest)
            if behind >= 2:
                yield self._finding(
                    "POLICY.DEPENDENCY.DOWNGRADE.001",
                    ctx,
                    dependency=dependency,
                    detail=(
                        f"{dependency.name} is pinned to {dependency.version} while "
                        f"{observed.latest} is current, {behind} major versions ahead"
                    ),
                )

    @staticmethod
    def _digest_conflict(dependency: Dependency, published: tuple[str, ...]) -> bool:
        """Whether the recorded hash contradicts every published one.

        Absence is not a conflict. A lockfile with no hash is already reported
        by the offline integrity rule, and a registry that publishes none
        cannot contradict anything -- treating either as a mismatch would make
        this rule fire on the ordinary case and mean nothing on the real one.
        """
        recorded = (dependency.integrity or "").strip()
        if not recorded or not published:
            return False

        # Lockfiles write hashes in several shapes: `sha256-<base64>`,
        # `sha256:<hex>`, or a bare digest. Comparison is on the digest itself,
        # since the framing differs by tool and says nothing about the artefact.
        def bare(value: str) -> str:
            for separator in ("-", ":", "="):
                head, found, tail = value.partition(separator)
                if found and head.lower().startswith(("sha", "md5")):
                    return tail.strip().lower()
            return value.strip().lower()

        return bare(recorded) not in {bare(entry) for entry in published}

    @staticmethod
    def _major_distance(pinned: str, latest: str) -> int:
        """How many major versions separate two version strings.

        Deliberately crude. Version schemes differ enough that a precise
        comparison needs each ecosystem's own rules, and the question here is
        only "is this pin far behind", which the leading number answers well
        enough to prompt a look. Anything unparseable returns zero rather than
        guessing.
        """

        def leading(value: str) -> int | None:
            head = value.lstrip("v=^~ ").split(".", 1)[0]
            digits = "".join(c for c in head if c.isdigit())
            return int(digits) if digits else None

        first, second = leading(pinned), leading(latest)
        if first is None or second is None:
            return 0
        return max(0, second - first)

    def _finding(
        self,
        rule_id: str,
        ctx: ScanContext,
        *,
        dependency: Dependency | None,
        detail: str,
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
        )


__all__ = ["MAX_QUERIES", "RegistryDetector"]
