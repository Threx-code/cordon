"""What fails a scan's gate, and what an organisation constrains: the severity and categories that
fail, the confidence a finding needs to, whether an incomplete scan fails, advisory sources, drift,
hardening, package and licence lists; and the organisation's limits on suppressions and on what a
repository's own configuration may loosen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)
from cordon_scanner.foundation.taxonomy import ThreatDomain

MAX_SUPPRESSION_DAYS = 365
"""Ceiling on suppression lifetime, lowerable by organisation policy.

Expiry is what converts a suppression from a permanent hole into a scheduled
question. It forces the decision to be re-examined while somebody still
remembers the context that justified it.
"""


@dataclass(frozen=True, slots=True)
class OrgConstraints:
    """What a repository is not permitted to do.

    Each field answers one question: can the repository layer weaken this?
    Defaults are permissive, because an organisation that has not deployed a
    policy should not have Cordon refusing its repositories' configurations.
    Once a policy is supplied, it binds.
    """

    detectors_required: frozenset[str] = frozenset()
    """Detectors a repository may not disable."""

    min_severity_threshold: Severity | None = None
    """The repository may not report *less* than this. A repository setting a
    stricter (lower) threshold is fine and is not a conflict."""

    min_confidence_threshold: Confidence | None = None

    allow_network: bool = True
    allow_plugins: bool = False
    allow_extra_rule_packs: bool = True
    allow_limit_increase: bool = False
    """Whether a repository may raise a resource limit. Denied by default: a
    repository able to raise its own limits can raise them until the protection
    stops applying."""

    max_suppression_days: int = MAX_SUPPRESSION_DAYS
    require_justification: bool = True
    require_approver: bool = False
    forbid_path_only_suppressions: bool = True
    forbid_suppressing: frozenset[Category] = frozenset({Category.MALICIOUS})
    """Categories a repository-level config may never suppress. Malicious by
    default: a repository that can silence a malware finding about itself is not
    being scanned."""

    max_total_timeout: float | None = None

    @classmethod
    def permissive(cls) -> OrgConstraints:
        """The no-policy default. Still forbids suppressing malware."""
        return cls()


DEFAULT_MAX_MAJOR_DRIFT = 2
"""See `Policy.max_major_drift`. Named here because a `slots=True` dataclass
has no readable class attribute to take the default from."""


DEFAULT_ADVISORY_DOMAINS = frozenset(
    {ThreatDomain.INFRASTRUCTURE, ThreatDomain.CONTAINER, ThreatDomain.CICD}
)
"""See `Policy.advisory_domains`. Named here because a `slots=True` dataclass has
no readable class attribute for the parser to fall back to."""


@dataclass(frozen=True, slots=True)
class Policy:
    """Failure policy: what turns findings into a non-zero exit.

    Separate from reporting thresholds on purpose. Teams routinely want to *see*
    medium findings while only *failing* on high ones, and collapsing the two
    forces them to choose between blindness and a blocked pipeline. The pipeline
    wins that argument every time, so the tool ends up reporting nothing.
    """

    fail_on_severity: Severity | None = Severity.HIGH
    fail_on_categories: frozenset[Category] = frozenset({Category.MALICIOUS})
    fail_on_incomplete: bool = False
    min_confidence_to_fail: Confidence = Confidence.MEDIUM
    """A low-confidence heuristic should surface for review, not stop a release.
    Without this floor, the noisiest rule in the pack sets the gate."""

    advisory_domains: frozenset[ThreatDomain] = DEFAULT_ADVISORY_DOMAINS
    """Domains that are REPORTED in full and do not fail the build by default.

    These three describe how a project configured its own infrastructure and
    pipelines: a security group open to the internet, `privileged: true`, a
    workflow that installs a tool with `curl | sh`. Every one of those is worth
    knowing and none of them is evidence that the code is compromised or is
    leaking anything -- they are choices the project already made, about itself,
    deliberately.

    Measured on 1,427 real repositories, they were most of the gate: with them
    failing the build, 76.2% of ordinary open-source projects went red, and
    infrastructure alone was 354 findings and the sole cause in 39 repositories.
    Triage of the largest classes found them overwhelmingly CORRECT --
    `SUSPECT.CI.FETCH_EXEC.001` was right in every sample examined, and
    `SUSPECT.DROPPER.001` in about nine of ten. They are not noise and deleting
    them would be wrong; they are simply not a reason to stop a release.

    A scanner that fails a build on the first day over a Dockerfile that runs
    `curl | sh` gets switched off, and a switched-off scanner catches nothing at
    all. That argument is written into half the rules in this pack; this is the
    same argument applied to the gate rather than to a pattern.

    What still fails, unchanged: malware, leaked credentials, obfuscation,
    exfiltration, and anything in the MALICIOUS category -- including
    `MALWARE.CI.SECRET_EXFIL.001`, which lives in `cicd` and is exempt from this
    carve-out because its category is the stronger claim.

    Set it empty to fail on everything, which is the pre-0.3 behaviour:

        policy:
          advisory_domains: []
    """

    hardening: bool = False
    """Report the hardening tier at its own severity.

    The advisory domains (`advisory_domains`) describe how a project configured its pipelines,
    containers and infrastructure: `curl | sh` in a workflow, a release job restoring a cache, a
    privileged pod. Those findings are correct and are not evidence that anything is attacking
    the project, and on the long-tail corpus they were most of what stopped repositories reading
    as quiet (review 98: Actions repositories 55% quiet with them, the infrastructure-heavy
    repository snapshots under 75%). So by default they form a hardening tier: every one is
    still in the report, recorded at LOW and labelled, and none is a warning. `--hardening`, or

        policy:
          hardening: true

    reports them at their own severity, for a team doing a hardening pass. Anything in the
    MALICIOUS category in those domains (`MALWARE.CI.SECRET_EXFIL.001`) is never in the tier.
    """

    max_major_drift: int = DEFAULT_MAX_MAJOR_DRIFT
    """How many major versions behind the current release a pin may sit before
    `POLICY.DEPENDENCY.DOWNGRADE.001` reports it.

    Two by default, and the default is a noise decision rather than a security
    one: a single major behind is the ordinary state of most dependencies in
    most projects, and a rule that fires on it fires on nearly everything.

    Configurable because "ordinary" is a property of the project rather than of
    the tool. A team that upgrades on a schedule wants 1; a codebase pinned to a
    long-term-support line wants 3 or more:

        policy:
          max_major_drift: 1
    """

    package_deny: tuple[str, ...] = ()
    """Packages that must not be used: `npm:event-stream`, `pypi:*-internal-*`,
    `pkg:npm/lodash@4.17.20`. Each match is `POLICY.PACKAGE.DENIED.001`.

        policy:
          packages:
            deny: ["npm:event-stream", "pypi:pycrypto"]
    """

    package_allow: tuple[str, ...] = ()
    """When set, the only packages that may be used; any other is `POLICY.PACKAGE.NOT_ALLOWED.001`."""

    license_deny: tuple[str, ...] = ()
    """Licences that must not be used: SPDX identifiers (`AGPL-3.0-only`) or categories
    (`network_copyleft`, `copyleft`, `weak_copyleft`, `permissive`, `unknown`)."""

    license_allow: tuple[str, ...] = ()
    """When set, the only licences that may be used. An expression is allowed when one of its
    `OR` branches is wholly allowed (`MIT OR GPL-3.0`); every part of an `AND` must be."""

    license_unknown: str = "allow"
    """What a dependency with no licence data, or one that cannot be classified, is: `allow`
    (not reported), `report` (`POLICY.LICENSE.UNKNOWN.001`, low) or `deny` (the same, high). With an
    allow list set, unknown is never approved: `allow` is read as `report`."""

    accept_no_feed: frozenset[str] | None = None
    """Ecosystems whose lack of any advisory source this project accepts. Their dependencies are
    still reported unchecked (`OPERATIONAL.ADVISORY.NO_FEED.001`, naming them), but no longer
    make the scan incomplete: an ecosystem no source covers can never be checked, and a gate that
    can never pass teaches a team to switch `fail_on_incomplete` off, which hides real gaps.

    Strict by default, and a choice made where reviewers see it. `None` is "not said", which a
    merge with an organisation policy that does say leaves to that policy; two that both say keep
    only what both accept."""

    @classmethod
    def default(cls) -> Policy:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on_severity": str(self.fail_on_severity) if self.fail_on_severity else None,
            "fail_on_categories": sorted(str(c) for c in self.fail_on_categories),
            "fail_on_incomplete": self.fail_on_incomplete,
            "min_confidence_to_fail": str(self.min_confidence_to_fail),
            "advisory_domains": sorted(str(d) for d in self.advisory_domains),
            "hardening": self.hardening,
            "max_major_drift": self.max_major_drift,
            "packages": {"deny": list(self.package_deny), "allow": list(self.package_allow)},
            "accept_no_feed": sorted(self.accept_no_feed)
            if self.accept_no_feed is not None
            else None,
            "licenses": {
                "deny": list(self.license_deny),
                "allow": list(self.license_allow),
                "unknown": self.license_unknown,
            },
        }


__all__ = [
    "DEFAULT_ADVISORY_DOMAINS",
    "DEFAULT_MAX_MAJOR_DRIFT",
    "MAX_SUPPRESSION_DAYS",
    "OrgConstraints",
    "Policy",
]
