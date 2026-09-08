"""Policy evaluation: turning findings into a verdict.

This module decides the exit code, and it is deliberately separate from both
detection and reporting. Detection answers "what is here". Policy answers "does
this stop the build". Fusing them is how tools end up with a severity threshold
that silently doubles as a reporting filter, so a team that wants to *see*
medium findings is forced to *fail* on them, and predictably chooses blindness.

The evaluation is a specification-pattern predicate over an immutable result,
which means the gate can be unit-tested exhaustively without running a scan.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from cordon.core.errors import ExitCode
from cordon.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    ScanResult,
    Severity,
    Suppression,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cordon.core.config import Config, Policy


@dataclass(frozen=True, slots=True)
class Verdict:
    """The outcome of a scan, as a policy sees it."""

    exit_code: ExitCode
    reason: str
    triggering: tuple[Finding, ...] = ()

    @property
    def passed(self) -> bool:
        return self.exit_code is ExitCode.CLEAN


class PolicyGate:
    """Decides whether a scan result should fail the build.

    Separate from the scan itself, and from reporting. The gate is the only
    thing a CI pipeline acts on, so it is kept small enough to read in one
    sitting and has no dependency on how findings are rendered.

    Stateless: the policy is passed in rather than held, because one process may
    evaluate the same result against an organisation policy and a repository one
    to explain which of them failed the build.
    """

    @classmethod
    def evaluate(cls, result: ScanResult, policy: Policy) -> Verdict:
        """Decide whether a scan result should fail the build.

        Order matters. Completeness is checked before findings, because a scan
        that did not finish cannot support a claim that nothing was found --
        reporting "clean" from a partial scan is a false negative that looks
        exactly like a pass.
        """
        if not result.complete and policy.fail_on_incomplete:
            return Verdict(
                ExitCode.INCOMPLETE,
                "the scan did not complete and policy requires a complete scan",
            )

        triggering = tuple(f for f in result.active if cls._fails(f, policy))
        if triggering:
            worst = max(f.severity for f in triggering)
            return Verdict(
                ExitCode.FINDINGS,
                f"{len(triggering)} finding(s) met the failure policy (highest: {worst})",
                triggering,
            )

        if not result.complete:
            # Reported, but not fatal without the flag. The distinction is
            # deliberate: making an incomplete scan fail by default would break
            # pipelines on the first large repository and teach people to append
            # `|| true`, which is worse than the failure it was preventing.
            return Verdict(
                ExitCode.CLEAN, "no findings met the failure policy (scan was incomplete)"
            )

        return Verdict(ExitCode.CLEAN, "no findings met the failure policy")

    @staticmethod
    def _fails(finding: Finding, policy: Policy) -> bool:
        """Whether one finding trips the gate.

        A category match bypasses the confidence floor. If a rule asserts
        evidence of intent to harm, "we were only moderately sure" is not a
        reason to let the build through -- it is a reason to look.
        """
        if finding.category in policy.fail_on_categories:
            return True
        if finding.confidence < policy.min_confidence_to_fail:
            return False
        return policy.fail_on_severity is not None and finding.severity >= policy.fail_on_severity

    @staticmethod
    def filter_for_reporting(result: ScanResult, config: Config) -> ScanResult:
        """Apply reporting thresholds.

        Separate from the failure policy on purpose, and applied after it. A
        finding below the reporting threshold is hidden from the report but has
        already been considered by the gate, so raising a reporting threshold
        can never accidentally weaken a gate.

        OPERATIONAL findings bypass the severity threshold entirely. They
        describe a degraded scan, and hiding them behind a threshold is how a
        scan that examined almost nothing comes to look like a clean one.
        """
        kept = tuple(
            f
            for f in result.findings
            if f.category is Category.OPERATIONAL
            or (
                f.severity >= config.severity_threshold
                and f.confidence >= config.confidence_threshold
            )
        )
        return replace(result, findings=kept)


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


class SuppressionMatcher:
    """Applies configured suppressions to findings.

    Two properties are load-bearing:

    * A suppressed finding is **marked, not removed**. It stays in the JSON and
      SARIF output with its justification attached. An auditor's first question
      is what the tool was told to ignore, and that must be answerable from a
      report rather than by reading every repository's configuration by hand.

    * Expiry is enforced here and reported separately. An expired suppression
      stops suppressing *and* produces a POLICY finding naming it, so the
      finding it was hiding reappears at the same moment somebody is told why.
    """

    def __init__(self, config: Config, today: date | None = None) -> None:
        self._today = today or date.today()
        self._active = config.active_suppressions(self._today)
        self._expired = config.expired_suppressions(self._today)
        self._forbidden = config.constraints.forbid_suppressing

    def apply(self, findings: Iterable[Finding]) -> tuple[Finding, ...]:
        return tuple(self._apply_one(f) for f in findings)

    def _apply_one(self, finding: Finding) -> Finding:
        # A category the organisation forbids suppressing cannot be silenced by
        # a repository-level config, whatever it says. A repository able to
        # suppress a malware finding about itself is not being scanned.
        if finding.category in self._forbidden:
            return finding

        for suppression in self._active:
            if self._matches(finding, suppression):
                return finding.with_suppression(suppression)
        return finding

    def expiry_findings(self) -> tuple[Finding, ...]:
        """One POLICY finding per expired suppression.

        Emitted so expiry is loud. A suppression that quietly lapses produces a
        sudden unexplained finding in an unrelated pull request, which reads as
        a false positive and gets suppressed again -- this time probably without
        anybody re-examining the original reasoning.
        """
        return tuple(
            Finding(
                rule_id="POLICY.SUPPRESSION.EXPIRED",
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                message=(
                    f"The suppression for {s.rule} at {s.path} expired on {s.expires} "
                    f"and is no longer in effect."
                ),
                location=Location(path=s.path),
                evidence=Evidence(
                    kind=EvidenceKind.METADATA,
                    match_hash=Evidence.hash_bytes(f"{s.rule}:{s.path}:{s.expires}".encode()),
                    redaction=RedactionMode.NONE,
                    metadata=(
                        ("rule", s.rule),
                        ("expires", s.expires),
                        ("approved_by", s.approved_by or ""),
                    ),
                ),
                remediation=(
                    "Re-examine the original reasoning. If it still holds, renew the "
                    "suppression with a new expiry and a current approver. If it does "
                    "not, remove the suppression and fix the finding."
                ),
                explanation=Explanation(
                    summary=(
                        "Suppressions expire so the decision is re-examined while somebody "
                        "still remembers the context that justified it."
                    ),
                    matched_rule="POLICY.SUPPRESSION.EXPIRED",
                ),
                risk=RiskScore(value=20, base=45, confidence_multiplier=1.0),
                detector="policy",
            )
            for s in self._expired
        )

    @classmethod
    def _matches(cls, finding: Finding, suppression: Suppression) -> bool:
        """Whether a suppression covers a finding.

        Both the rule and the path must match. This is the whole point of the
        pair form: a suppression for a spawn rule in one release script must not
        also exempt that script from every other rule, nor exempt every file
        from the spawn rule.
        """
        if finding.rule_id != suppression.rule:
            return False
        return cls._path_matches(finding.location.path, suppression.path)

    @staticmethod
    def _path_matches(path: str, pattern: str) -> bool:
        """Path matching for suppressions.

        Supports an exact path, a directory prefix (trailing slash), and simple
        glob wildcards. Deliberately does not support arbitrary regular
        expressions: a suppression pattern is written once and read many times,
        usually by somebody deciding whether a security exception is still
        justified, and a regex is a poor medium for that conversation. It is
        also one more place for a catastrophic backtracking pattern to reach the
        engine.
        """
        if pattern == path:
            return True
        if pattern.endswith("/"):
            return path.startswith(pattern)
        if "*" in pattern or "?" in pattern:
            return fnmatchcase(path, pattern)
        return False


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class Baseline:
    """A recorded set of findings to treat as already-known.

    Baselines exist so a tool can be adopted into an existing codebase without
    demanding that the entire backlog be fixed on day one. The alternative --
    turn it on, get four hundred findings, turn it off -- is the most common way
    a security tool fails to be adopted at all.

    Keyed on fingerprint rather than path and line, so reformatting a file does
    not silently empty the baseline and re-raise everything it contained.
    """

    def __init__(self, fingerprints: Iterable[str]) -> None:
        self._known = frozenset(fingerprints)

    @classmethod
    def from_result(cls, result: ScanResult) -> Baseline:
        return cls(f.fingerprint for f in result.findings)

    @classmethod
    def from_fingerprints(cls, fingerprints: Sequence[str]) -> Baseline:
        return cls(fingerprints)

    def __contains__(self, finding: Finding) -> bool:
        return finding.fingerprint in self._known

    def __len__(self) -> int:
        return len(self._known)

    def apply(self, findings: Iterable[Finding]) -> tuple[Finding, ...]:
        """Suppress findings present in the baseline.

        Baselined findings are marked with a suppression carrying an explicit
        justification, so they are visibly baselined rather than invisibly
        absent. A baseline that hides its own contents is indistinguishable from
        a scanner that stopped working.

        Malicious findings are never baselined. A baseline records "we have not
        fixed this yet", which is not a coherent position to hold about evidence
        of intent to harm.
        """
        out: list[Finding] = []
        for finding in findings:
            if finding.category is not Category.MALICIOUS and finding in self:
                out.append(
                    finding.with_suppression(
                        Suppression(
                            rule=finding.rule_id,
                            path=finding.location.path,
                            justification=(
                                "Present in the baseline: this finding predates the adoption "
                                "of the current policy and is tracked as existing debt."
                            ),
                            expires="9999-12-31",
                            approved_by="baseline",
                        )
                    )
                )
            else:
                out.append(finding)
        return tuple(out)

    def to_dict(self) -> dict[str, object]:
        return {"version": 1, "fingerprints": sorted(self._known)}


__all__ = [
    "Baseline",
    "PolicyGate",
    "SuppressionMatcher",
    "Verdict",
]
