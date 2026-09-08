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
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.errors import ConfigError, ExitCode
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

    @classmethod
    def filter_for_reporting(cls, result: ScanResult, config: Config) -> ScanResult:
        """Apply reporting thresholds.

        Separate from the failure policy, and unable to weaken it. Anything that
        trips the gate is kept regardless of threshold, because the alternative
        was demonstrably worse than it sounds: this filter runs inside the scan,
        so the gate only ever saw what survived it, and

            scan:
              confidence_threshold: confirmed

        in a repository's own configuration hid a CRITICAL malware finding about
        that repository and returned exit 0. One line, in a file the scan target
        supplies, and the build went green over a fetch-and-execute preinstall
        hook.

        The docstring here previously asserted the opposite -- that the gate had
        already run and so could not be weakened. It had not. Keeping the
        gate-tripping findings in the filter itself is what makes the claim true
        rather than intended, and it holds no matter where the filter is called
        from.

        Findings about the scan itself bypass the severity threshold entirely
        -- every OPERATIONAL finding, and anything flagged `always_report`.
        They describe a degraded scan, and hiding one behind a threshold is how
        a scan that examined almost nothing comes to look like a clean one.

        That exemption is load-bearing rather than tidy. Without it, a
        repository blinds its own scan with `exclude: ["**/*"]` and then hides
        the finding that says so with `severity_threshold: critical` -- two
        lines, in a file the scan target itself supplies, and the result is
        again indistinguishable from clean.
        """
        policy = config.policy
        kept = tuple(
            f
            for f in result.findings
            if f.category is Category.OPERATIONAL
            or f.always_report
            or cls._fails(f, policy)
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

    * Findings about the scan itself cannot be suppressed at all. Suppressing
      one does not accept a known risk; it asserts that a scan which examined
      nothing should be read as a pass.
    """

    def __init__(self, config: Config, today: date | None = None) -> None:
        self._today = today or date.today()
        self._active = config.active_suppressions(self._today)
        self._expired = config.expired_suppressions(self._today)
        self._forbidden = config.constraints.forbid_suppressing

    def apply(self, findings: Iterable[Finding]) -> tuple[Finding, ...]:
        return tuple(self._apply_one(f) for f in findings)

    def _apply_one(self, finding: Finding) -> Finding:
        # A finding that reports the scan itself was degraded is never
        # suppressible, by anyone. Suppressing "this scan examined no files"
        # does not hide a finding about the code -- it asserts that a result
        # nobody produced should be treated as a pass. A suppression is a
        # decision to accept a known risk; there is no risk described here to
        # accept, only an absent scan.
        #
        # Unconditional, and not left to organisation policy, because the
        # scan target supplies its own configuration and this is the one
        # finding that says whether any of the others could have been found.
        if finding.always_report:
            return finding

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

        Supports an exact path, a directory prefix (trailing slash), and glob
        wildcards with **path** semantics -- `*` does not cross `/`.

        It used `fnmatchcase`, whose `*` does cross `/`, so `path: "*.js"`
        suppressed the rule in every `.js` file at any depth. That is the
        repository-wide hole the rule-and-path pair exists to prevent, spelled
        with four characters instead of one, and the guard against it only
        rejected the literal strings `*`, `**` and `**/*`.

        Deliberately not regular expressions: a suppression is written once and
        read many times, usually by somebody deciding whether a security
        exception is still justified, and a regex is a poor medium for that
        conversation. It is also one more place for a catastrophic backtracking
        pattern to reach the engine.
        """
        if pattern == path:
            return True
        if pattern.endswith("/"):
            return path.startswith(pattern)
        if "*" in pattern or "?" in pattern or "[" in pattern:
            from cordon.core.walker import PathGlob

            # `compile().match`, not `matches()`. The latter additionally treats
            # a pattern with no `/` as matching that name at any depth, which is
            # right for an ignore pattern -- `node_modules` should mean every
            # one of them -- and wrong here: it made `*.js` suppress the rule in
            # every directory, which is what this fix is for.
            return PathGlob.compile(pattern).match(path) is not None
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

    def __init__(self, fingerprints: Iterable[str], entries: Iterable[dict[str, str]] = ()) -> None:
        self._known = frozenset(fingerprints)
        self._entries = tuple(entries)

    @property
    def entries(self) -> tuple[dict[str, str], ...]:
        """The recorded entries, in the readable form written to disk."""
        return self._entries

    @classmethod
    def from_result(cls, result: ScanResult) -> Baseline:
        return cls(
            (f.fingerprint for f in result.findings),
            entries=[
                {
                    "fingerprint": f.fingerprint,
                    "rule": f.rule_id,
                    "path": f.location.path,
                }
                for f in sorted(result.findings, key=lambda f: (f.rule_id, f.fingerprint))
            ],
        )

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
        """The on-disk form.

        Entries carry the rule and the path alongside the fingerprint. A
        fingerprint is a pure function of values the committer controls, so an
        attacker can compute the one their payload will produce and add it in
        the same commit -- and against a bare list of hashes a reviewer has no
        way to see what a new line means. `SUSPECT.DECODE_EXEC.001 at
        src/loader.js` is reviewable; `24188f3138b15088` is not.

        `fingerprints` is still written, so a file produced here loads in an
        older build and the format change is not a migration.
        """
        return {
            "version": 2,
            "fingerprints": sorted(self._known),
            "entries": list(self._entries),
        }

    @classmethod
    def from_file(cls, path: str | Path) -> Baseline:
        """Read a baseline written by :meth:`write`.

        A missing file is an error rather than an empty baseline. Treating it as
        empty would mean a mistyped `--baseline` path silently re-raises the
        entire backlog, which reads as the tool having broken and is the fastest
        route to it being switched off.

        A malformed one is also an error, and for the opposite reason: an
        unreadable baseline that degraded to "suppress nothing" would be noisy,
        but one that degraded to "suppress everything" would be silent, and the
        parser should not be the thing deciding which.
        """
        import json

        file = Path(path)
        if not file.is_file():
            raise ConfigError(
                f"baseline not found: {file}",
                hint="Create one with `cordon baseline create`.",
            )
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"{file}: baseline is not readable JSON: {exc}") from exc

        if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
            raise ConfigError(
                f"{file}: baseline must be an object with a `fingerprints` list",
                hint="Regenerate it with `cordon baseline create`.",
            )
        raw_entries = data.get("entries")
        entries = (
            [e for e in raw_entries if isinstance(e, dict)] if isinstance(raw_entries, list) else []
        )
        return cls((str(f) for f in data["fingerprints"]), entries=entries)

    def write(self, path: str | Path) -> Path:
        """Write the baseline, sorted, so a diff of it is reviewable."""
        import json

        file = Path(path)
        file.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return file

    def compare(self, result: ScanResult) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
        """What this result adds to, and what it has cleared from, the baseline.

        Both directions matter. New findings are why anybody runs the comparison;
        cleared ones are what lets a baseline shrink, and a baseline that only
        grows stops meaning anything within a year.
        """
        seen = {f.fingerprint for f in result.findings}
        added = tuple(f for f in result.findings if f.fingerprint not in self._known)
        cleared = tuple(sorted(f for f in self._known if f not in seen))
        return added, cleared


__all__ = [
    "Baseline",
    "PolicyGate",
    "SuppressionMatcher",
    "Verdict",
]
