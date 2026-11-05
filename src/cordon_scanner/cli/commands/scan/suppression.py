"""`scan --baseline` and `scan --vex`: findings a baseline or a VEX statement rules out, kept in the
report and announced, never silently dropped."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.foundation.results import ScanResult


class ScanSuppression:
    @classmethod
    def apply_baseline(cls, args: argparse.Namespace, result: ScanResult) -> ScanResult:
        """`--baseline`: the findings it records marked suppressed, and one finding saying so."""
        if args.baseline:
            from dataclasses import replace as _replace

            from cordon_scanner.decide.policy import Baseline

            baseline = Baseline.from_file(args.baseline)
            applied = baseline.apply(result.findings)
            silenced = [
                f
                for f in applied
                if f.suppressed is not None and f.suppressed.approved_by == "baseline"
            ]
            findings = list(applied)
            if silenced:
                # Announced in every scan, not merely absent. A fingerprint is a
                # pure function of values the committer controls, so an attacker
                # can compute the one their payload will produce and add it to
                # the baseline in the same commit. That cannot be prevented
                # without signing, and it can be made loud: the suppression is
                # named in the output of every run that honours it, and the
                # finding is one no reporting threshold can hide.
                findings.append(cls.baseline_notice(silenced, Path(args.baseline)))
            result = _replace(result, findings=tuple(findings))
        return result

    @staticmethod
    def apply_vex(args: argparse.Namespace, result: ScanResult) -> ScanResult:
        """`--vex`: the vulnerability findings its statements rule out marked suppressed."""
        if getattr(args, "vex", None):
            from dataclasses import replace as _replace_vex

            from cordon_scanner.decide.vex import VexDocuments, VexError

            try:
                statements = VexDocuments.load(args.vex)
            except VexError as exc:
                raise ConfigError(f"--vex: {exc}") from exc
            ruled = VexDocuments.apply(result.findings, statements)
            count = sum(
                1 for f in ruled if f.suppressed is not None and f.suppressed.approved_by == "vex"
            )
            if count:
                print(
                    f"{PROGRAM}: {count} vulnerability finding(s) marked suppressed by VEX "
                    f"statements; they remain in the report with the statement that ruled them out",
                    file=sys.stderr,
                )
            result = _replace_vex(result, findings=ruled)
        return result

    @staticmethod
    def baseline_notice(silenced: Sequence[Finding], path: Path) -> Finding:
        """One always-reported finding naming what the baseline is hiding."""
        from cordon_scanner.foundation.models import (
            Category,
            Confidence,
            Evidence,
            EvidenceKind,
            Explanation,
            Finding,
            Location,
            RedactionMode,
            RiskScore,
            Severity,
        )

        rules = sorted({f.rule_id for f in silenced})
        listed = ", ".join(rules[:8]) + (" and others" if len(rules) > 8 else "")
        return Finding(
            rule_id="POLICY.BASELINE.APPLIED",
            category=Category.POLICY,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=(
                f"{len(silenced)} finding(s) were suppressed by {path.name}: {listed}. "
                f"A baseline records debt somebody chose to carry, and its entries are "
                f"computable by whoever can commit to this repository, so what it "
                f"hides is stated here on every run."
            ),
            location=Location(path=path.name),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(",".join(rules).encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=(
                "Review the baseline. Every entry names the rule and the path it "
                "silences, so a new one is legible in a diff."
            ),
            explanation=Explanation(
                summary="Reported so that a baseline never hides its own contents.",
                matched_rule="POLICY.BASELINE.APPLIED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector="engine",
            always_report=True,
        )


__all__ = ["ScanSuppression"]
