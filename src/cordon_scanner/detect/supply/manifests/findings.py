"""A manifest finding, built the one way every part of the manifest detector builds it.

The rule's severity and message at the line a manifest entry sits on, with the evidence a reader
needs, and the operational finding a manifest that cannot be read reports instead."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.decide.scoring import ScoringContext
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.foundation.capabilities import Capability
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
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    pass


class ManifestFinding:
    """Building a manifest finding from a rule and an entry of a manifest."""

    #: The id every manifest finding carries, wherever in the package it is built.
    DETECTOR: ClassVar[str] = "manifest"

    @classmethod
    def finding(
        cls,
        *,
        rule_id: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: str,
        message: str,
        remediation: str,
        unit: FileUnit,
        ctx: ScanContext,
        detail: str,
        capabilities: list[Capability] | tuple[Capability, ...],
        reasons: list[str],
        fixture_ceiling: bool = True,
    ) -> Finding:
        line = cls._line_of(unit, detail)

        if (
            fixture_ceiling
            and category is not Category.MALICIOUS
            and SourcePaths.is_test_material_here(unit.path, ctx)
        ):
            # The ceiling every other detector applies, arrived at last here because a
            # manifest felt like the one file that is never a fixture. It is: a package
            # manager's own tests need packages to install, so pnpm carries
            # `exec/lifecycle/test/fixtures/*/package.json`, each declaring the install
            # hooks whose runner is under test -- `node -e "console.log('install')"`
            # four times in one manifest. Sixteen HIGH findings, every one of them
            # describing test input for the code that runs install hooks.
            #
            # Still reported, and MALICIOUS is untouched: a fixture tree is where a
            # real payload would most like to sit, and the severity is what changes.
            severity = min(severity, FIXTURE_CEILING)
            message = (
                f"{message} This manifest sits under a path that holds test material, "
                f"where a declared install script is usually input to a test of the "
                f"installer rather than something that ships, so it is reported below "
                f"its usual severity."
            )

        risk = ctx.scorer.score(
            severity,
            confidence,
            ScoringContext(
                # A lifecycle script is install-time by definition; the manifest
                # need not be listed as a hook for that to be true.
                in_install_hook=True,
                capabilities=frozenset(capabilities),
            ),
        )

        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=unit.path, line=line, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.MASKED,
                # Masked because a lifecycle command can embed a token, and a
                # finding must never be the thing that copies one into a log.
                snippet=Redactor.mask(detail[:200]),
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=title,
                matched_rule=rule_id,
                escalations=tuple(reasons),
            ),
            risk=risk,
            detector=cls.DETECTOR,
            capabilities=tuple(dict.fromkeys(capabilities)),
        )

    @staticmethod
    def _line_of(unit: FileUnit, detail: str) -> int | None:
        """Find the line a manifest entry sits on.

        Best effort by design. The parsers work on parsed structures, which
        carry no positions, so the key is located in the raw text afterwards.
        A missing line number is acceptable; a wrong file is not.
        """
        key = detail.split(":", 1)[0].split(" =", 1)[0].strip()
        if not key:
            return None
        needle = f'"{key}"'.encode()
        index = unit.content.raw.find(needle)
        if index == -1:
            index = unit.content.raw.find(key.encode())
        return unit.content.line_of(index) if index != -1 else None

    @classmethod
    def operational(cls, path: str, message: str) -> Finding:
        return Finding(
            rule_id="OPERATIONAL.MANIFEST.UNPARSED",
            category=Category.OPERATIONAL,
            # MEDIUM, not INFO. A manifest is the file that decides what runs at
            # install time, so being unable to read one is a coverage hole
            # rather than a note: every lifecycle check, every declared
            # dependency and every install-hook path for this package is
            # unavailable, and the report should not read like a package that
            # was examined and found to declare nothing.
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(path.encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Fix the syntax error so the manifest can be checked.",
            explanation=Explanation(
                summary="A manifest that cannot be parsed is a manifest that was not checked.",
                matched_rule="OPERATIONAL.MANIFEST.UNPARSED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector=cls.DETECTOR,
        )


__all__ = ["ManifestFinding"]
