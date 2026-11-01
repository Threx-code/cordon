"""The code model's per-file scores (release item 47), computed in the supervised workers, since
reading a file's tokens is parsing hostile input (outer-layer review of note 47's integration).

For each reached JavaScript file (an install hook's, an import entry's or the library closure's) the
detector scores the file's buckets with the shipped weights and returns one internal record, never a
finding a reader sees: `INTERNAL.CODE_MODEL.FILE_SCORE`, info, operational, its score and the platform
n-grams that raised it in the evidence's metadata, versioned (`FileScoreRecord`). The package step in
the parent takes the maximum, decides, and removes every record; the result assembly strips any left.
The weights are this detector's own, loaded when the engine builds it: no module or class cache.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.code_model import (
    CodeFeatures,
    CodeModelUnavailable,
    CodeModelWeights,
    FileScoreRecord,
)
from cordon_scanner.detect.base import NO_RISK, BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import (
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

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from cordon_scanner.detect.base import ScanContext, Unit

MODEL_RULE = "SUSPECT.CODE.MODEL.001"
UNAVAILABLE = "OPERATIONAL.CODE_MODEL.UNAVAILABLE"
CAPPED = "OPERATIONAL.CODE_MODEL.CAPPED"


class CodeModelScores(BaseDetector):
    id = "code-model"
    version = "0.1.0"
    categories = frozenset({Category.OPERATIONAL, Category.SUSPICIOUS})
    requires = DetectorRequirements()
    LANGUAGES: ClassVar[frozenset[str]] = frozenset({"javascript", "typescript"})
    MAX_FILE: ClassVar[int] = 2_000_000

    def __init__(self, weights_path: Path | None = None) -> None:
        self.unavailable: str | None = None
        try:
            self.weights = (
                CodeModelWeights.load()
                if weights_path is None
                else CodeModelWeights.load(weights_path)
            )
        except CodeModelUnavailable as error:
            self.weights, self.unavailable = None, str(error)

    def applicable(self, ctx: ScanContext) -> bool:
        return self.weights is not None

    @staticmethod
    def reached(path: str, ctx: ScanContext) -> bool:
        """The scanner's own reach, as every detector reads it (the ONE RULE)."""
        return (
            path in ctx.install_hook_paths
            or path in ctx.import_entry_paths
            or path in ctx.library_closure_paths
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        weights = self.weights
        if (
            weights is None
            or not isinstance(unit, FileUnit)
            or unit.language not in self.LANGUAGES
            or "#" in unit.path.rpartition("!")[2]  # the scan's own derived units
            or not self.reached(unit.path, ctx)
        ):
            return ()
        content = unit.content
        if content.size > self.MAX_FILE:
            return (
                self.operational(
                    path=unit.path,
                    rule_id=CAPPED,
                    message="A reached file is past the code model's size cap and was not scored.",
                    detail=f"{content.size} bytes",
                ),
            )
        text = content.text
        buckets = CodeFeatures.buckets(text)
        score = weights.score(buckets)
        carriers = weights.carriers(buckets, CodeFeatures.ngrams(text))
        return (self.record(unit.path, score, carriers),)

    def record(self, path: str, score: float, carriers: list[str]) -> Finding:
        """The internal record of one file's score: info, operational, never reported alone."""
        message = FileScoreRecord.encode(score, carriers)
        return Finding(
            rule_id=FileScoreRecord.RULE,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{FileScoreRecord.RULE}:{path}:{message}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("record", message),),
            ),
            remediation="",
            explanation=Explanation(
                summary="The code model's score for one file.", matched_rule=FileScoreRecord.RULE
            ),
            risk=NO_RISK,
            detector=self.id,
            always_report=False,
        )

    def model_finding(
        self, path: str, score: float, carriers: list[str], blocking: bool
    ) -> Finding:
        """SUSPECT.CODE.MODEL.001 at the package's highest-scoring reached file: HIGH where the score
        reaches `block_at`, else MEDIUM (reported, below the gate)."""
        rule = next(r for r in self.declared_rules() if r.id == MODEL_RULE)
        named = f" The platform calls that weighed most: {', '.join(carriers)}." if carriers else ""
        return Finding(
            rule_id=MODEL_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH if blocking else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            message=f"{rule.message} Score {score:.2f} for this file.{named}",
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{MODEL_RULE}:{path}:{score:.4f}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("score", f"{score:.4f}"), ("carriers", "|".join(carriers))),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=MODEL_RULE),
            risk=NO_RISK,
            detector=self.id,
            references=rule.references,
        )

    def unavailable_note(self, path: str) -> Finding | None:
        """OPERATIONAL.CODE_MODEL.UNAVAILABLE, once a scan, when the weights are damaged or mismatched;
        nothing when the build ships none."""
        if self.unavailable is None:
            return None
        return self.operational(path=path, rule_id=UNAVAILABLE, message=self.unavailable)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=MODEL_RULE,
                title="The code itself reads as malicious to Cordon's code model",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=CodeModelScores.id,
                message=(
                    "Cordon's code model, trained on real malicious and legitimate packages, reads the "
                    "code this package runs on install or import and scores it as malicious. It reads "
                    "what the code looks like (its structure and the platform calls it makes, in "
                    "order), not what any rule found, so it is evidence of its own. A model's score is "
                    "evidence, not proof: read the named file before trusting it."
                ),
                remediation=(
                    "Do not install or run it until the named file has been reviewed. If it is a "
                    "dependency, pin the last release you have reviewed, or remove it."
                ),
                references=(ref.EMBEDDED_MALICIOUS_CODE, ref.ATTACK_MALICIOUS_FILE),
            ),
            DeclaredRule(
                id=UNAVAILABLE,
                title="The code model's weights could not be used",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=CodeModelScores.id,
                message="The shipped code model is damaged or was made for other features, so no package was scored by it.",
                remediation="Reinstall Cordon, or report the build: the weights ship with it.",
                references=(),
            ),
            DeclaredRule(
                id=CAPPED,
                title="A reached file was past the code model's size cap",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=CodeModelScores.id,
                message="A file this package runs was too large for the code model and was not scored; every other check read it.",
                remediation="No action required; the cap bounds the model's cost per file.",
                references=(),
            ),
        )
