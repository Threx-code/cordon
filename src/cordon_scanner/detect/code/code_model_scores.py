"""The code model's per-file scores (release item 47), computed in the supervised workers, since
reading a file's tokens is parsing hostile input (outer-layer review of note 47's integration).

For each reached JavaScript file (an install hook's, an import entry's or the library closure's) the
detector scores the file's buckets with the shipped weights and returns one internal record, never a
finding a reader sees: `INTERNAL.CODE_MODEL.FILE_SCORE`, info, operational, its score and the platform
n-grams that raised it in the evidence's metadata, versioned (`FileScoreRecord`). The package step in
the parent takes the maximum, decides, and removes every record; the result assembly strips any left.
The weights are this detector's own (no module or class cache), read when the first reached
JavaScript file needs them (release item 17: 0.1 s of every scan went on weights a Python package
never uses). A worker reads them for itself; a long-running scanner whose scan needed them reads them
once in the parent before its next scan's template, so every later worker has them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.code_model import (
    WEIGHTS_PATH,
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


class CodeModelScores(BaseDetector):
    id = "code-model"
    version = "0.1.0"
    categories = frozenset({Category.OPERATIONAL, Category.SUSPICIOUS})
    requires = DetectorRequirements()
    LANGUAGES: ClassVar[frozenset[str]] = frozenset({"javascript", "typescript"})

    def __init__(self, weights_path: Path | None = None) -> None:
        self.weights_path = WEIGHTS_PATH if weights_path is None else weights_path
        self.unavailable: str | None = None
        #: A scan reached JavaScript: the next scan's parent reads the weights before its template.
        self.wanted = False
        self._weights: CodeModelWeights | None = None
        self._loaded = False

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def weights(self) -> CodeModelWeights | None:
        """The weights, read on first use; None when the build ships none or they are damaged
        (`unavailable` says why)."""
        if not self._loaded:
            self._loaded = True
            try:
                self._weights = CodeModelWeights.load(self.weights_path)
            except CodeModelUnavailable as error:
                self.unavailable = str(error)
        return self._weights

    def applicable(self, ctx: ScanContext) -> bool:
        # A stat, not a read: whether the weights are sound is learnt where a file needs them.
        return self._weights is not None if self._loaded else self.weights_path.exists()

    @staticmethod
    def reached(path: str, ctx: ScanContext) -> bool:
        """The scanner's own reach, as every detector reads it (the ONE RULE)."""
        return (
            path in ctx.install_hook_paths
            or path in ctx.import_entry_paths
            or path in ctx.library_closure_paths
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if (
            not isinstance(unit, FileUnit)
            or unit.language not in self.LANGUAGES
            or "#" in unit.path.rpartition("!")[2]  # the scan's own derived units
            or not self.reached(unit.path, ctx)
        ):
            return ()
        weights = self.weights
        if weights is None:
            # The parent keeps one of these a scan (`CodeModelPass`).
            note = self.unavailable_note(unit.path)
            return () if note is None else (note,)
        # Every window of the file, however large: no size escapes the model (the owner's no-caps
        # rule). The file's score is its highest window's; a file within one window scores as trained.
        score: float = 0.0
        carriers: list[str] = []
        for buckets, names in CodeFeatures.windows(unit.content.text):
            window_score = weights.score(buckets)
            if window_score > score or not carriers:
                score, carriers = window_score, weights.carriers(buckets, names)
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
        """OPERATIONAL.CODE_MODEL.UNAVAILABLE when the weights are damaged or mismatched and a reached
        file needed them; nothing when the build ships none."""
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
        )
