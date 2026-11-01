"""The code model's package step (release item 47): the parent's half, numbers only. The workers'
detector (`detect/code/code_model_scores.py`) returns one internal record per reached file; here the
records are read before the folds, the package decided on the max over its files, and the model's
finding handed back to be added after the verdict, which never reads it (no echo, item 46).

    detection (workers) ─► INTERNAL.CODE_MODEL.FILE_SCORE records ─► CodeModelPass.decide
         ─► records removed ─► folds ─► verdict ─► + SUSPECT.CODE.MODEL.001
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.javascript.code_model import FileScoreRecord

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.models import Finding


class CodePackageStep:
    """The parent's half (outer-layer review: numbers only): the max over the package's reached files'
    scores, the decision, and the removal of every record. Runs after the verdict, so the model's
    finding never feeds the verdict model's features (no echo, item 46), and is its own evidence
    family (item 45)."""

    #: The operating point. `block_at` is off (None) until the joint choice with reuse and the
    #: false-alarm levers is made (notes/47); `report_at` reports at MEDIUM, below the gate.
    REPORT_AT: ClassVar[float] = 0.9
    BLOCK_AT: ClassVar[float | None] = None
    MAX_FILES: ClassVar[int] = 64

    @classmethod
    def records(cls, findings: list[Any]) -> list[tuple[float, list[str], Any]]:
        """Each record's (score, carriers, finding), in the current version only."""
        out = []
        for f in findings:
            if f.rule_id != FileScoreRecord.RULE:
                continue
            decoded = FileScoreRecord.decode(f.message)
            if decoded is not None:
                out.append((decoded[0], decoded[1], f))
        return out

    @classmethod
    def decide(
        cls,
        findings: list[Any],
        model_finding: Any,
        report_at: float | None = None,
        block_at: float | None = None,
    ) -> tuple[list[Any], Any | None]:
        """(`findings` without the records, the model's finding or None). Taken before the folds,
        which could merge one rule's records across files, and the finding added after the verdict,
        which must not read it. `model_finding(path, score, carriers, blocking)` builds it."""
        report_at = cls.REPORT_AT if report_at is None else report_at
        block_at = cls.BLOCK_AT if block_at is None else block_at
        scored = sorted(cls.records(findings), key=lambda r: (-r[0], r[2].location.path))[
            : cls.MAX_FILES
        ]
        kept = [f for f in findings if f.rule_id != FileScoreRecord.RULE]
        if not scored or scored[0][0] < report_at:
            return kept, None
        score, carriers, record = scored[0]
        blocking = block_at is not None and score >= block_at
        return kept, model_finding(record.location.path, score, carriers, blocking)


class CodeModelPass:
    DETECTOR = "code-model"

    @staticmethod
    def detector(engine: Any) -> Any | None:
        return next(
            (d for d in engine.detectors if getattr(d, "id", "") == CodeModelPass.DETECTOR), None
        )

    @staticmethod
    def decide(
        engine: Any, findings: list[Finding], ctx: ScanContext
    ) -> tuple[list[Finding], tuple[Finding, ...]]:
        """(the findings without the records, what to add after the verdict)."""
        detector = CodeModelPass.detector(engine)
        if detector is None:
            return CodeModelPass.without_records(findings), ()
        try:
            config = engine.config
            kept, finding = CodePackageStep.decide(
                findings,
                detector.model_finding,
                report_at=getattr(config, "code_model_report_at", None),
                block_at=getattr(config, "code_model_block_at", None),
            )
        except Exception as error:  # noqa: BLE001 -- extra evidence must never cost the scan
            note = detector.operational(
                path=".",
                rule_id="OPERATIONAL.CODE_MODEL.UNAVAILABLE",
                message=f"The code model's package step failed, so no package was scored: {error}",
            )
            return CodeModelPass.without_records(findings), (note,)
        extra = [finding] if finding is not None else []
        note = detector.unavailable_note(".")
        if note is not None:
            extra.append(note)
        return kept, tuple(extra)

    @staticmethod
    def without_records(findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.rule_id != FileScoreRecord.RULE]


__all__ = ["CodeModelPass", "CodePackageStep"]
