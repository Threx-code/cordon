"""verdict_train reads features as the scanner scores them: through FeatureRecord.read, folded.

```
  row ── evidence(row) ──────────────► rebuilt from findings + verdict.package, folded
  row ── evidence(row, record=True) ─► the scan's own record where it has one, folded
```
"""

from __future__ import annotations

import sys

from cordon_scanner.decide.feature_schema import FeatureFold, FeatureRecord
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from verdict_train import VerdictTrain


class VerdictTrainKit:
    PACKAGE: dict[str, float] = {"code_import_tok_517": 2.0, "code_import_tok_5": 1.0, "files": 3.0}  # noqa: RUF012

    @staticmethod
    def row(record: dict[str, float] | None = None) -> dict:
        verdict: dict = {"package": dict(VerdictTrainKit.PACKAGE)}
        if record is not None:
            verdict["features"] = {"schema": "fs1-test", "values": record}
        return {
            "file": "npm/x-1.0.0.tgz",
            "findings": [
                ["SUSPECT.X.001", "high", "high", "suspicious", "package/index.js", 1, "h"]
            ],
            "verdict": verdict,
        }


class TestEvidence:
    def test_a_row_is_rebuilt_and_folded_as_the_scanner_folds(self) -> None:
        row = VerdictTrainKit.row()
        features = VerdictTrain.evidence(row)
        assert features == FeatureRecord.read(row)[1]
        assert features["pkg:code_import_tok_f5"] == 3.0
        assert "pkg:code_import_tok_517" not in features

    def test_the_record_is_read_only_when_asked(self) -> None:
        record = {"pkg:code_import_tok_517": 7.0, "r:SUSPECT.Y.001": 1.0}
        row = VerdictTrainKit.row(record)
        assert VerdictTrain.evidence(row, record=True) == FeatureFold.apply(record)
        assert VerdictTrain.evidence(row) == VerdictTrain.evidence(VerdictTrainKit.row())
