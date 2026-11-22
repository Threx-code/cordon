"""The feedback loop's records (SI-I1): a miss, a false positive, a new detection and a rollback each become an append-only record the next loop run reads.

    Feedback.add(log_dir, kind, artifact_digest, detail)   appends one record (id = its position) to `<log_dir>/feedback.jsonl`
    Feedback.read(log_dir, after)                          -> (records after the watermark, the new watermark)
    Feedback.acquisition(records)                          -> what the next run acquires or re-checks, by kind

The watermark is the id of the last record a run has read, so a record is read by exactly one run and a run that reads nothing leaves it where it was. A record is never edited; a correction is a
new record that names the one it corrects.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

KINDS: Final = ("miss", "false_positive", "new_detection", "rollback")
#: What each kind asks of the next run.
ACQUIRE: Final = {
    "miss": "acquire units like it (the same family and mechanism) for the next capture window",
    "false_positive": "acquire legitimate lookalikes and re-measure the rule that blocked it",
    "new_detection": "acquire its neighbours and add its family to the labelled set",
    "rollback": "re-evaluate the candidate that was rolled back before it is proposed again",
}


class Feedback:
    @staticmethod
    def path(log_dir: Path) -> Path:
        return log_dir / "feedback.jsonl"

    @staticmethod
    def add(
        log_dir: Path,
        kind: str,
        artifact_digest: str,
        detail: dict[str, Any] | None = None,
        corrects: int | None = None,
    ) -> int:
        """Append a record and return its id."""
        if kind not in KINDS:
            raise ValueError(f"feedback kind {kind!r} not in {list(KINDS)}")
        log_dir.mkdir(parents=True, exist_ok=True)
        existing = Feedback.records(log_dir)
        if corrects is not None and not 0 <= corrects < len(existing):
            raise ValueError(f"no record {corrects} to correct")
        record = {
            "id": len(existing),
            "kind": kind,
            "artifact_digest": artifact_digest,
            "detail": detail or {},
            "corrects": corrects,
        }
        with Feedback.path(log_dir).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return len(existing)

    @staticmethod
    def records(log_dir: Path) -> list[dict[str, Any]]:
        path = Feedback.path(log_dir)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    @staticmethod
    def read(log_dir: Path, after: int = -1) -> tuple[list[dict[str, Any]], int]:
        """The records with an id above the watermark `after`, and the new watermark (unchanged when there are none)."""
        fresh = [r for r in Feedback.records(log_dir) if r["id"] > after]
        return fresh, (fresh[-1]["id"] if fresh else after)

    @staticmethod
    def acquisition(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """For each kind present: the ask and the artifacts it is about. A record that a later one corrects is left out."""
        corrected = {r["corrects"] for r in records if r.get("corrects") is not None}
        out: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            if record["id"] in corrected:
                continue
            entry = out.setdefault(record["kind"], [])
            entry.append(
                {"artifact_digest": record["artifact_digest"], "ask": ACQUIRE[record["kind"]]}
            )
        return out
