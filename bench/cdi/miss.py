"""E (Miss Analysis & Learning): a DetectionMiss from a confirmed false negative.

Promotes the census tools (reviews/*/tools/census.py, skills_census.py) to a structured record: per
confirmed FN, what ran, what was absent, the failure mechanism, the nearest benign lookalike, and
what is needed. ``dataset_membership`` is read from a5's manifests (the single source of truth); this
record only references it. A miss informs the factory only when ``schemas.Schemas.eligible_for_factory`` is
true (confirmed/corroborated label AND train/dev split) -- val/held/fresh misses are reported, never
learned from.
"""

from __future__ import annotations

from typing import Any

from . import schemas

_NEEDED_KINDS = frozenset({"extractor", "correction", "rule", "composite", "model", "capability"})


class Miss:
    """Build a DetectionMiss record. Stateless; call the static method."""

    @staticmethod
    def detection_miss(
        *,
        miss_id: str,
        artifact_id: str,
        artifact_digest: str,
        label_ref: str,
        dataset_membership: str,
        baseline: dict[str, Any],
        reproduce: dict[str, Any],
        detectors_ran: list[str],
        absent_or_misweighted: list[dict[str, Any]],
        failure_mechanism: str,
        needed: dict[str, Any],
        lookalike_comparison: dict[str, Any] | None = None,
        candidate_ids: list[str] | None = None,
        regression_test_ref: str | None = None,
    ) -> dict[str, Any]:
        if needed.get("kind") not in _NEEDED_KINDS:
            raise ValueError(f"needed.kind {needed.get('kind')!r} not in {sorted(_NEEDED_KINDS)}")
        record = {
            "schema_version": schemas.SCHEMA_VERSIONS["DetectionMiss"],
            "miss_id": miss_id,
            "artifact_id": artifact_id,
            "artifact_digest": artifact_digest,
            "label_ref": label_ref,
            "dataset_membership": dataset_membership,
            "baseline": baseline,
            "reproduce": reproduce,
            "detectors_ran": list(detectors_ran),
            "absent_or_misweighted": list(absent_or_misweighted),
            "failure_mechanism": failure_mechanism,
            "lookalike_comparison": lookalike_comparison or {},
            "needed": needed,
            "candidate_ids": list(candidate_ids or []),
            "regression_test_ref": regression_test_ref,
        }
        return schemas.Schemas.validate("DetectionMiss", record)
