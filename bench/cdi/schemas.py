"""Versioned, append-only record schemas for the CDI learning pipeline (the B/E/F side of §8).

The modelling + learning team owns four of the CDI §8 data model: FeatureSet, ThreatCluster,
DetectionMiss, CandidateDetector. a5 owns Artifact / Evidence / Label / EvaluationRun /
PromotionDecision / DetectionBundle / DeploymentObservation, and these records reference those by id.

Records are APPEND-ONLY: an edit is a new version (tamper-evident, CDI §6). The ``build_*`` helpers in
the sibling modules are deterministic -- the same inputs give the same record, including its digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA_VERSIONS: dict[str, str] = {
    "FeatureSet": "1.0.0",
    "ThreatCluster": "1.0.0",
    "DetectionMiss": "1.0.0",
    "CandidateDetector": "1.0.0",
}

#: Required top-level keys per schema. Light structural validation only; the gate (a5) does the
#: measurement checks. Keeping this here means a malformed record is caught at build time.
REQUIRED: dict[str, frozenset[str]] = {
    "FeatureSet": frozenset(
        {
            "schema_version",
            "featureset_digest",
            "artifact_id",
            "artifact_digest",
            "ecosystem",
            "extractors",
            "features",
            "verdict_features",
        }
    ),
    "ThreatCluster": frozenset(
        {"schema_version", "cluster_id", "method", "method_version", "members", "edges", "label"}
    ),
    "DetectionMiss": frozenset(
        {
            "schema_version",
            "miss_id",
            "artifact_id",
            "artifact_digest",
            "label_ref",
            "dataset_membership",
            "baseline",
            "reproduce",
            "failure_mechanism",
            "needed",
        }
    ),
    "CandidateDetector": frozenset(
        {
            "schema_version",
            "candidate_id",
            "version",
            "kind",
            "lane",
            "derived_from_miss_ids",
            "train_dataset_digest",
            "compatibility",
            "status",
        }
    ),
}

#: The split assignment is manifest-owned (a5), the single source of truth; a DetectionMiss only
#: references it. Factory eligibility is two gates: a confirmed/corroborated Label AND a train/dev
#: split (CDI §4; the leakage that bit us twice).
FACTORY_TIERS: frozenset[str] = frozenset({"confirmed", "corroborated"})
FACTORY_SPLITS: frozenset[str] = frozenset({"train", "dev"})


def canonical_json(obj: Any) -> str:
    """A stable, sorted JSON string: the basis for every digest, so a record hashes identically
    wherever it is built."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def validate(kind: str, record: dict[str, Any]) -> dict[str, Any]:
    """Structural + version check. Raises ValueError; returns the record so callers can
    ``return validate(...)``."""
    if kind not in SCHEMA_VERSIONS:
        raise ValueError(f"unknown schema {kind!r}")
    missing = REQUIRED[kind] - set(record)
    if missing:
        raise ValueError(f"{kind} missing keys: {sorted(missing)}")
    want = SCHEMA_VERSIONS[kind]
    if record.get("schema_version") != want:
        raise ValueError(f"{kind} schema_version {record.get('schema_version')!r} != {want!r}")
    return record


def eligible_for_factory(label_tier: str, split: str) -> bool:
    """The two-gate rule E and F obey before a miss may inform a candidate."""
    return label_tier in FACTORY_TIERS and split in FACTORY_SPLITS
