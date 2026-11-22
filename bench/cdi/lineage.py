"""The lineage check by content (SI-Q11): a model's training units against every eval unit, grouped by the normalised-content key and never by sha256 alone.

A reworded skill, a re-released package or a repacked archive has a new sha256 and the same content, so a check on sha256 reports no overlap for exactly the copies that
let a model grade its own homework. The key is the FeatureSet's `featureset_digest` (`featureset.py`): content features only, no location, no confidence, no scanner or intel
version. A unit with no content feature at all (a clean scan with no package facts) has no content key: every such unit would otherwise share one, so it is compared by sha256
only. Both counts are reported, so a report says how many overlaps only the content key found.
"""

from __future__ import annotations

from typing import Any

from bench.cdi.featureset import FeatureSetBuilder


class Lineage:
    @staticmethod
    def content_key(row: dict[str, Any]) -> str | None:
        """The normalised-content key of one scan row, or None when the row has no content feature to key on."""
        record = FeatureSetBuilder.build_featureset(
            row, artifact_id=str(row.get("file", "")), ecosystem="unknown"
        )
        if not any(f.get("source") == "content" for f in record["features"]):
            return None
        return str(record["featureset_digest"])

    @staticmethod
    def sha(row: dict[str, Any]) -> str:
        return str(row.get("sha256") or row.get("file") or "")

    @staticmethod
    def overlap(
        train: dict[str, dict[str, Any]], held: dict[str, dict[str, Any]]
    ) -> dict[str, int]:
        """How many eval units share a training unit's content key or its sha256 (`units`, each once), by which (`by_content`, `by_sha256`), and how many only the content key
        found (`missed_by_sha256`)."""
        content = {key for row in train.values() if (key := Lineage.content_key(row)) is not None}
        shas = {Lineage.sha(row) for row in train.values()}
        units = by_content = by_sha = missed = 0
        for row in held.values():
            key = Lineage.content_key(row)
            same_content = key is not None and key in content
            same_sha = Lineage.sha(row) in shas
            units += same_content or same_sha
            by_content += same_content
            by_sha += same_sha
            missed += same_content and not same_sha
        return {
            "units": units,
            "by_content": by_content,
            "by_sha256": by_sha,
            "missed_by_sha256": missed,
        }
