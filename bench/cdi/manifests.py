"""Which split an artifact is in, read from the dataset manifests (SI-Q10): the single source of truth, never copied onto a miss.

A manifest is `{"dataset": name, "split": "train" | "dev" | "held" | ..., "artifacts": [artifact digest, ...]}`. A miss records the artifact's digest and nothing about its split, so
moving an artifact between manifests moves its membership with no edit to the miss. An artifact in two splits is a leak, and asking for its membership says so instead of picking one.
"""

from __future__ import annotations

from typing import Any


class ManifestConflict(ValueError):
    """An artifact is listed in more than one split: its membership is not defined, and a factory must not guess."""

    def __init__(self, digest: str, splits: tuple[str, ...]) -> None:
        super().__init__(f"{digest} is in more than one split: {', '.join(splits)}")
        self.digest = digest
        self.splits = splits


class Manifests:
    def __init__(self, manifests: list[dict[str, Any]]) -> None:
        self._splits: dict[str, set[str]] = {}
        for manifest in manifests:
            for digest in manifest.get("artifacts", ()):
                self._splits.setdefault(str(digest), set()).add(str(manifest["split"]))

    def membership(self, artifact_digest: str) -> str | None:
        """The split an artifact is in, None when no manifest lists it; `ManifestConflict` when two splits do."""
        splits = self._splits.get(artifact_digest)
        if not splits:
            return None
        if len(splits) > 1:
            raise ManifestConflict(artifact_digest, tuple(sorted(splits)))
        return next(iter(splits))

    def of_miss(self, miss: dict[str, Any]) -> str | None:
        """The split of the artifact a miss is about."""
        return self.membership(str(miss["artifact_digest"]))
