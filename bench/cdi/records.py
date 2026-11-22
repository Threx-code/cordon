"""The three records the platform side of the loop needs beside the learning side's: ThreatCluster, DetectionBundle and DeploymentObservation.

    ThreatCluster          a group of artefacts that belong together, how it was grouped (method, version), the edges that joined it and its label. Built from a `ThreatGraph` (`graph.py`).
    DetectionBundle        what a promotion publishes: the artefacts of a candidate (path and sha256 each), the decision that allowed it, the scanner versions it is compatible with, its channel.
    DeploymentObservation  what the fleet reported for one artefact on one channel: scans seen, would-change counts, fires, confirmed fires, crashes, timeouts.

Records are versioned and append-only like the others (`schemas.py`); each builder returns a validated record, and the same inputs give the same record, digest included.
"""

from __future__ import annotations

from typing import Any, Final

from bench.cdi.schemas import SCHEMA_VERSIONS, Schemas

COUNTERS: Final = ("scans_seen", "would_change", "fires", "confirmed_fires", "crashes", "timeouts")
CHANNELS: Final = ("shadow", "canary", "stable")


class Records:
    @staticmethod
    def threat_cluster(
        *,
        members: list[str],
        edges: list[dict[str, Any]],
        method: str,
        method_version: str,
        label: str | None,
    ) -> dict[str, Any]:
        """`edges`: `{"a", "b", "kind", "weight"}`, each between two members. The id is the digest of the sorted members, so the same group has the same id wherever it is built."""
        ordered = sorted(members)
        if len(set(ordered)) != len(ordered) or len(ordered) < 2:
            raise ValueError("a cluster needs at least two distinct members")
        for edge in edges:
            if edge["a"] not in ordered or edge["b"] not in ordered:
                raise ValueError(f"edge {edge['a']!r}-{edge['b']!r} joins a non-member")
        record = {
            "schema_version": SCHEMA_VERSIONS["ThreatCluster"],
            "cluster_id": Schemas.digest(ordered),
            "method": method,
            "method_version": method_version,
            "members": ordered,
            "edges": sorted(edges, key=lambda e: (e["a"], e["b"], e["kind"])),
            "label": label,
        }
        return Schemas.validate("ThreatCluster", record)

    @staticmethod
    def detection_bundle(
        *,
        candidate_id: str,
        artefacts: list[dict[str, str]],
        decision_digest: str,
        compatibility: dict[str, str],
        channel: str,
    ) -> dict[str, Any]:
        """`artefacts`: `{"path", "sha256"}` each, at least one. A bundle is addressed by the digest of what it holds, so a changed file is another bundle."""
        if channel not in CHANNELS:
            raise ValueError(f"channel {channel!r} not in {list(CHANNELS)}")
        if not artefacts or any(not a.get("path") or not a.get("sha256") for a in artefacts):
            raise ValueError("a bundle needs at least one artefact, each with a path and a sha256")
        ordered = sorted(artefacts, key=lambda a: a["path"])
        record = {
            "schema_version": SCHEMA_VERSIONS["DetectionBundle"],
            "bundle_id": Schemas.digest([candidate_id, ordered, decision_digest]),
            "candidate_id": candidate_id,
            "artefacts": ordered,
            "decision_digest": decision_digest,
            "compatibility": dict(compatibility),
            "channel": channel,
        }
        return Schemas.validate("DetectionBundle", record)

    @staticmethod
    def deployment_observation(
        *, bundle_id: str, channel: str, window: str, counts: dict[str, int]
    ) -> dict[str, Any]:
        """The fleet's counts for a bundle on a channel over a window (an ISO date range). Every counter is present and not negative; a fire cannot be confirmed more often than it fired."""
        if channel not in CHANNELS:
            raise ValueError(f"channel {channel!r} not in {list(CHANNELS)}")
        missing = [c for c in COUNTERS if c not in counts]
        if missing:
            raise ValueError(f"missing counters: {', '.join(missing)}")
        if any(counts[c] < 0 for c in COUNTERS):
            raise ValueError("a counter is negative")
        if counts["confirmed_fires"] > counts["fires"]:
            raise ValueError("more confirmed fires than fires")
        record = {
            "schema_version": SCHEMA_VERSIONS["DeploymentObservation"],
            "bundle_id": bundle_id,
            "channel": channel,
            "window": window,
            **{c: int(counts[c]) for c in COUNTERS},
        }
        return Schemas.validate("DeploymentObservation", record)
