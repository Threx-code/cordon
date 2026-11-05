"""The evaluation gate (CDI §4): one decision for every candidate, from scans already taken.

    python -m bench.cdi.gate --spec spec.json --out DIR

Scanning is not done here: both sides of every set are scanned the way every A/B in this review was
(`reviews/review-98/tools/rescan_sample.py`, network off, the measurement config), and the gate reads
the two `scans.jsonl` per set. That keeps the decision reproducible from archived files alone
(CDI §9.12).

The spec names the candidate, the policy and every set:

    {"candidate_id": "...", "policy": {...} | "path/to/policy.json",
     "sets": [{"name": "pypi-halfA", "kind": "malware", "area": "pypi", "split": "dev",
               "off": "off/scans.jsonl", "on": "on/scans.jsonl"},
              {"name": "pypi-benign-work", "kind": "benign", "area": "pypi", "split": "work", ...}],
     "lineage": {"train_keys": "train.txt", "eval_keys": ["held.txt", "fresh.txt"]}}

What it decides, each a named gate with a reason (`PromotionDecision.gates`):
  lose_zero     no unit blocked before is unblocked after, in any malware set
  benign_bar    per area: the after-side malware-class block rate's Wilson upper bound is within
                the policy's bar, or no worse than before where the area is not yet at it
  new_benign    every newly blocked benign unit is LISTED; the policy may allow some only once read
  runtime       p99 seconds per unit within the policy's ratio; no new timeouts
  lineage       zero overlap between the candidate's training content keys and any eval set
                (normalised-content keys, `featureset.py`), so a model never grades its own homework

A failing gate rejects with the reasons. Insufficient evidence (a set too small for its bar) is
reported as such and never as a pass (CDI §4: "insufficient evidence means research or shadow").
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"
DEFAULT_POLICY: dict[str, Any] = {
    "policy_id": "gate-policy/1",
    "lose_max": 0,
    "benign_ub_bar": 0.005,
    "allow_new_benign_blocks": 0,
    "p99_ratio_max": 2.0,
    "new_timeouts_max": 0,
    "lineage_overlap_max": 0,
    "min_benign_n_for_bar": 740,
}
Z = 1.96


class Gate:
    """The CDI gate: from the off and on scans of every set, the evaluation and the decision."""

    @staticmethod
    def wilson(k: int, n: int) -> tuple[float, float]:
        if n == 0:
            return (0.0, 1.0)
        p = k / n
        d = 1 + Z * Z / n
        m = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
        return ((p + Z * Z / (2 * n) - m) / d, (p + Z * Z / (2 * n) + m) / d)

    @staticmethod
    def read_scans(path: str) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    rows[row["file"]] = row
        return rows

    @staticmethod
    def blocked(row: dict[str, Any] | None) -> bool:
        """What a user sees: the default gate's exit status. A failed scan is not a block."""
        return bool(row) and row.get("exit") == 1

    @staticmethod
    def malware_class_block(row: dict[str, Any] | None) -> bool:
        """A benign unit blocked for malware, not only for a leaked secret or a policy finding (the
        owner's ruling: SECRET.* and policy-only blocks are reported apart)."""
        if not Gate.blocked(row):
            return False
        findings = row.get("findings") or []
        serious = [f for f in findings if len(f) > 1 and f[1] in ("high", "critical")]
        return any(not str(f[0]).startswith(("SECRET.", "VULNERABLE.", "POLICY.")) for f in serious)

    @staticmethod
    def p99(rows: dict[str, dict[str, Any]]) -> float:
        secs = sorted(float(r.get("seconds") or 0) for r in rows.values())
        return secs[min(len(secs) - 1, int(0.99 * len(secs)))] if secs else 0.0

    @staticmethod
    def timeouts(rows: dict[str, dict[str, Any]]) -> set[str]:
        return {f for f, r in rows.items() if r.get("exit") == "timeout"}

    @staticmethod
    def keys(path: str) -> set[str]:
        return {
            line.strip()
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    @staticmethod
    def file_digest(path: str) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @staticmethod
    def evaluate(spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        policy = spec.get("policy") or DEFAULT_POLICY
        if isinstance(policy, str):
            policy = json.loads(Path(policy).read_text(encoding="utf-8"))
        policy = {**DEFAULT_POLICY, **policy}
        metrics: dict[str, Any] = {"sets": {}, "per_area_benign": {}}
        lost: list[str] = []
        new_benign: list[str] = []
        datasets = []
        gates: dict[str, Any] = {}
        benign_by_area: dict[str, list[int]] = {}
        for s in spec["sets"]:
            off, on = Gate.read_scans(s["off"]), Gate.read_scans(s["on"])
            common = sorted(set(off) & set(on))
            datasets.append(
                {
                    "name": s["name"],
                    "split": s.get("split", ""),
                    "n": len(common),
                    "off_digest": Gate.file_digest(s["off"]),
                    "on_digest": Gate.file_digest(s["on"]),
                }
            )
            entry: dict[str, Any] = {"n": len(common), "missing_on": len(set(off) - set(on))}
            if s["kind"] == "malware":
                b_off = {f for f in common if Gate.blocked(off[f])}
                b_on = {f for f in common if Gate.blocked(on[f])}
                set_lost = sorted(b_off - b_on)
                lost += [f"{s['name']}:{f}" for f in set_lost]
                lo, hi = Gate.wilson(len(b_on), len(common))
                entry.update(
                    blocked_off=len(b_off),
                    blocked_on=len(b_on),
                    lost=len(set_lost),
                    gained=len(b_on - b_off),
                    recall_on=[len(b_on), len(common), round(lo, 4), round(hi, 4)],
                )
            else:
                m_off = {f for f in common if Gate.malware_class_block(off[f])}
                m_on = {f for f in common if Gate.malware_class_block(on[f])}
                fresh = sorted(m_on - m_off)
                new_benign += [f"{s['name']}:{f}" for f in fresh]
                acc = benign_by_area.setdefault(s.get("area", "all"), [0, 0, 0])
                acc[0] += len(m_off)
                acc[1] += len(m_on)
                acc[2] += len(common)
                entry.update(
                    malware_class_off=len(m_off),
                    malware_class_on=len(m_on),
                    new_blocks=len(fresh),
                    unblocked=len(m_off - m_on),
                )
            entry.update(
                p99_off=Gate.p99({f: off[f] for f in common}),
                p99_on=Gate.p99({f: on[f] for f in common}),
                new_timeouts=len(
                    Gate.timeouts({f: on[f] for f in common})
                    - Gate.timeouts({f: off[f] for f in common})
                ),
            )
            metrics["sets"][s["name"]] = entry

        gates["lose_zero"] = (
            "pass" if len(lost) <= policy["lose_max"] else "fail",
            f"{len(lost)} lost",
        )
        bar_fail, insufficient = [], []
        for area, (k_off, k_on, n) in benign_by_area.items():
            _, ub_off = Gate.wilson(k_off, n)
            _, ub_on = Gate.wilson(k_on, n)
            metrics["per_area_benign"][area] = {
                "n": n,
                "off": k_off,
                "on": k_on,
                "ub_off": round(ub_off, 5),
                "ub_on": round(ub_on, 5),
            }
            if n < policy["min_benign_n_for_bar"]:
                insufficient.append(area)
            if ub_on > policy["benign_ub_bar"] and ub_on > ub_off:
                bar_fail.append(f"{area} ub {ub_on:.4f} > bar and worse than {ub_off:.4f}")
        gates["benign_bar"] = (
            "fail" if bar_fail else "pass",
            "; ".join(bar_fail) or "within bar or no worse",
        )
        if insufficient:
            gates["benign_bar_evidence"] = (
                "insufficient",
                f"n below {policy['min_benign_n_for_bar']}: {insufficient}",
            )
        gates["new_benign"] = (
            "pass" if len(new_benign) <= policy["allow_new_benign_blocks"] else "fail",
            f"{len(new_benign)} new benign blocks, each to be read",
        )
        worst = max(
            (e["p99_on"] / e["p99_off"] for e in metrics["sets"].values() if e.get("p99_off")),
            default=1.0,
        )
        new_to = sum(e["new_timeouts"] for e in metrics["sets"].values())
        gates["runtime"] = (
            "pass"
            if worst <= policy["p99_ratio_max"] and new_to <= policy["new_timeouts_max"]
            else "fail",
            f"worst p99 ratio {worst:.2f}, new timeouts {new_to}",
        )
        if spec.get("requires_reach") or spec.get("reach"):
            # A rule pack fires wherever its text appears. Every area its patterns reach in benign
            # content must be one the measured benign sets cover, or the block was never measured.
            reach = spec.get("reach") or {}
            unmeasured = sorted(
                f"{area} {r['matched']}/{r['units']}"
                for area, r in reach.items()
                if r.get("matched") and area not in benign_by_area
            )
            metrics["reach"] = reach
            if not reach:
                gates["reach"] = ("fail", "the pack's reach beyond its own sets was not measured")
            else:
                gates["reach"] = (
                    "fail" if unmeasured else "pass",
                    "matches benign content in unmeasured areas: " + ", ".join(unmeasured)
                    if unmeasured
                    else f"no benign match outside measured areas ({len(reach)} areas searched)",
                )
        lineage = spec.get("lineage")
        if lineage:
            train = Gate.keys(lineage["train_keys"])
            overlap = sum(len(train & Gate.keys(p)) for p in lineage["eval_keys"])
            gates["lineage"] = (
                "pass" if overlap <= policy["lineage_overlap_max"] else "fail",
                f"overlap {overlap}",
            )
        else:
            gates["lineage"] = ("not_applicable", "no trained component")
        outcome = "reject" if any(v[0] == "fail" for v in gates.values()) else "shadow"
        run = {
            "schema_version": SCHEMA_VERSION,
            "kind": "EvaluationRun",
            "candidate_id": spec.get("candidate_id", ""),
            "scanner_build": spec.get("scanner_build", {}),
            "intel_snapshot_digest": spec.get("intel_snapshot_digest", ""),
            "datasets": datasets,
            "metrics": metrics,
            "lost": lost,
            "new_benign_blocks": new_benign,
        }
        run["run_id"] = hashlib.sha256(json.dumps(run, sort_keys=True).encode()).hexdigest()[:24]
        decision = {
            "schema_version": SCHEMA_VERSION,
            "kind": "PromotionDecision",
            "candidate_id": spec.get("candidate_id", ""),
            "run_ids": [run["run_id"]],
            "policy_id": policy["policy_id"],
            "gates": {k: {"result": v[0], "reason": v[1]} for k, v in gates.items()},
            # A pass earns SHADOW, never blocking: promotion to blocking needs the shadow period and a
            # team approval (owner decision, 2026-10-22).
            "outcome": outcome,
            "approver": policy["policy_id"],
            # Binds the decision to the exact evaluation it was drawn from.
            "evaluation_run_sha256": hashlib.sha256(Gate.canonical(run)).hexdigest(),
        }
        return run, decision

    @staticmethod
    def canonical(document: dict[str, Any]) -> bytes:
        """The bytes a signature covers: sorted keys, no whitespace, the signature itself left out."""
        body = {k: v for k, v in document.items() if k != "signature"}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def sign(decision: dict[str, Any], seed_hex: str) -> dict[str, Any]:
        """Sign a decision with the evaluation lab's Ed25519 key (CDI §7).

        The Cloud promotes only a decision signed by a key it is configured to trust, so a decision
        written by hand -- "outcome": "shadow" for a candidate the gate rejected -- promotes nothing.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex.strip()))
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        return {
            **decision,
            "signature": {
                "keyid": hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16],
                "public": public,
                "sig": key.sign(Gate.canonical(decision)).hex(),
            },
        }

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--spec", required=True)
        parser.add_argument("--out", required=True)
        parser.add_argument(
            "--sign-key",
            help="file holding the evaluation lab's Ed25519 seed (hex); never committed",
        )
        args = parser.parse_args(argv)
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        run, decision = Gate.evaluate(spec)
        if args.sign_key:
            decision = Gate.sign(decision, Path(args.sign_key).read_text(encoding="utf-8"))
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "evaluation_run.json").write_text(
            json.dumps(run, indent=1, sort_keys=True), encoding="utf-8"
        )
        (out / "promotion_decision.json").write_text(
            json.dumps(decision, indent=1, sort_keys=True), encoding="utf-8"
        )
        print(json.dumps({"outcome": decision["outcome"], "gates": decision["gates"]}, indent=1))
        return 0 if decision["outcome"] != "reject" else 1


if __name__ == "__main__":
    sys.exit(Gate.main())
