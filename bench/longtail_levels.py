#!/usr/bin/env python3
"""Turn data/scans.jsonl into the benign-noise tables: per ecosystem, per rule, per path context.

    python3 bench/longtail_levels.py bench/longtail > bench/longtail/summary.json

Levels, per package:
  known    -- blocked, and a known-malicious intel record matched (MALWARE.*.KNOWN*): real malware
              in the random draw, counted apart -- it is the long tail's base rate, not noise
  blocked  -- Cordon exited 1 on content alone: a false positive OR unknown malware, to adjudicate
  warned   -- not blocked, but at least one finding at medium or above that is not OPERATIONAL.*
  noted    -- only low/info findings (or OPERATIONAL.* notes)
  clean    -- no findings at all except OPERATIONAL.*
  error    -- timeout, crash, or unparseable output
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ORDER = ["info", "low", "medium", "high", "critical"]
TEST = re.compile(
    r"(^|/)(tests?|testing|__tests__|spec|specs|fixtures?|testdata|test-data|examples?|samples?|docs?|demo|benchmarks?)(/|$)",
    re.I,
)
VENDOR = re.compile(
    r"(^|/)(node_modules|vendor|third_party|3rdparty|external|dist|build)(/|$)|\.min\.js$|\.bundle\.js$",
    re.I,
)


class LongtailLevels:
    @staticmethod
    def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
        if n == 0:
            return (0.0, 0.0)
        p = k / n
        d = 1 + z * z / n
        c = p + z * z / (2 * n)
        r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
        return (round((c - r) / d, 4), round((c + r) / d, 4))

    @staticmethod
    def level(rec: dict) -> str:
        if rec.get("exit") not in (0, 1, 4) or "findings" not in rec:
            return "error"
        if rec["exit"] == 1:
            if any(".KNOWN" in f[0] and f[0].startswith("MALWARE.") for f in rec["findings"]):
                return "known"
            return "blocked"
        top = -1
        for rule, sev, *_ in rec["findings"]:
            if rule.startswith("OPERATIONAL."):
                continue
            top = max(top, ORDER.index(sev) if sev in ORDER else 0)
        if top >= ORDER.index("medium"):
            return "warned"
        if top >= 0:
            return "noted"
        return "clean"

    @staticmethod
    def context(path: str) -> str:
        if TEST.search(path):
            return "test/docs/example"
        if VENDOR.search(path):
            return "vendored/built"
        return "source"

    @staticmethod
    def main(data: Path) -> dict:
        manifest = {}
        if (data / "manifest.jsonl").exists():
            for line in (data / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
                r = json.loads(line)
                manifest[r["file"]] = r
        per_eco: dict[str, Counter] = defaultdict(Counter)
        defaultdict(Counter)  # rule -> level of the finding -> packages
        rule_eco: dict[str, Counter] = defaultdict(Counter)
        block_rules: Counter = Counter()
        warn_rules: Counter = Counter()
        ctx_counts: dict[str, Counter] = defaultdict(Counter)
        incomplete = Counter()
        blocked_list = []
        for line in (data / "scans.jsonl").read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            eco = rec["file"].split("/", 1)[0]
            lv = LongtailLevels.level(rec)
            per_eco[eco][lv] += 1
            per_eco[eco]["total"] += 1
            if rec.get("complete") is False:
                incomplete[eco] += 1
            seen_block, seen_warn = set(), set()
            # A known-malicious package is a true positive; its findings are not benign noise.
            for rule, sev, conf, cat, path in [] if lv == "known" else rec.get("findings", []):
                if rule.startswith("OPERATIONAL."):
                    continue
                sev_i = ORDER.index(sev) if sev in ORDER else 0
                gate = cat == "malicious" or (
                    sev_i >= ORDER.index("high") and conf in ("medium", "high", "confirmed")
                )
                if lv == "blocked" and gate:
                    seen_block.add(rule)
                    ctx_counts["block:" + rule][LongtailLevels.context(path)] += 1
                elif sev_i >= ORDER.index("medium"):
                    seen_warn.add(rule)
                    ctx_counts["warn:" + rule][LongtailLevels.context(path)] += 1
            for r in seen_block:
                block_rules[r] += 1
                rule_eco[r]["block:" + eco] += 1
            for r in seen_warn:
                warn_rules[r] += 1
                rule_eco[r]["warn:" + eco] += 1
            if lv == "blocked":
                blocked_list.append(
                    {
                        "file": rec["file"],
                        "rules": sorted(seen_block),
                        "paths": sorted(
                            {p for r, s, c, cat, p in rec["findings"] if r in seen_block}
                        )[:5],
                    }
                )
        out = {
            "ecosystems": {},
            "block_rules": block_rules.most_common(),
            "warn_rules": warn_rules.most_common(60),
            "contexts": {k: dict(v) for k, v in ctx_counts.items()},
            "blocked": blocked_list,
            "incomplete": dict(incomplete),
            "rule_by_eco": {k: dict(v) for k, v in rule_eco.items()},
        }
        total = Counter()
        for eco, c in sorted(per_eco.items()):
            n = c["total"] - c["error"] - c["known"]
            total.update(c)
            out["ecosystems"][eco] = {
                "scanned": c["total"],
                "errors": c["error"],
                "known_malicious": c["known"],
                "blocked": c["blocked"],
                "warned": c["warned"],
                "not_blocked_rate": round(1 - c["blocked"] / n, 4) if n else None,
                "not_blocked_ci": LongtailLevels.wilson(n - c["blocked"], n),
                "no_warning_rate": round((c["clean"] + c["noted"]) / n, 4) if n else None,
                "no_warning_ci": LongtailLevels.wilson(c["clean"] + c["noted"], n),
                "clean_rate": round(c["clean"] / n, 4) if n else None,
            }
        n = total["total"] - total["error"] - total["known"]
        out["all"] = {
            "scanned": total["total"],
            "errors": total["error"],
            "known_malicious": total["known"],
            "blocked": total["blocked"],
            "warned": total["warned"],
            "not_blocked_rate": round(1 - total["blocked"] / n, 4) if n else None,
            "not_blocked_ci": LongtailLevels.wilson(n - total["blocked"], n),
            "no_warning_rate": round((total["clean"] + total["noted"]) / n, 4) if n else None,
            "no_warning_ci": LongtailLevels.wilson(total["clean"] + total["noted"], n),
        }
        return out


if __name__ == "__main__":
    json.dump(LongtailLevels.main(Path(sys.argv[1])), sys.stdout, indent=1)
