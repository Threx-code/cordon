#!/usr/bin/env python3
"""Turn data/scans.jsonl into the benign-noise tables: per ecosystem, per rule, per path context.

    python3 bench/longtail_levels.py bench/longtail > bench/longtail/summary.json
    python3 bench/longtail_levels.py bench/longtail --split work      # tune on this half
    python3 bench/longtail_levels.py bench/longtail --split holdout   # publish this half
    python3 bench/longtail_levels.py bench/longtail --strict          # exit 1 if integrity fails

Split (fixed and published, so no package can be moved between halves): sha256 of
"<ecosystem>:<lower-cased name>"; first byte even -> work, odd -> holdout. Packages read by hand
while tuning are listed in <data>/holdout-excluded.txt (one manifest `file` per line) and are left
out of the holdout half, because reading them would have leaked them into the tuning.

Integrity (reported in every summary; `--strict` fails on any of them): every manifest entry has
exactly one result, scanner errors (exit 2 / unparseable) stay under 0.1%, and the data directory
records the scanner version that produced it (scanner-version.json).

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

import hashlib
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


class Split:
    @staticmethod
    def of(ecosystem: str, name: str) -> str:
        digest = hashlib.sha256(f"{ecosystem}:{name.lower()}".encode()).digest()
        return "work" if digest[0] % 2 == 0 else "holdout"


class Kind:
    """What a blocking rule is about. A CVE in a declared dependency answers a different question
    from malicious code, and the two are never added together."""

    PRIORITY = ("malicious-or-suspicious-code", "secret", "iac-or-policy", "vulnerability")

    @staticmethod
    def of(rule: str) -> str:
        if rule.startswith("VULNERABLE."):
            return "vulnerability"
        if rule.startswith("SECRET."):
            return "secret"
        if rule.startswith(("MALWARE.", "SUSPECT.")) and not rule.startswith(
            ("SUSPECT.IAC.", "SUSPECT.K8S.", "SUSPECT.CFN.")
        ):
            return "malicious-or-suspicious-code"
        return "iac-or-policy"

    @classmethod
    def primary(cls, kinds: set[str]) -> str:
        return next((k for k in cls.PRIORITY if k in kinds), "other")


class Incomplete:
    """Why a scan says `complete: false`. Two different things share the flag: content Cordon did
    not read (members rejected, truncated, pruned, timed out), and an ecosystem with no offline
    advisory feed, where every byte was read. Only the first is a detection gap."""

    CONTENT = (
        "OPERATIONAL.ARCHIVE.",
        "OPERATIONAL.FILE.TRUNCATED",
        "OPERATIONAL.FORMAT.UNREADABLE",
        "POLICY.COVERAGE.PRUNED",
    )
    ADVISORY = ("OPERATIONAL.ADVISORY.",)

    @classmethod
    def kind(cls, rec: dict) -> str | None:
        if rec.get("complete") is not False:
            return None
        rules = [f[0] for f in rec.get("findings", [])]
        if rec.get("exit") == "timeout" or any(r.startswith(cls.CONTENT) for r in rules):
            return "content"
        if any(r.startswith(cls.ADVISORY) for r in rules):
            return "advisory-only"
        return "unexplained"


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
    def integrity(data: Path, manifest: dict, results: list[dict]) -> dict:
        counts = Counter(r["file"] for r in results)
        missing = sorted(set(manifest) - set(counts))
        duplicated = sorted(f for f, n in counts.items() if n > 1)
        errors = sum(1 for r in results if r.get("exit") == 2 or "parse_error" in r)
        version = data / "scanner-version.json"
        problems = []
        if manifest and missing:
            problems.append(f"{len(missing)} manifest entries have no result")
        if duplicated:
            problems.append(f"{len(duplicated)} files have more than one result")
        if results and errors / len(results) > 0.001:
            problems.append(f"{errors} scanner errors ({errors / len(results):.2%}) exceed 0.1%")
        if not version.exists():
            problems.append("no scanner-version.json: the numbers cannot name the scanner")
        return {
            "results": len(results),
            "manifest_entries": len(manifest),
            "missing": len(missing),
            "missing_examples": missing[:10],
            "duplicated": len(duplicated),
            "scanner_errors": errors,
            "scanner_version": json.loads(version.read_text(encoding="utf-8"))
            if version.exists()
            else None,
            "ok": not problems,
            "problems": problems,
        }

    @staticmethod
    def main(data: Path, split: str | None = None) -> dict:
        manifest = {}
        if (data / "manifest.jsonl").exists():
            for line in (data / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
                r = json.loads(line)
                manifest[r["file"]] = r
        excluded = set()
        if (data / "holdout-excluded.txt").exists():
            excluded = {
                x.strip()
                for x in (data / "holdout-excluded.txt").read_text(encoding="utf-8").splitlines()
                if x.strip() and not x.startswith("#")
            }
        results = [
            json.loads(x)
            for x in (data / "scans.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        integrity = LongtailLevels.integrity(data, manifest, results)

        def half(rec: dict) -> str:
            meta = manifest.get(rec["file"])
            eco = meta["ecosystem"] if meta else rec["file"].split("/", 1)[0]
            name = meta["name"] if meta else rec["file"].split("/", 1)[-1]
            return Split.of(eco, name)

        if split is not None:
            results = [
                r
                for r in results
                if half(r) == split and not (split == "holdout" and r["file"] in excluded)
            ]
        per_eco: dict[str, Counter] = defaultdict(Counter)
        defaultdict(Counter)  # rule -> level of the finding -> packages
        rule_eco: dict[str, Counter] = defaultdict(Counter)
        block_rules: Counter = Counter()
        warn_rules: Counter = Counter()
        ctx_counts: dict[str, Counter] = defaultdict(Counter)
        incomplete = Counter()
        incomplete_kind: dict[str, Counter] = defaultdict(Counter)
        blocked_list = []
        for rec in results:
            eco = rec["file"].split("/", 1)[0]
            lv = LongtailLevels.level(rec)
            per_eco[eco][lv] += 1
            per_eco[eco]["total"] += 1
            why = Incomplete.kind(rec)
            if why:
                incomplete[eco] += 1
                incomplete_kind[eco][why] += 1
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
                per_eco[eco][
                    "blocked_primary:" + Kind.primary({Kind.of(r) for r in seen_block})
                ] += 1
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
            "warn_rules": warn_rules.most_common(),
            "contexts": {k: dict(v) for k, v in ctx_counts.items()},
            "blocked": blocked_list,
            "incomplete": dict(incomplete),
            "incomplete_by_kind": {k: dict(v) for k, v in incomplete_kind.items()},
            "split": split,
            "holdout_excluded": len(excluded) if split == "holdout" else 0,
            "integrity": integrity,
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
                "blocked_primary": {
                    k.split(":", 1)[1]: v for k, v in c.items() if k.startswith("blocked_primary:")
                },
                "not_blocked_for_code_rate": round(
                    1 - c["blocked_primary:malicious-or-suspicious-code"] / n, 4
                )
                if n
                else None,
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
    args = sys.argv[1:]
    split = args[args.index("--split") + 1] if "--split" in args else None
    if split not in (None, "work", "holdout"):
        raise SystemExit("--split must be work or holdout")
    summary = LongtailLevels.main(Path(args[0]), split)
    json.dump(summary, sys.stdout, indent=1)
    if "--strict" in args and not summary["integrity"]["ok"]:
        print("\nintegrity: " + "; ".join(summary["integrity"]["problems"]), file=sys.stderr)
        raise SystemExit(1)
