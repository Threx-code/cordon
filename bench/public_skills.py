#!/usr/bin/env python3
"""Cordon on the public malicious-skill benchmarks, as their papers report it (MEAS-5).

```
  MalSkillBench (arXiv 2606.07131)          Dataset/Skills/{malware,benign}/<skill>/   3,944 / 4,000
  MaliciousSkillBench (arXiv 2608.19901)    primary.parquet -> skills.jsonl (prepare)  7,505 / 2,235
        │
        ▼   each skill scanned as what it is to a user: a third-party skill folder, offline
  Cordon's default gate (PolicyGate, as the CLI decides)
        │
        ▼
  blocked      = the gate fails the skill
  flagged      = blocked, or any finding at MEDIUM or above
  per benchmark: recall, benign not blocked / no warning, precision -- each with a 95% interval --
  and, for MalSkillBench, recall by attack vector (CI / PI / MIXED) and generated vs. wild
```

    # MaliciousSkillBench ships Parquet; turn it into JSON lines once (needs pyarrow, so network):
    docker run --rm -v cordon-bench-public:/p -v "$PWD/bench:/b:ro" python:3.12-slim sh -c \\
      'pip -q install pyarrow && python /b/public_skills.py prepare /p/maliciousskillbench'
    # then scan, no network:
    docker run --rm --network none -v cordon-bench-public:/p:ro -v "$PWD:/s:ro" -v OUT:/out \\
      --entrypoint sh cordon-prepush:<tag> -c 'cp -r /s /tmp/w && PYTHONPATH=/tmp/w/src \\
      python /tmp/w/bench/public_skills.py malskillbench /p/malskillbench --out /out'

Nothing in a sample is run. These are research datasets of malicious skills, read as text.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run import Wilson

GENERATED = re.compile(r"__(?P<vector>CI|PI|MIXED)_(?P<behaviour>B\d+)$")


class PublicSkills:
    @staticmethod
    def scan(target: str) -> tuple[str, bool, bool, list[str]]:
        """(target, blocked by the default gate, flagged at MEDIUM or above, rules at MEDIUM+)."""
        from cordon_scanner import Scanner
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.foundation.config import Config

        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(Path(target))
        blocked = any(PolicyGate._fails(f, config.policy) for f in result.findings)
        noted = sorted(
            {
                f"{f.rule_id}/{f.severity.name}"
                for f in result.findings
                if f.severity.name in ("MEDIUM", "HIGH", "CRITICAL")
                and not f.rule_id.startswith(("OPERATIONAL.", "POLICY.COVERAGE"))
            }
        )
        return target, blocked, blocked or bool(noted), noted

    @staticmethod
    def rate(hits: int, total: int) -> dict[str, Any]:
        return {
            "rate": round(hits / max(total, 1), 4),
            "of": total,
            "ci95": list(Wilson.interval(hits, total)),
        }

    @classmethod
    def summarise(cls, rows: list[dict[str, Any]]) -> dict[str, Any]:
        bad = [r for r in rows if r["malicious"]]
        good = [r for r in rows if not r["malicious"]]
        out: dict[str, Any] = {}
        for level in ("blocked", "flagged"):
            tp = sum(1 for r in bad if r[level])
            fp = sum(1 for r in good if r[level])
            out[level] = {
                "recall": cls.rate(tp, len(bad)),
                "benign_clean": cls.rate(len(good) - fp, len(good)),
                "precision": cls.rate(tp, tp + fp),
                "false_positives": fp,
            }
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in bad:
            groups[r.get("group", "all")].append(r)
        out["recall_by_group"] = {
            group: {
                "blocked": cls.rate(sum(1 for r in mine if r["blocked"]), len(mine)),
                "flagged": cls.rate(sum(1 for r in mine if r["flagged"]), len(mine)),
            }
            for group, mine in sorted(groups.items())
        }
        out["benign_blocking_rules"] = Counter(
            rule for r in good if r["blocked"] for rule in r["rules"]
        ).most_common(15)
        return out

    @classmethod
    def run(cls, items: list[tuple[str, bool, str]], workers: int) -> list[dict[str, Any]]:
        with ProcessPoolExecutor(workers) as pool:
            results = list(pool.map(cls.scan, [path for path, _, _ in items], chunksize=8))
        return [
            {
                "skill": Path(path).name,
                "malicious": malicious,
                "group": group,
                "blocked": blocked,
                "flagged": flagged,
                "rules": rules,
            }
            for (path, malicious, group), (_, blocked, flagged, rules) in zip(
                items, results, strict=True
            )
        ]

    @staticmethod
    def malskillbench(root: Path) -> list[tuple[str, bool, str]]:
        items: list[tuple[str, bool, str]] = []
        for side, malicious in (("malware", True), ("benign", False)):
            for skill in sorted((root / "Dataset" / "Skills" / side).iterdir()):
                if skill.is_dir():
                    generated = GENERATED.search(skill.name)
                    group = (
                        f"generated {generated.group('vector')}"
                        if generated
                        else "wild or tool test"
                    )
                    items.append((str(skill), malicious, group if malicious else "benign"))
        return items

    @staticmethod
    def prepare(root: Path) -> int:
        """MaliciousSkillBench's primary.parquet -> skills.jsonl (benchmark_id, label, text)."""
        import pyarrow.parquet as pq

        table = pq.read_table(root / "primary.parquet").to_pylist()
        with (root.parent / "maliciousskillbench.jsonl").open("w", encoding="utf-8") as sink:
            for row in table:
                text = row.get("skill_text") or row.get("public_skill_text")
                if text:
                    sink.write(
                        json.dumps(
                            {"id": row["benchmark_id"], "label": str(row["label"]), "text": text}
                        )
                        + "\n"
                    )
        return len(table)

    @staticmethod
    def maliciousskillbench(jsonl: Path, work: Path) -> list[tuple[str, bool, str]]:
        items: list[tuple[str, bool, str]] = []
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            folder = work / row["id"]
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "SKILL.md").write_text(row["text"], encoding="utf-8", errors="surrogatepass")
            malicious = row["label"] == "1"
            items.append((str(folder), malicious, "malicious" if malicious else "benign"))
        return items

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument(
            "benchmark", choices=("malskillbench", "maliciousskillbench", "prepare")
        )
        parser.add_argument("source", type=Path)
        parser.add_argument("--out", type=Path, default=Path("/out"))
        parser.add_argument("--workers", type=int, default=4)
        args = parser.parse_args()
        if args.benchmark == "prepare":
            print(f"{cls.prepare(args.source)} records")
            return 0
        work = Path(tempfile.mkdtemp(prefix="skills-"))
        items = (
            cls.malskillbench(args.source)
            if args.benchmark == "malskillbench"
            else cls.maliciousskillbench(args.source, work)
        )
        rows = cls.run(items, args.workers)
        summary = cls.summarise(rows)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / f"{args.benchmark}.json").write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=1), encoding="utf-8"
        )
        print(json.dumps(summary, indent=1))
        return 0


if __name__ == "__main__":
    raise SystemExit(PublicSkills.main())
