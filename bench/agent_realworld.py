#!/usr/bin/env python3
"""False alarms on real agent configuration: the held-out half of the real-world corpus.

Scans each repository's committed agent files (collected by `bench/fetch_agent_configs.py`) and
reports how many repositories Cordon warns on (MEDIUM or above) and blocks (HIGH or above) with an
agent or MCP rule, and which rules. Only the `evaluate` half is scanned: the `calibrate` half graded
the Agent Threat Rules for instruction files, so measuring on it would grade the tool by its own
answer key.

    python bench/agent_realworld.py --corpus corpus-dir [--json out.json]

These repositories are popular public projects, not a labelled benign set: a finding here is a
false alarm only when reading it shows the configuration is ordinary. Committed auto-approve
settings or an MCP server launched at `@latest` are real findings in a real repository.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fetch_agent_configs import AgentConfigCorpus

AGENT_RULES = ("SUSPECT.AGENT", "MALWARE.AGENT", "POLICY.AGENT", "SUSPECT.MCP", "SECRET.MCP")


class RealWorldAgents:
    """False alarms on the held-out half of the real-world agent-configuration corpus."""

    @staticmethod
    def scan(repository: str) -> tuple[str, list[list[str]]]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        report = Scanner(Config.default().with_overrides(use_cache=False)).scan(Path(repository))
        return repository, [
            [
                f.rule_id,
                f.severity.name,
                f.location.path,
                (f.evidence.snippet or "")[:200] if f.evidence else "",
                f.message,
            ]
            for f in report.findings
            if f.rule_id.startswith(AGENT_RULES)
            and f.severity.name in ("MEDIUM", "HIGH", "CRITICAL")
        ]

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--corpus", type=Path, required=True)
        parser.add_argument("--workers", type=int, default=6)
        parser.add_argument("--json", type=Path)
        args = parser.parse_args()
        repositories = sorted(
            str(p)
            for p in (args.corpus / "files").iterdir()
            if p.is_dir() and AgentConfigCorpus.half_of(p.name.replace("__", "/", 1)) == "evaluate"
        )
        with ProcessPoolExecutor(args.workers) as pool:
            results = dict(pool.map(RealWorldAgents.scan, repositories, chunksize=8))
        warned = [r for r, found in results.items() if found]
        blocked = [
            r for r, found in results.items() if any(f[1] in ("HIGH", "CRITICAL") for f in found)
        ]
        total = len(results)
        print(f"held-out repositories: {total}")
        print(f"  warned (MEDIUM+): {len(warned)} ({len(warned) / total:.1%})")
        print(f"  blocked (HIGH+):  {len(blocked)} ({len(blocked) / total:.1%})")
        counts = Counter(
            f"{f[0]}/{f[1]}"
            for found in results.values()
            for f in {(x[0], x[1]): x for x in found}.values()
        )
        for rule, n in counts.most_common(30):
            print(f"  {n:5} {rule}")
        if args.json:
            args.json.write_text(json.dumps(results, indent=1), encoding="utf-8")
        return 0


if __name__ == "__main__":
    sys.exit(RealWorldAgents.main())
