#!/usr/bin/env python3
"""Identity coverage: is every known-malicious release flagged by name and version alone?

Reads every OSV record in OpenSSF's malicious-packages repository (`osv/malicious/<ecosystem>/`,
about 239,000 records) and asks Cordon's advisory database, exactly as a scan does
(`AdvisoryDatabase.matching`), whether each release a record names is reported.

A record counts as COVERED when every version it lists is matched (or, for a record whose range
covers every version, when any version is). Nothing is downloaded but metadata; no package code is
read. Docker only:

    docker run --rm -v cordon-bench-osv:/osv -v "$PWD/bench/results:/results" cordon-bench:dev \\
        ... python /bench/identity.py --osv /osv/malicious-packages --out /results/identity.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

#: OSV ecosystem name -> Cordon's.
ECOSYSTEMS = {
    "npm": "npm",
    "PyPI": "pypi",
    "RubyGems": "rubygems",
    "NuGet": "nuget",
    "crates.io": "cargo",
    "Go": "gomod",
    "Maven": "maven",
    "Packagist": "composer",
    "Pub": "pub",
    "Hex": "hex",
    "VSCode": "vscode",
    "VSCode:https://open-vsx.org": "vscode",
    "GitHub Actions": "actions",
}


class Identity:
    """The identity benchmark."""

    @staticmethod
    def records(root: Path):
        for path in sorted((root / "osv" / "malicious").rglob("*.json")):
            try:
                yield path, json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue

    @staticmethod
    def wanted(affected: dict) -> tuple[list[str], bool]:
        """The versions a record names, and whether its range admits every version."""
        versions = [str(v) for v in affected.get("versions") or []]
        every = False
        for rng in affected.get("ranges") or []:
            events = rng.get("events") or []
            introduced = [e.get("introduced") for e in events if "introduced" in e]
            closed = any("fixed" in e or "last_affected" in e for e in events)
            if "0" in introduced and not closed:
                every = True
        return versions, every

    @staticmethod
    def run(osv_root: Path) -> dict:
        from cordon_scanner.intel.advisories import AdvisoryDatabase

        db = AdvisoryDatabase.bundled()
        totals: Counter[str] = Counter()
        covered: Counter[str] = Counter()
        reasons: dict[str, Counter[str]] = defaultdict(Counter)
        missed_examples: dict[str, list[str]] = defaultdict(list)
        for path, record in Identity.records(osv_root):
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                if not package:
                    # A repository record: no package, a GIT range naming the repository.
                    from cordon_scanner.intel.osv_import import OsvImport

                    repos = [
                        OsvImport.repository_key(str(r.get("repo") or ""))
                        for r in affected.get("ranges") or []
                        if r.get("type") == "GIT"
                    ]
                    totals["git"] += 1
                    if repos and all(r and db.for_package("git", r) for r in repos):
                        covered["git"] += 1
                    else:
                        reasons["git"]["repository not in the bundled database"] += 1
                        missed_examples["git"].append(f"{path.name}: {repos}")
                    continue
                osv_eco = str(package.get("ecosystem", ""))
                eco = ECOSYSTEMS.get(osv_eco)
                name = str(package.get("name", ""))
                key = eco or f"unsupported:{osv_eco}"
                totals[key] += 1
                if eco is None:
                    reasons[key]["ecosystem has no advisory data in Cordon"] += 1
                    continue
                versions, every = Identity.wanted(affected)
                if every:
                    hit = bool(db.matching(eco, name, versions[0] if versions else "0.0.0"))
                elif versions:
                    hit = all(db.matching(eco, name, v) for v in versions)
                else:
                    hit = bool(db.for_package(eco, name))
                if hit:
                    covered[key] += 1
                    continue
                if not db.for_package(eco, name):
                    reasons[key]["package not in the bundled database"] += 1
                else:
                    reasons[key]["package known, a listed version not matched"] += 1
                if len(missed_examples[key]) < 15:
                    missed_examples[key].append(f"{path.name}: {name}")
        rows = {
            eco: {
                "records": totals[eco],
                "covered": covered[eco],
                "rate": round(100 * covered[eco] / totals[eco], 3) if totals[eco] else 0.0,
                "misses_by_reason": dict(reasons[eco]),
                "missed_examples": missed_examples[eco],
            }
            for eco in sorted(totals)
        }
        total = sum(totals.values())
        hit = sum(covered.values())
        return {
            "suite": "identity",
            "source": "github.com/ossf/malicious-packages osv/malicious",
            "records": total,
            "covered": hit,
            "rate": round(100 * hit / total, 3) if total else 0.0,
            "by_ecosystem": rows,
        }

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--osv", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        args = parser.parse_args()
        result = Identity.run(args.osv)
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"identity: {result['covered']}/{result['records']} = {result['rate']}%")
        for eco, row in result["by_ecosystem"].items():
            print(
                f"  {eco:24s} {row['covered']:>7}/{row['records']:<7} {row['rate']:>7}%  {row['misses_by_reason']}"
            )
        return 0


if __name__ == "__main__":
    raise SystemExit(Identity.main())
