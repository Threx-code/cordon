"""The CDI loop for the rule-pack lane: misses in, a signed promotion bundle (or a recorded rejection) out.

    discover   bench/cdi/discover.py: a candidate pack from the misses' shared text
    measure    every configured set, before and after the pack
    gate       bench/cdi/gate.py: lose 0, the benign bar, every new block listed, runtime, lineage
    sign       the decision, with the evaluation lab's key
    hand off   promotion/<pack>.yaml + promotion/decision.json, which the Cloud ingests with
               `manage.py cdi_promote` (shadow); blocking still needs a named person

Measuring an indicator pack is exact without rescanning everything: its rules add a finding only in
a file their patterns match, so a unit with no match scans identically with and without the pack.
The loop searches every unit of every set with the pack's own compiled patterns, scans each matching
unit twice in the same run -- without the pack and with it (the real scanner, `--rules`) -- and
carries every other record over unchanged. The
search covers each unit in full, and the report says how many units it rescanned.

A miss list must come from a dev split. Held-out and sealed sets are measured here, never learned from.
A config may name a `pack` instead (one a person wrote): it skips discovery and is measured the same.

Reach: the pack's patterns are also searched, exhaustively, in a fixed benign listing of every area
(`reach`). A match in an area none of the measured benign sets covers is a block the gate never saw,
and the gate rejects it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from bench.cdi.discover import Discovery, UnitText
from bench.cdi.gate import Gate


class PackMatch:
    """Which units of a set a pack's patterns can touch, under each rule's own path filters."""

    @staticmethod
    def patterns(pack: Path) -> list[tuple[Any, tuple[str, ...], tuple[str, ...]]]:
        from cordon_scanner.rules.loader import RuleLoader

        return [
            (c.match.regex, c.rule.paths_include, c.rule.paths_exclude)
            for c in RuleLoader().load_file(pack).rules
            if c.match.regex is not None
        ]

    @staticmethod
    def units(pack: Path, root: Path, units: list[str], workers: int = 1) -> list[str]:
        rules = PackMatch.patterns(pack)
        if workers <= 1:
            return [unit for unit in units if PackMatch.touches(rules, str(root / unit))]
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(workers) as pool:
            flags = pool.map(
                PackMatch.touches,
                [rules] * len(units),
                [str(root / u) for u in units],
                chunksize=16,
            )
            return [unit for unit, hit in zip(units, flags, strict=True) if hit]

    @staticmethod
    def touches(rules: list[tuple[Any, tuple[str, ...], tuple[str, ...]]], path: str) -> bool:
        from cordon_scanner.engine.walker import PathGlob

        for name, blob in UnitText.files(path):
            for regex, include, exclude in rules:
                # The scanner's own path filter (`RuleSelector.rule_applies_to_path`).
                if include and not any(PathGlob.matches(name, g) for g in include):
                    continue
                if any(PathGlob.matches(name, g) for g in exclude):
                    continue
                if regex.search(blob):
                    return True
        return False

    @staticmethod
    def reach(pack: Path, areas: list[dict[str, str]], workers: int) -> dict[str, Any]:
        """Where the pack's patterns land in benign content of EVERY area, not only the sets the
        candidate is measured on: a pattern written for one ecosystem fires wherever its text
        appears (found end to end: an indicator gated on CI sets matched 4% of npm packages)."""
        out: dict[str, Any] = {}
        for area in areas:
            listing = Path(area["listing"])
            units = listing.read_text(encoding="utf-8").split()
            hits = PackMatch.units(pack, Path(area["root"]), units, workers)
            out[area["area"]] = {
                "units": len(units),
                "matched": len(hits),
                "listing_sha256": Gate.file_digest(str(listing)),
                "examples": hits[:20],
            }
        return out


class CdiLoop:
    @staticmethod
    def rescan(
        tools: Path, root: Path, units: list[str], pack: Path | None, out: Path, workers: int
    ) -> None:
        if not units:
            out.write_text("", encoding="utf-8")
            return
        listing = out.with_suffix(".units.txt")
        listing.write_text("".join(f"{u}\n" for u in units), encoding="utf-8")
        out.unlink(missing_ok=True)
        subprocess.run(
            [sys.executable, str(tools / "rescan_sample.py"), str(listing), str(out), str(workers)],
            cwd=root,
            env={**os.environ, "EXTRA_RULES": str(pack)} if pack else dict(os.environ),
            check=True,
            capture_output=True,
        )

    @staticmethod
    def paired(
        tools: Path,
        root: Path,
        units: list[str],
        pack: Path,
        before: Path,
        after: Path,
        workers: int,
    ) -> None:
        """Both sides at once, half the workers each: whatever else loads the machine loads both
        alike, so the runtime gate compares the pack and not the hour (run one after the other, a
        p99 ratio of 3.59 on 16 units came from a job that started between them)."""
        from concurrent.futures import ThreadPoolExecutor

        half = max(1, workers // 2)
        with ThreadPoolExecutor(2) as pool:
            sides = [
                pool.submit(CdiLoop.rescan, tools, root, units, None, before, half),
                pool.submit(CdiLoop.rescan, tools, root, units, pack, after, half),
            ]
            for side in sides:
                side.result()

    @staticmethod
    def merged(off: Path, rescanned: Path, out: Path, prefix: str = "") -> None:
        fresh = {}
        for line in rescanned.read_text(encoding="utf-8").splitlines():
            if line:
                row = json.loads(line)
                row["file"] = row["file"][len(prefix) :] if prefix else row["file"]
                fresh[row["file"]] = json.dumps(row)
        rows = []
        for line in off.read_text(encoding="utf-8").splitlines():
            if line:
                rows.append(fresh.get(json.loads(line)["file"], line))
        out.write_text("".join(f"{r}\n" for r in rows), encoding="utf-8")

    @staticmethod
    def discover(config: dict[str, Any], root: Path) -> tuple[str | None, dict[str, Any]]:
        listed = [str(root / u) for u in Path(config["misses"]).read_text(encoding="utf-8").split()]
        benign = [
            str(root / u)
            for u in Path(config["discovery_benign"]).read_text(encoding="utf-8").split()
        ]
        return Discovery.run(
            listed,
            benign,
            min_support=config.get("min_support", 3),
            max_rules=config.get("max_rules", 5),
            pack_id=config["pack_id"],
            reference=config["reference"],
            paths=config.get("paths", []),
        )

    @staticmethod
    def run(config: dict[str, Any], work: Path, sign_key: Path | None) -> dict[str, Any]:
        work.mkdir(parents=True, exist_ok=True)
        root = Path(config["root"])
        if config.get("pack"):
            # A pack a person wrote (a rapid response to an incident) is measured and gated exactly
            # as a discovered one is; only where it came from differs, and the report says so.
            pack_text = Path(config["pack"]).read_text(encoding="utf-8")
            report = {"kind": "SuppliedPack", "sha256": Gate.file_digest(config["pack"])}
        else:
            pack_text, report = CdiLoop.discover(config, root)
        (work / "discovery_report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        if pack_text is None:
            return {"outcome": "no_candidate", "discovery": report}
        pack = work / f"rulepack-{config['pack_id'].replace('.', '-')}.yaml"
        pack.write_text(pack_text, encoding="utf-8")

        sets, rescanned = [], {}
        for entry in config["sets"]:
            units = [
                json.loads(line)["file"]
                for line in Path(entry["off"]).read_text(encoding="utf-8").splitlines()
                if line
            ]
            # A set's records name units relative to its own volume; the volume is mounted at
            # <root>/<prefix>, and the scan tool resolves units against <root>.
            prefix = entry.get("prefix", "")
            touched = PackMatch.units(pack, root / prefix, units, config.get("workers", 4))
            # Each touched unit is scanned twice in this run, without and with the pack, so the two
            # sides differ by the pack alone -- not by the machine's load when the old record was made.
            listed_units = [prefix + u for u in touched]
            tools, workers = Path(config["tools"]), config.get("workers", 4)
            before = work / f"{entry['name']}.before.jsonl"
            after = work / f"{entry['name']}.after.jsonl"
            CdiLoop.paired(tools, root, listed_units, pack, before, after, workers)
            off = work / f"{entry['name']}.off.jsonl"
            on = work / f"{entry['name']}.on.jsonl"
            CdiLoop.merged(Path(entry["off"]), before, off, prefix)
            CdiLoop.merged(Path(entry["off"]), after, on, prefix)
            rescanned[entry["name"]] = {"units": len(units), "matched_and_rescanned": len(touched)}
            sets.append(
                {
                    **{k: v for k, v in entry.items() if k != "prefix"},
                    "off": str(off),
                    "on": str(on),
                }
            )

        reach = PackMatch.reach(pack, config.get("reach", []), config.get("workers", 4))
        run, decision = Gate.evaluate(
            {
                "candidate_id": f"rulepack:{config['pack_id']}@1.0.0",
                "sets": sets,
                "reach": reach,
                "requires_reach": True,
            }
        )
        run["rescanned"] = rescanned
        if sign_key is not None:
            decision = Gate.sign(decision, sign_key.read_text(encoding="utf-8"))
        (work / "evaluation_run.json").write_text(
            json.dumps(run, indent=1, sort_keys=True), encoding="utf-8"
        )
        (work / "promotion_decision.json").write_text(
            json.dumps(decision, indent=1, sort_keys=True), encoding="utf-8"
        )
        if decision["outcome"] != "reject":
            bundle = work / "promotion"
            bundle.mkdir(exist_ok=True)
            (bundle / pack.name).write_text(pack_text, encoding="utf-8")
            (bundle / "decision.json").write_text(
                json.dumps(decision, sort_keys=True), encoding="utf-8"
            )
        return {"outcome": decision["outcome"], "gates": decision["gates"], "rescanned": rescanned}

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--config", required=True)
        parser.add_argument("--work", required=True)
        parser.add_argument("--sign-key")
        args = parser.parse_args(argv)
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        result = CdiLoop.run(
            config, Path(args.work), Path(args.sign_key) if args.sign_key else None
        )
        print(json.dumps(result, indent=1))
        return 0 if result["outcome"] not in ("reject", "no_candidate") else 1


if __name__ == "__main__":
    sys.exit(CdiLoop.main())
