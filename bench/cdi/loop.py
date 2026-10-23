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
    """Which units of a set a pack's patterns can touch."""

    @staticmethod
    def patterns(pack: Path) -> list[Any]:
        from cordon_scanner.rules.loader import RuleLoader

        return [
            c.match.regex for c in RuleLoader().load_file(pack).rules if c.match.regex is not None
        ]

    @staticmethod
    def units(pack: Path, root: Path, units: list[str]) -> list[str]:
        regexes = PackMatch.patterns(pack)
        return [
            unit
            for unit in units
            if any(r.search(blob) for _, blob in UnitText.files(str(root / unit)) for r in regexes)
        ]


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
    def run(config: dict[str, Any], work: Path, sign_key: Path | None) -> dict[str, Any]:
        work.mkdir(parents=True, exist_ok=True)
        root = Path(config["root"])
        listed = [str(root / u) for u in Path(config["misses"]).read_text(encoding="utf-8").split()]
        benign = [
            str(root / u)
            for u in Path(config["discovery_benign"]).read_text(encoding="utf-8").split()
        ]
        pack_text, report = Discovery.run(
            listed,
            benign,
            min_support=config.get("min_support", 3),
            max_rules=config.get("max_rules", 5),
            pack_id=config["pack_id"],
            reference=config["reference"],
            paths=config.get("paths", []),
        )
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
            touched = PackMatch.units(pack, root / prefix, units)
            # Each touched unit is scanned twice in this run, without and with the pack, so the two
            # sides differ by the pack alone -- not by the machine's load when the old record was made.
            listed_units = [prefix + u for u in touched]
            tools, workers = Path(config["tools"]), config.get("workers", 4)
            before = work / f"{entry['name']}.before.jsonl"
            after = work / f"{entry['name']}.after.jsonl"
            CdiLoop.rescan(tools, root, listed_units, None, before, workers)
            CdiLoop.rescan(tools, root, listed_units, pack, after, workers)
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

        run, decision = Gate.evaluate(
            {"candidate_id": f"rulepack:{config['pack_id']}@1.0.0", "sets": sets}
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
