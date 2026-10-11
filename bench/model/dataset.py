#!/usr/bin/env python3
"""The labelled package dataset for Cordon's code model: a manifest, no contents.

Malicious (label 1): DataDog's npm and PyPI samples -- `malicious_intent` (written to harm) and
`compromised_lib` (a real library with malware injected), each dated by its file name -- and
malregistry's PyPI releases (an ASE 2023 study; undated, so all of it is older than DataDog's).
Legitimate (label 0): the top npm and PyPI packages, and a random draw of ordinary ones (the long
tail). A legitimate release that Cordon's bundled known-malicious records name is dropped.

Two splits, both fixed:

    hash   sha256(source/ecosystem/name) even -> train, odd -> held; a package and all its
           versions fall on one side, so no near-copy of a held sample is trained on
    time   train: malregistry, and DataDog published before --cutoff; held: DataDog from the
           cutoff on. Legitimate packages follow the hash split. The time split is the
           "attacks never seen" measurement.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-random:/random:ro \\
      -v "$PWD/bench/model:/model" -v cordon-model-work:/work cordon-model:dev python dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

DATED = re.compile(r"^(\d{4}-\d{2}-\d{2})-")


class Dataset:
    @staticmethod
    def hash_split(key: str) -> str:
        return "train" if hashlib.sha256(key.encode()).digest()[0] % 2 == 0 else "held"

    @staticmethod
    def malicious(data: Path, cutoff: str) -> list[dict[str, str | int]]:
        rows: list[dict[str, str | int]] = []
        for ecosystem in ("npm", "pypi"):
            base = data / "datadog" / "samples" / ecosystem
            for kind in ("malicious_intent", "compromised_lib"):
                for archive in sorted((base / kind).rglob("*.zip")):
                    name = archive.parent.parent.name
                    date = (DATED.match(archive.name) or [None, ""])[1]
                    key = f"datadog/{ecosystem}/{name}"
                    rows.append(
                        {
                            "id": f"{key}/{archive.parent.name}/{archive.name}",
                            "source": "datadog",
                            "ecosystem": ecosystem,
                            "name": name,
                            "label": 1,
                            "kind": kind,
                            "date": date,
                            "path": archive.relative_to(data).as_posix(),
                            "volume": "data",
                            "hash_split": Dataset.hash_split(key),
                            "time_split": "held" if date >= cutoff else "train",
                        }
                    )
        for archive in sorted((data / "malregistry").rglob("*")):
            if not archive.is_file() or not archive.name.endswith(
                (".tar.gz", ".zip", ".whl", ".tgz")
            ):
                continue
            name = archive.parent.parent.name
            key = f"malregistry/pypi/{name}"
            rows.append(
                {
                    "id": f"{key}/{archive.parent.name}/{archive.name}",
                    "source": "malregistry",
                    "ecosystem": "pypi",
                    "name": name,
                    "label": 1,
                    "kind": "malicious_intent",
                    "date": "",
                    "path": archive.relative_to(data).as_posix(),
                    "volume": "data",
                    "hash_split": Dataset.hash_split(key),
                    "time_split": "train",
                }
            )
        return rows

    @staticmethod
    def legitimate(data: Path, random_root: Path) -> list[dict[str, str | int]]:
        from cordon_scanner.intel.advisories import AdvisoryDatabase

        database = AdvisoryDatabase.bundled()
        rows: list[dict[str, str | int]] = []
        top = json.loads((data / "benign" / "manifest.json").read_text(encoding="utf-8"))
        drawn_path = random_root / "manifest.json"
        drawn = json.loads(drawn_path.read_text(encoding="utf-8")) if drawn_path.exists() else []
        for source, entries, volume, root in (
            ("top", top, "data", data),
            ("random", drawn, "random", random_root),
        ):
            for entry in entries:
                ecosystem, name = str(entry["ecosystem"]), str(entry["name"])
                version = str(entry.get("version") or "")
                path = Path(str(entry.get("file") or entry.get("path") or ""))
                if not (root / path).is_file():
                    continue
                if Dataset.known_malicious(database, ecosystem, name, version):
                    continue
                key = f"{source}/{ecosystem}/{name}"
                split = Dataset.hash_split(key)
                rows.append(
                    {
                        "id": f"{key}/{version}",
                        "source": source,
                        "ecosystem": ecosystem,
                        "name": name,
                        "label": 0,
                        "kind": "legitimate",
                        "date": "",
                        "path": (root / path)
                        .relative_to(data if volume == "data" else random_root)
                        .as_posix(),
                        "volume": volume,
                        "hash_split": split,
                        "time_split": split,
                    }
                )
        return rows

    @staticmethod
    def known_malicious(database: object, ecosystem: str, name: str, version: str) -> bool:
        """Whether Cordon's bundled records name this release as malicious."""
        found = database.matching(ecosystem, name, version or None)  # type: ignore[attr-defined]
        return any(getattr(a, "malicious", False) for a in found)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--random", type=Path, default=Path("/random"))
        parser.add_argument("--out", type=Path, default=Path("/work/manifest.jsonl"))
        parser.add_argument("--cutoff", default="2025-07-01")
        args = parser.parse_args()
        rows = Dataset.malicious(args.data, args.cutoff) + Dataset.legitimate(
            args.data, args.random
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        summary: dict[str, int] = {}
        for r in rows:
            k = f"{r['label']} {r['source']} {r['ecosystem']} {r['kind']} hash={r['hash_split']} time={r['time_split']}"
            summary[k] = summary.get(k, 0) + 1
        for k in sorted(summary):
            print(f"{summary[k]:7d}  {k}")
        return 0


if __name__ == "__main__":
    sys.exit(Dataset.main())
