#!/usr/bin/env python3
"""Cordon on the npm detector benchmark of Guo et al. (arXiv 2603.27549), as the paper reports it.

```
  NPMStudy.zip (figshare 10.6084/m9.figshare.31869370, CC-BY-4.0)
     ├── Dataset/zip_malware/<name>/<version>/*.tgz          shipped: extract
     └── Dataset/zip_benign/zip_benign_list.txt              names only: fetch from npm, sha1 checked
                │
                ▼   offline, each release scanned as a published package, default gate
  recall (blocked / flagged), benign not blocked / no warning, precision -- 95% intervals --
  on the whole malicious set AND on the part not in DataDog's or malregistry's sets, which Cordon's
  rules were developed against (the paper drew from overlapping public sources)
```

    docker run --rm -v cordon-bench-public:/p -v "$PWD/bench:/b:ro" python:3.12-slim \\
      python -I /b/public_npm.py extract /p/npmstudy.zip --to /p/npmstudy
    docker run --rm -v cordon-bench-public:/p -v "$PWD/bench:/b:ro" python:3.12-slim \\
      python -I /b/public_npm.py fetch-benign /p/npmstudy           # network
    docker run --rm --network none -v cordon-bench-public:/p:ro -v cordon-bench-data:/data:ro \\
      -v "$PWD:/s:ro" -v OUT:/out --entrypoint sh cordon-prepush:<tag> -c 'cp -r /s /tmp/w && \\
      PYTHONPATH=/tmp/w/src python /tmp/w/bench/public_npm.py scan /p/npmstudy --out /out'

Nothing in a sample is run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from public_skills import PublicSkills
from run import Harness

PREFIX = "NPMStudy/Dataset/"
AGENT = {"User-Agent": "cordon-benchmark (research; github.com/Threx-code/cordon)"}


class PublicNpm:
    @staticmethod
    def package_name(directory: str) -> str:
        """`@scope##name` and `@scope@name` are how the study spells `@scope/name` in paths."""
        name = directory.replace("##", "/")
        if name.startswith("@") and "/" not in name and "@" in name[1:]:
            scope, _, rest = name[1:].partition("@")
            name = f"@{scope}/{rest}"
        return name

    @staticmethod
    def extract(archive: Path, to: Path) -> int:
        count = 0
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                name = info.filename
                if name.startswith(PREFIX + "zip_malware/") and name.endswith(".tgz"):
                    target = to / "malware" / name.removeprefix(PREFIX + "zip_malware/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(bundle.read(info))
                    count += 1
            listing = bundle.read(PREFIX + "zip_benign/zip_benign_list.txt")
        (to / "benign-list.txt").write_bytes(listing)
        return count

    @classmethod
    def fetch_one(cls, root: Path, line: str) -> str:
        parts = line.strip().split("/")
        if len(parts) < 3:
            return "unparsed"
        name, version = cls.package_name(parts[0]), parts[1]
        target = root / "benign" / line.strip()
        if target.exists():
            return "kept"
        try:
            meta_url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"
            with urllib.request.urlopen(
                urllib.request.Request(meta_url, headers=AGENT), timeout=60
            ) as reply:
                dist = json.load(reply).get("dist") or {}
            with urllib.request.urlopen(
                urllib.request.Request(dist["tarball"], headers=AGENT), timeout=120
            ) as reply:
                body = reply.read(64 << 20)
        except (OSError, ValueError, KeyError) as exc:
            return f"error: {type(exc).__name__}"
        if dist.get("shasum") and hashlib.sha1(body).hexdigest() != dist["shasum"]:  # noqa: S324 - npm's own digest
            return "digest-mismatch"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        return "fetched"

    @classmethod
    def fetch_benign(cls, root: Path, workers: int) -> dict[str, int]:
        lines = [
            x
            for x in (root / "benign-list.txt").read_text(encoding="utf-8").splitlines()
            if x.strip()
        ]
        with ThreadPoolExecutor(workers) as pool:
            outcomes = list(pool.map(lambda line: cls.fetch_one(root, line), lines))
        summary: dict[str, int] = {}
        for outcome in outcomes:
            key = outcome.split(":")[0]
            summary[key] = summary.get(key, 0) + 1
        return summary

    @staticmethod
    def tuned_on(data: Path) -> set[tuple[str, str]]:
        """(name, version) of every DataDog and malregistry sample, normalised as run.py keys them."""
        keys: set[tuple[str, str]] = set()
        for _, archive, _ in Harness.malware_samples(data):
            relative = (
                archive.relative_to(data / "datadog" / "samples")
                if "datadog" in archive.parts
                else None
            )
            key = (
                Harness._datadog_key(relative)
                if relative is not None
                else Harness._malregistry_key(archive)
            )
            if key is not None:
                keys.add(key)
        return keys

    @classmethod
    def scan(cls, root: Path, data: Path, out: Path, workers: int) -> dict[str, object]:
        tuned = cls.tuned_on(data) if data.exists() else set()
        items: list[tuple[str, bool, str]] = []
        for side, malicious in (("malware", True), ("benign", False)):
            for archive in sorted((root / side).rglob("*.tgz")):
                parts = archive.relative_to(root / side).parts
                key = (
                    Harness._release_key(cls.package_name(parts[0]), parts[1])
                    if len(parts) >= 3
                    else None
                )
                group = (
                    (
                        "seen in DataDog/malregistry"
                        if key in tuned
                        else "not in DataDog/malregistry"
                    )
                    if malicious
                    else "benign"
                )
                items.append((str(archive), malicious, group))
        rows = PublicSkills.run(items, workers)
        summary = PublicSkills.summarise(rows)
        out.mkdir(parents=True, exist_ok=True)
        (out / "npmstudy.json").write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=1), encoding="utf-8"
        )
        return summary

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("action", choices=("extract", "fetch-benign", "scan"))
        parser.add_argument("source", type=Path)
        parser.add_argument("--to", type=Path, default=Path("/p/npmstudy"))
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--out", type=Path, default=Path("/out"))
        parser.add_argument("--workers", type=int, default=8)
        args = parser.parse_args()
        if args.action == "extract":
            print(f"{cls.extract(args.source, args.to)} malicious archives extracted")
        elif args.action == "fetch-benign":
            print(json.dumps(cls.fetch_benign(args.source, args.workers)))
        else:
            print(json.dumps(cls.scan(args.source, args.data, args.out, args.workers), indent=1))
        return 0


if __name__ == "__main__":
    raise SystemExit(PublicNpm.main())
