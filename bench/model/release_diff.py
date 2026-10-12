#!/usr/bin/env python3
"""Compromised releases against the release before them: what `--compare-with` catches.

A compromised library is the real library and a change: a new install hook, a new obfuscated file,
a new destination. Cordon compares a release with the one before it (`scan --compare-with`, or
`--online` for a published npm or PyPI artefact). This measures that on DataDog's compromised npm
releases: for each, the newest earlier version on the registry is fetched (a legitimate release,
checked against the registry's digest), and the compromised one is scanned against it, offline.

    docker run --rm -v cordon-bench-data:/data:ro -v "$PWD/bench:/bench:ro" -v cordon-model-work:/work \\
      cordon-bench:dev python /bench/model/release_diff.py --split time
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/bench")
from run import Harness

_UA = {"User-Agent": "cordon-release-diff-study"}


class ReleaseDiff:
    @staticmethod
    def get(url: str, limit: int = 64 << 20) -> bytes:
        for attempt in range(4):
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(url, headers=_UA), timeout=60
                ) as r:
                    return r.read(limit + 1)
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    raise
                time.sleep(2 + 3 * attempt)
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(2 + 3 * attempt)
        raise OSError(url)

    @staticmethod
    def previous(name: str, version: str) -> tuple[str, bytes] | None:
        """The newest version published before `version`, its tarball verified by SHA-1/512."""
        try:
            doc = json.loads(
                ReleaseDiff.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
            )
        except (OSError, ValueError, urllib.error.HTTPError):
            return None
        times = doc.get("time") or {}
        here = times.get(version)
        earlier = [
            (t, v)
            for v, t in times.items()
            if v not in ("created", "modified")
            and v in (doc.get("versions") or {})
            and (here is None or t < here)
            and v != version
        ]
        if not earlier:
            return None
        _, chosen = max(earlier)
        dist = doc["versions"][chosen].get("dist") or {}
        try:
            body = ReleaseDiff.get(dist["tarball"])
        except (OSError, KeyError, urllib.error.HTTPError):
            return None
        if dist.get("shasum") and hashlib.sha1(body).hexdigest() != dist["shasum"]:  # noqa: S324 - npm's own digest
            return None
        return chosen, body

    @staticmethod
    def one(row: dict[str, str]) -> dict[str, object]:
        version = row["id"].split("/")[3]
        out: dict[str, object] = {"id": row["id"], "name": row["name"], "version": version}
        found = ReleaseDiff.previous(row["name"], version)
        if found is None:
            out["result"] = "no earlier release on the registry"
            return out
        previous_version, tarball = found
        out["previous"] = previous_version
        with tempfile.TemporaryDirectory() as work:
            sample = Harness._unzip_datadog(Path("/data") / row["path"], Path(work) / "sample")
            earlier = Path(work) / "previous.tgz"
            earlier.write_bytes(tarball)
            if sample is None:
                out["result"] = "sample unreadable"
                return out
            run = subprocess.run(
                [
                    "cordon-scanner",
                    "scan",
                    str(sample),
                    "--offline",
                    "--format",
                    "json",
                    "--quiet",
                    "--no-color",
                    "--compare-with",
                    str(earlier),
                ],
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        try:
            report = json.loads(run.stdout[run.stdout.index("{") :])
        except ValueError:
            out["result"] = f"no report (exit {run.returncode})"
            return out
        added = [
            f["rule_id"]
            for f in report.get("findings", [])
            if f["rule_id"].startswith(("RELEASE.", "SUSPECT.RELEASE"))
        ]
        out.update(result="scanned", blocked=run.returncode == 1, release_rules=sorted(set(added)))
        return out

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--split", default="time")
        args = parser.parse_args()
        rows = [
            json.loads(x)
            for x in Path("/work/manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        chosen = [
            r
            for r in rows
            if r["source"] == "datadog"
            and r["ecosystem"] == "npm"
            and r["kind"] == "compromised_lib"
            and r[f"{args.split}_split"] == "held"
        ]
        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(ReleaseDiff.one, chosen))
        Path(f"/work/release_diff_{args.split}.json").write_text(
            json.dumps(results), encoding="utf-8"
        )
        scanned = [r for r in results if r["result"] == "scanned"]
        print(
            f"{len(chosen)} compromised npm releases; {len(scanned)} compared with an earlier release"
        )
        print(
            f"  blocked with --compare-with: {sum(1 for r in scanned if r['blocked'])} ({100 * sum(1 for r in scanned if r['blocked']) / max(len(scanned), 1):.2f}%)"
        )
        print(f"  a release-change rule fired: {sum(1 for r in scanned if r['release_rules'])}")
        for reason in sorted({str(r["result"]) for r in results if r["result"] != "scanned"}):
            print(f"  not compared: {reason}: {sum(1 for r in results if r['result'] == reason)}")
        return 0


if __name__ == "__main__":
    sys.exit(ReleaseDiff.main())
