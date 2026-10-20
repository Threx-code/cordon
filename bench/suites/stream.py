#!/usr/bin/env python3
"""False positives at scale: the most-downloaded packages, fetched, scanned and deleted one by one.

Storing 100,000 published archives would cost several hundred gigabytes, so this keeps none:

  list      the top N packages per ecosystem by downloads (ecosyste.ms), saved once with its
            SHA-256 so a later run measures the same population
  scan      for each: fetch the newest release's artefact, check it against the digest the
            registry publishes (PyPI sha256, npm sha512 integrity), scan it with `--offline`,
            append one JSON line, delete the file

Resumable: a package already in the results file is skipped. `--guarddog N` also runs GuardDog
on a fixed-seed random N of them, so the comparison is drawn from the same population.

Network for fetching only; the scanner runs with `--offline`. Docker only, like every benchmark
here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

RANKED = (
    "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages"
    "?sort=downloads&order=desc&per_page=100&page={page}"
)
REGISTRIES = {"pypi": "pypi.org", "npm": "npmjs.org"}
USER_AGENT = "cordon-benchmark (+https://github.com/Threx-code/cordon)"
SEED = 20261001
"""Fixed so the GuardDog subset is the same sample on every run."""


class BenignStream:
    """Streaming tens of thousands of popular packages through Cordon and GuardDog."""

    @staticmethod
    def get(url: str, *, attempts: int = 4) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        for attempt in range(attempts):
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    body: bytes = response.read()
                    return body
            except Exception:
                if attempt == attempts - 1:
                    raise
                time.sleep(2**attempt)
        raise RuntimeError("unreachable")

    @staticmethod
    def ranked(ecosystem: str, count: int, out: Path) -> list[str]:
        """The top `count` names, cached in `out` so every run measures the same list."""
        if out.exists():
            names: list[str] = json.loads(out.read_text(encoding="utf-8"))["names"]
            if len(names) >= count:
                return names[:count]
        names = []
        page = 1
        while len(names) < count:
            rows = json.loads(
                BenignStream.get(RANKED.format(registry=REGISTRIES[ecosystem], page=page))
            )
            if not rows:
                break
            names += [row["name"] for row in rows if isinstance(row, dict) and row.get("name")]
            page += 1
        names = list(dict.fromkeys(names))[:count]
        body = json.dumps({"ecosystem": ecosystem, "names": names})
        out.write_text(
            json.dumps(
                {
                    "ecosystem": ecosystem,
                    "fetched": time.strftime("%Y-%m-%d"),
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "names": names,
                }
            ),
            encoding="utf-8",
        )
        return names

    @staticmethod
    def artefact(ecosystem: str, name: str) -> tuple[str, str, bytes]:
        """`(version, filename, bytes)` of the newest release, verified against the registry digest."""
        if ecosystem == "pypi":
            document = json.loads(
                BenignStream.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            )
            files = [f for f in document.get("urls", []) if f.get("packagetype") == "sdist"]
            files = files or document.get("urls", [])[:1]
            if not files:
                raise LookupError("no files")
            chosen = files[0]
            blob = BenignStream.get(chosen["url"])
            if hashlib.sha256(blob).hexdigest() != chosen["digests"]["sha256"]:
                raise ValueError("digest mismatch")
            return document["info"]["version"], chosen["filename"], blob
        document = json.loads(
            BenignStream.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest")
        )
        blob = BenignStream.get(document["dist"]["tarball"])
        integrity = document["dist"].get("integrity", "")
        if integrity.startswith("sha512-"):
            if base64.b64encode(hashlib.sha512(blob).digest()).decode() != integrity[7:]:
                raise ValueError("integrity mismatch")
        elif hashlib.sha1(blob).hexdigest() != document["dist"].get("shasum"):  # noqa: S324
            raise ValueError("shasum mismatch")
        filename = f"{name.replace('/', '__')}-{document['version']}.tgz"
        return document["version"], filename, blob

    @staticmethod
    def cordon(path: Path) -> dict[str, Any]:
        started = time.monotonic()
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(path),
                "--offline",
                "--no-color",
                "--quiet",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
        seconds = round(time.monotonic() - started, 2)
        blocking: list[str] = []
        try:
            report = json.loads(process.stdout)
            blocking = sorted(
                {
                    f"{f['rule_id']}/{f['severity']}"
                    for f in report.get("findings", [])
                    if f.get("severity") in ("high", "critical")
                }
            )
        except (json.JSONDecodeError, AttributeError):
            pass
        return {
            "blocked": process.returncode == 1,
            "error": process.returncode not in (0, 1),
            "blocking": blocking,
            "seconds": seconds,
        }

    @staticmethod
    def guarddog(path: Path, ecosystem: str) -> dict[str, Any]:
        """The same verdict `run.py` takes from GuardDog: its risk label, else its issue count."""
        process = subprocess.run(
            ["guarddog", ecosystem, "scan", str(path), "--output-format", "json"],
            capture_output=True,
            text=True,
            timeout=900,
        )
        try:
            document = json.loads(process.stdout[process.stdout.index("{") :])
        except (ValueError, TypeError):
            return {"blocked": None, "error": True}
        label = str((document.get("risk_score") or {}).get("label", ""))
        if label:
            return {"blocked": label != "no_risks_detected", "error": False, "label": label}
        return {"blocked": int(document.get("issues", 0)) > 0, "error": False}

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--count", type=int, default=50_000, help="per ecosystem")
        parser.add_argument(
            "--ecosystems", nargs="+", default=["pypi", "npm"], choices=list(REGISTRIES)
        )
        parser.add_argument("--out", type=Path, default=Path("/results/stream"))
        parser.add_argument("--workers", type=int, default=8)
        parser.add_argument(
            "--guarddog", type=int, default=0, help="GuardDog on a random N as well"
        )
        args = parser.parse_args()
        args.out.mkdir(parents=True, exist_ok=True)
        results = args.out / "results.jsonl"
        done = set()
        if results.exists():
            for line in results.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                done.add((row["ecosystem"], row["name"]))

        work: list[tuple[str, str]] = []
        for ecosystem in args.ecosystems:
            names = BenignStream.ranked(ecosystem, args.count, args.out / f"top-{ecosystem}.json")
            work += [(ecosystem, name) for name in names]
        # A reproducible sample, not a secret: the seed is published so anyone draws the same one.
        compared = set(random.Random(SEED).sample(work, min(args.guarddog, len(work))))  # noqa: S311
        pending = [item for item in work if item not in done]
        print(
            f"{len(work)} packages, {len(done)} already measured, {len(pending)} to go", flush=True
        )

        lock = threading.Lock()
        counter = {"n": 0}

        def one(item: tuple[str, str]) -> None:
            ecosystem, name = item
            row: dict[str, Any] = {"ecosystem": ecosystem, "name": name}
            try:
                version, filename, blob = BenignStream.artefact(ecosystem, name)
                row.update(version=version, sha256=hashlib.sha256(blob).hexdigest())
                with tempfile.TemporaryDirectory(prefix="stream-") as work_dir:
                    target = Path(work_dir) / filename
                    target.write_bytes(blob)
                    row["cordon"] = BenignStream.cordon(target)
                    if item in compared:
                        row["guarddog"] = BenignStream.guarddog(target, ecosystem)
            except Exception as exc:  # one package failing to fetch is a row, not a stop
                row["fetch_error"] = f"{type(exc).__name__}: {exc}"[:200]
            with lock:
                with results.open("a") as handle:
                    handle.write(json.dumps(row) + "\n")
                counter["n"] += 1
                if counter["n"] % 500 == 0:
                    print(f"{counter['n']}/{len(pending)}", flush=True)

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(one, pending))
        return BenignStream.summarise(results)

    @staticmethod
    def summarise(results: Path) -> int:
        rows = [json.loads(line) for line in results.read_text(encoding="utf-8").splitlines()]
        for ecosystem in sorted({r["ecosystem"] for r in rows}):
            scanned = [r for r in rows if r["ecosystem"] == ecosystem and "cordon" in r]
            blocked = [r for r in scanned if r["cordon"]["blocked"]]
            print(f"{ecosystem}: {len(scanned)} scanned, {len(blocked)} blocked by Cordon")
            compared = [
                r for r in scanned if "guarddog" in r and r["guarddog"]["blocked"] is not None
            ]
            if compared:
                print(
                    f"  same sample of {len(compared)}: Cordon {sum(r['cordon']['blocked'] for r in compared)}"
                    f", GuardDog {sum(r['guarddog']['blocked'] for r in compared)}"
                )
        return 0


if __name__ == "__main__":
    sys.exit(BenignStream.main())
