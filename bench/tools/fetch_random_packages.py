#!/usr/bin/env python3
"""A random sample of ordinary npm and PyPI packages: the long tail a model must not flag.

The top packages are large and well kept, and nothing like the typical malicious release: a model
trained against them alone learns "small and obscure is malicious". This draws names at random --
PyPI's simple index lists every project; npm's registry is sampled through its public search, by
random two-letter queries -- and downloads each one's latest release archive with its registry
digest. Never installed, never run. Anything Cordon's known-malicious records name is dropped by
the dataset builder, not here.

    python bench/tools/fetch_random_packages.py --out corpus-dir --npm 10000 --pypi 5000 --seed 20261011

Run inside a container with network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MAX_ARCHIVE = 32 << 20
_UA = {"User-Agent": "cordon-random-package-study"}


class RandomPackages:
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
                time.sleep(2 + attempt * 3)
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(2 + attempt * 3)
        raise OSError(f"could not fetch {url}")

    @staticmethod
    def pypi_names(draw: random.Random, count: int) -> list[str]:
        index = RandomPackages.get("https://pypi.org/simple/", 256 << 20).decode("utf-8", "replace")
        names = re.findall(r'<a href="/simple/([^/]+)/">', index)
        return draw.sample(names, min(count * 2, len(names)))

    @staticmethod
    def npm_names(draw: random.Random, count: int) -> list[str]:
        names: set[str] = set()
        letters = string.ascii_lowercase
        while len(names) < count * 2:
            query = "".join(draw.choice(letters) for _ in range(2))
            offset = draw.randrange(0, 2000, 250)
            try:
                found = json.loads(
                    RandomPackages.get(
                        f"https://registry.npmjs.org/-/v1/search?text={query}&size=250&from={offset}"
                    )
                )
            except (OSError, ValueError, urllib.error.HTTPError):
                continue
            names.update(o["package"]["name"] for o in found.get("objects", []) if o.get("package"))
            time.sleep(0.3)
        return draw.sample(sorted(names), count * 2)

    @staticmethod
    def pypi_release(name: str) -> tuple[str, str, str] | None:
        try:
            meta = json.loads(
                RandomPackages.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            )
        except (OSError, ValueError, urllib.error.HTTPError):
            return None
        files = meta.get("urls") or []
        chosen = next((f for f in files if f.get("packagetype") == "sdist"), None) or next(
            (f for f in files if f.get("packagetype") == "bdist_wheel"), None
        )
        if not chosen:
            return None
        return (
            str(meta["info"]["version"]),
            str(chosen["url"]),
            f"sha256:{chosen['digests']['sha256']}",
        )

    @staticmethod
    def npm_release(name: str) -> tuple[str, str, str] | None:
        try:
            meta = json.loads(
                RandomPackages.get(
                    f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest"
                )
            )
        except (OSError, ValueError, urllib.error.HTTPError):
            return None
        dist = meta.get("dist") or {}
        if not dist.get("tarball") or not dist.get("shasum"):
            return None
        return str(meta.get("version")), str(dist["tarball"]), f"sha1:{dist['shasum']}"

    @staticmethod
    def fetch(out: Path, ecosystem: str, name: str) -> dict[str, str] | None:
        release = (
            RandomPackages.npm_release if ecosystem == "npm" else RandomPackages.pypi_release
        )(name)
        if release is None:
            return None
        version, url, digest = release
        try:
            body = RandomPackages.get(url, MAX_ARCHIVE)
        except (OSError, urllib.error.HTTPError):
            return None
        if len(body) > MAX_ARCHIVE:
            return None
        algorithm, expected = digest.split(":", 1)
        if hashlib.new(algorithm, body).hexdigest() != expected:
            return None
        safe = re.sub(r"[^\w.@-]", "_", name)
        target = (
            out
            / ecosystem
            / f"{safe}-{version}{Path(urllib.parse.urlsplit(url).path).suffix or '.tgz'}"
        )
        if url.endswith(".tar.gz"):
            target = (
                target.with_suffix("").with_suffix(".tar.gz")
                if not str(target).endswith(".tar.gz")
                else target
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "file": target.relative_to(out).as_posix(),
            "digest": digest,
        }

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--npm", type=int, default=10000)
        parser.add_argument("--pypi", type=int, default=5000)
        parser.add_argument("--seed", type=int, default=20261011)
        args = parser.parse_args()
        draw = random.Random(args.seed)  # noqa: S311 - a reproducible sample, not a secret
        args.out.mkdir(parents=True, exist_ok=True)
        manifest: list[dict[str, str]] = []
        for ecosystem, count, names in (
            ("pypi", args.pypi, RandomPackages.pypi_names(draw, args.pypi)),
            ("npm", args.npm, RandomPackages.npm_names(draw, args.npm)),
        ):
            kept: list[dict[str, str]] = []
            with ThreadPoolExecutor(12) as pool:
                for record in pool.map(
                    lambda n, e=ecosystem: RandomPackages.fetch(args.out, e, n), names
                ):
                    if record and len(kept) < count:
                        kept.append(record)
            manifest += kept
            print(f"{ecosystem}: {len(kept)} packages", flush=True)
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        return 0


if __name__ == "__main__":
    sys.exit(RandomPackages.main())
