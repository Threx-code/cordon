#!/usr/bin/env python3
"""Fetch the benchmark inputs into /data. Network; run in its own container, never on the host.

malware   DataDog's malicious-software-packages-dataset: password-protected zips, which stay
          encrypted until a scan container opens them. Sampled, not cloned whole (20 GB).
benign    The top N npm and PyPI packages, as published archives, with their registry digests.
lockfiles Real lockfiles from popular repositories, for the CVE-agreement suite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

DATADOG = "https://github.com/DataDog/malicious-software-packages-dataset.git"
MALREGISTRY = "https://github.com/lxyeternal/pypi_malregistry.git"
"""The ASE 2023 "Empirical Study of Malicious Code in PyPI" dataset: 10,000+ malicious PyPI
releases as published, one directory per package. Overlaps DataDog; the harness counts each
`name/version` once."""
TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_TOP = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=downloads&order=desc&per_page=100&page={}"


class BenchmarkData:
    """Fetching the malware and benign corpora into the benchmark volume."""

    @staticmethod
    def get(url: str) -> bytes:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "cordon-bench"}), timeout=120
        ) as r:
            return r.read()

    @staticmethod
    def clone(url: str, into: Path) -> None:
        if into.exists():
            subprocess.run(["git", "-C", str(into), "pull", "--ff-only", "-q"], check=True)
        else:
            subprocess.run(["git", "clone", "--depth", "1", "-q", url, str(into)], check=True)

    @staticmethod
    def datadog_sample(into: Path, count: int) -> None:
        """The first `count` samples per ecosystem, without downloading the 20 GB repository: a
        partial clone fetches blobs only for the paths checked out."""
        if not into.exists():
            subprocess.run(
                [
                    "git",
                    "clone",
                    "-q",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--no-checkout",
                    DATADOG,
                    str(into),
                ],
                check=True,
            )
        listing = subprocess.run(
            ["git", "-C", str(into), "ls-tree", "-r", "--name-only", "HEAD", "samples/"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        chosen: list[str] = []
        # Every folder the dataset has, not only npm and PyPI: it now also carries IDE extensions
        # (.vsix) and AI agent skills, which are exactly the surfaces the agent rules cover.
        folders = sorted({p.split("/")[1] for p in listing if p.count("/") >= 2})
        for ecosystem in folders:
            chosen += [
                p
                for p in listing
                if p.startswith(f"samples/{ecosystem}/") and p.endswith((".zip", ".vsix"))
            ][:count]
        # On stdin: the whole dataset is 28,000 paths, past the argument-length limit.
        subprocess.run(
            ["git", "-C", str(into), "sparse-checkout", "set", "--no-cone", "--stdin"],
            input="\n".join(chosen),
            text=True,
            check=True,
        )
        subprocess.run(["git", "-C", str(into), "checkout", "-q", "HEAD"], check=True)
        print(f"malware: {len(chosen)} samples")

    @staticmethod
    def malregistry(into: Path) -> None:
        """A shallow clone. The archives are the packages as they were published, unextracted;
        they are opened only by a scan container with its network off."""
        if not into.exists():
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", MALREGISTRY, str(into)], check=True
            )
        archives = [p for p in into.rglob("*") if p.suffix in (".gz", ".zip", ".whl", ".egg")]
        print(f"malregistry: {len(archives)} archives")

    @staticmethod
    def benign(data: Path, count: int, ecosystems: tuple[str, ...] = ("pypi", "npm")) -> None:
        out = data / "benign"
        out.mkdir(parents=True, exist_ok=True)
        manifest: list[dict[str, str]] = []
        already = (
            {
                (e["ecosystem"], e["name"])
                for e in json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            }
            if (out / "manifest.json").exists()
            else set()
        )
        manifest += (
            list(json.loads((out / "manifest.json").read_text(encoding="utf-8"))) if already else []
        )
        # What is already on disk counts as fetched, manifest or not: a run that stopped before
        # writing its manifest is resumed, not repeated.
        on_disk = {
            p.name
            for registry in ("pypi", "npm")
            if (out / registry).is_dir()
            for p in (out / registry).iterdir()
        }
        pypi = (
            [row["project"] for row in json.loads(BenchmarkData.get(TOP_PYPI))["rows"][:count]]
            if "pypi" in ecosystems
            else []
        )
        for name in pypi:
            if ("pypi", name) in already:
                continue
            try:
                document = json.loads(BenchmarkData.get(f"https://pypi.org/pypi/{name}/json"))
            except Exception as exc:
                print(f"pypi {name}: {exc}", file=sys.stderr)
                continue
            files = [
                f for f in document.get("urls", []) if f.get("packagetype") == "sdist"
            ] or document.get("urls", [])[:1]
            if not files:
                continue
            chosen = files[0]
            if chosen["filename"] in on_disk:
                manifest.append(
                    {"ecosystem": "pypi", "name": name, "file": f"benign/pypi/{chosen['filename']}"}
                )
                continue
            blob = BenchmarkData.get(chosen["url"])
            if hashlib.sha256(blob).hexdigest() != chosen["digests"]["sha256"]:
                print(f"pypi {name}: digest mismatch, skipped", file=sys.stderr)
                continue
            target = out / "pypi" / chosen["filename"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
            manifest.append(
                {"ecosystem": "pypi", "name": name, "file": target.relative_to(data).as_posix()}
            )
        names: list[str] = []
        for page in range(1, (count // 100 + 2) if "npm" in ecosystems else 1):
            names += [
                row["name"]
                for row in json.loads(BenchmarkData.get(NPM_TOP.format(page)))
                if isinstance(row, dict) and row.get("name")
            ]
            if len(names) >= count:
                break
        names = names[:count]
        stems = {p.rsplit("-", 1)[0] for p in on_disk if p.endswith(".tgz")}
        for name in names:
            if ("npm", name) in already:
                continue
            if name.replace("/", "__") in stems:
                # Fetched by a run that stopped before writing its manifest: recorded, not refetched.
                existing = next(
                    p
                    for p in sorted(on_disk)
                    if p.endswith(".tgz") and p.rsplit("-", 1)[0] == name.replace("/", "__")
                )
                manifest.append(
                    {"ecosystem": "npm", "name": name, "file": f"benign/npm/{existing}"}
                )
                continue
            try:
                document = json.loads(
                    BenchmarkData.get(
                        f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest"
                    )
                )
                blob = BenchmarkData.get(document["dist"]["tarball"])
            except Exception as exc:
                print(f"npm {name}: {exc}", file=sys.stderr)
                continue
            target = out / "npm" / f"{name.replace('/', '__')}-{document['version']}.tgz"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
            manifest.append(
                {"ecosystem": "npm", "name": name, "file": target.relative_to(data).as_posix()}
            )
        (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        print(f"benign: {len(manifest)} archives")

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument(
            "suite", choices=["malware", "malregistry", "benign", "lockfiles", "all"]
        )
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--count", type=int, default=1000)
        parser.add_argument(
            "--ecosystems", default="pypi,npm", help="for benign: which registries' top packages"
        )
        args = parser.parse_args()
        args.data.mkdir(parents=True, exist_ok=True)
        if args.suite in ("malware", "all"):
            BenchmarkData.datadog_sample(args.data / "datadog", args.count)
        if args.suite in ("malregistry", "all"):
            BenchmarkData.malregistry(args.data / "malregistry")
        if args.suite in ("benign", "all"):
            BenchmarkData.benign(args.data, args.count, tuple(args.ecosystems.split(",")))
        if args.suite in ("lockfiles", "all"):
            lockfiles = args.data / "lockfiles"
            lockfiles.mkdir(exist_ok=True)
            fetched = 0
            for repo, path in json.loads(
                (Path(__file__).parent / "lockfiles.json").read_text(encoding="utf-8")
            ):
                # One directory per lockfile, under its own file name: every tool finds it by name.
                target = (
                    lockfiles / f"{repo.replace('/', '__')}__{Path(path).stem}" / Path(path).name
                )
                try:
                    data = BenchmarkData.get(
                        f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
                    )
                except Exception as exc:
                    print(f"{repo}/{path}: {exc}", file=sys.stderr)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                fetched += 1
            print(f"lockfiles: {fetched}")
        return 0


if __name__ == "__main__":
    raise SystemExit(BenchmarkData.main())
