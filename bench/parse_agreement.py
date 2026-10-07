"""How closely Cordon's reading of real lockfiles agrees with Trivy's, at scale.

For every lockfile `fetch_lockfiles.py` collected, the packages Cordon resolves from it are compared
with the packages Trivy lists for it (`trivy fs --list-all-pkgs`, its database read offline from a
cache). Agreement per lockfile is the F1 of the two (name, version) sets, names normalised the way
each ecosystem defines equality. Neither tool is the truth: the result keeps every lockfile's
difference, so each disagreement can be examined and decided, and the summary says per registry how
many lockfiles agree exactly and the mean agreement. Run inside Docker only, network off, with
Trivy's database cached in a volume first:

    docker run --rm -v cordon-trivy-cache:/root/.cache/trivy --entrypoint trivy cordon-bench:dev image --download-db-only
    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-trivy-cache:/root/.cache/trivy \\
      -v "$PWD/bench/results/full-2026-10-07:/results" --entrypoint python cordon-bench:dev /bench/parse_agreement.py
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

#: Trivy's lockfile types, mapped to Cordon's ecosystem ids.
TRIVY_TYPES = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi", "python-pkg": "pypi",
    "cargo": "cargo", "gomod": "gomod", "gobinary": "gomod",
    "pom": "maven", "gradle": "gradle", "sbt": "maven",
    "nuget": "nuget", "dotnet-core": "nuget", "packages-props": "nuget",
    "composer": "composer", "bundler": "rubygems", "gemspec": "rubygems",
    "hex": "hex", "pub": "pub", "swift": "swift", "cocoapods": "cocoapods",
    "conda-pkg": "conda", "conda-environment": "conda", "conan": "conan",
}  # fmt: skip


class Agreement:
    """One lockfile's two readings, normalised and compared."""

    #: The toolchain that wrote the lockfile, which Cordon lists (for its own advisories) and
    #: Trivy does not: `BUNDLED WITH`, `COCOAPODS:`. Excluded from the adjusted figure only.
    TOOLCHAIN = frozenset({("rubygems", "bundler"), ("cocoapods", "cocoapods"), ("gomod", "stdlib")})

    @staticmethod
    def name(ecosystem: str, name: str) -> str:
        if ecosystem == "pypi":
            return re.sub(r"[-_.]+", "-", name).lower()
        if ecosystem == "swift":
            # Trivy names a Swift package by its host and path (or, for an ssh remote, the remote
            # as written), Cordon by its path.
            return name.lower().removeprefix("git@github.com:").removeprefix("github.com/").removesuffix(".git")
        if ecosystem == "cocoapods":
            # Trivy lists each subspec (`Pod/Core`) as a package; Cordon the pod it belongs to.
            return name.lower().split("/", 1)[0]
        if ecosystem in ("maven", "gradle"):
            return name.lower()
        return name.lower() if ecosystem not in ("gomod",) else name

    #: Formats both tools read from the lockfile alone. Compared that way: beside its manifest, a
    #: workspace lockfile was read by Trivy only as far as the root manifest reaches, and the
    #: members' manifests were not fetched.
    LOCK_ALONE = frozenset({"Cargo.lock", "mix.lock", "Gemfile.lock", "pubspec.lock", "composer.lock", "Podfile.lock", "Package.resolved", "packages.lock.json"})
    _SEMVER = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?$")

    @staticmethod
    def version(ecosystem: str, version: str) -> str:
        version = version.strip()
        if ecosystem == "swift" and not Agreement._SEMVER.match(version):
            # A branch pin: Cordon records the commit it resolved to, Trivy the branch's name.
            return "branch-pin"
        return version.removeprefix("v") if ecosystem in ("gomod",) else version

    @staticmethod
    def cordon(folder: Path) -> set[tuple[str, str]]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True), detectors=()).scan(folder)
        out: set[tuple[str, str]] = set()
        for dependency in result.dependencies:
            # A workspace member or path package with a version is in the lockfile, and Trivy
            # lists it: compared, though Cordon marks it local.
            if not dependency.version or dependency.ecosystem in ("image", "actions"):
                continue
            ecosystem = "maven" if dependency.ecosystem == "gradle" else dependency.ecosystem
            out.add((Agreement.name(ecosystem, dependency.name), Agreement.version(ecosystem, dependency.version)))
        return out

    @staticmethod
    def trivy(folder: Path) -> tuple[set[tuple[str, str]], str]:
        completed = subprocess.run(  # noqa: S603 - fixed argv, the benchmark's own binary
            ["trivy", "fs", "--quiet", "--skip-db-update", "--offline-scan", "--scanners", "vuln", "--list-all-pkgs", "--include-dev-deps", "--format", "json", str(folder)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            return set(), f"trivy failed: {completed.stderr.strip()[:200]}"
        document: dict[str, Any] = json.loads(completed.stdout or "{}")
        out: set[tuple[str, str]] = set()
        kinds = set()
        for result in document.get("Results") or []:
            ecosystem = TRIVY_TYPES.get(str(result.get("Type")), str(result.get("Type")))
            kinds.add(ecosystem)
            for package in result.get("Packages") or []:
                if package.get("Name") and package.get("Version"):
                    out.add((Agreement.name(ecosystem, package["Name"]), Agreement.version(ecosystem, package["Version"])))
        return out, ",".join(sorted(kinds))

    @staticmethod
    def own_packages(folder: Path) -> set[str]:
        """The project's own packages, by name, as its lockfile marks them: uv's root
        (`source = { editable = "." }`, `virtual`, `directory`), Cargo's workspace crates (no
        `source`), Bundler's `PATH` gems. Trivy lists them; Cordon does not call the project
        its own dependency. Excluded from both sides of the comparison, and counted."""
        names: set[str] = set()
        for lock in folder.iterdir():
            try:
                text = lock.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if lock.name in ("uv.lock", "Cargo.lock"):
                for block in re.split(r"\n(?=\[\[package\]\])", text):
                    name = re.search(r'^name = "([^"]+)"', block, re.M)
                    if not name:
                        continue
                    local = re.search(r'^source = \{ (?:editable|virtual|directory) = ', block, re.M) if lock.name == "uv.lock" else not re.search(r"^source = ", block, re.M)
                    if local:
                        names.add(Agreement.name("pypi" if lock.name == "uv.lock" else "cargo", name.group(1)))
            elif lock.name == "Gemfile.lock":
                for section in re.findall(r"(?ms)^PATH\n(.*?)(?:\n\n|\Z)", text):
                    names |= {m.lower() for m in re.findall(r"^    ([A-Za-z0-9_.-]+) \(", section, re.M)}
        return names

    @staticmethod
    def one(entry: dict[str, str]) -> dict[str, Any]:
        folder = Path(DATA) / "lockfiles-large" / entry["folder"]
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as alone:
            lock = Path(entry["path"]).name
            if lock in Agreement.LOCK_ALONE and (folder / lock).is_file():
                shutil.copy(folder / lock, Path(alone) / lock)
                read = Path(alone)
            else:
                read = folder
            try:
                ours = Agreement.cordon(read)
                theirs, kinds = Agreement.trivy(read)
            except Exception as exc:  # noqa: BLE001 - one lockfile's failure is recorded, not fatal
                return {**entry, "error": f"{type(exc).__name__}: {exc}"[:300]}
        if not kinds:
            return {**entry, "trivy_types": "", "cordon": len(ours), "trivy_reads_nothing": True}
        ecosystems = {TRIVY_TYPES.get(k, k) for k in kinds.split(",")}
        own = Agreement.own_packages(folder)
        ours = {(n, v) for n, v in ours if not any((e, n) in Agreement.TOOLCHAIN for e in ecosystems) and n not in own}
        theirs = {(n, v) for n, v in theirs if n not in own}
        both = ours & theirs
        precision = len(both) / len(ours) if ours else (1.0 if not theirs else 0.0)
        recall = len(both) / len(theirs) if theirs else (1.0 if not ours else 0.0)
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
        return {
            **entry,
            "trivy_types": kinds,
            "cordon": len(ours),
            "trivy": len(theirs),
            "agree": len(both),
            "f1": round(f1, 4),
            "only_cordon": sorted(f"{n}@{v}" for n, v in ours - theirs)[:25],
            "only_trivy": sorted(f"{n}@{v}" for n, v in theirs - ours)[:25],
        }

    @staticmethod
    def run(results: Path, workers: int) -> None:
        index = json.loads((Path(DATA) / "lockfiles-large" / "index.json").read_text())
        with multiprocessing.get_context("fork").Pool(workers) as pool:
            rows = list(pool.imap_unordered(Agreement.one, index, chunksize=4))
        by_registry: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            by_registry[row["registry"]].append(row)
        summary: dict[str, Any] = {}
        for registry, items in sorted(by_registry.items()):
            compared = [r for r in items if "f1" in r and (r["trivy"] or r["cordon"])]
            summary[registry] = {
                "lockfiles": len(items),
                "trivy_reads_nothing": sum(1 for r in items if r.get("trivy_reads_nothing")),
                "compared": len(compared),
                "errors": sum(1 for r in items if "error" in r),
                "exact": sum(1 for r in compared if r["f1"] == 1.0),
                "mean_f1": round(sum(r["f1"] for r in compared) / len(compared), 4) if compared else None,
            }
        (results / "parse-agreement.json").write_text(json.dumps({"summary": summary, "lockfiles": rows}, indent=1))
        print(json.dumps(summary, indent=1))


DATA = "/data"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", default="/data")
    parser.add_argument("--results", type=Path, default=Path("/results"))
    parser.add_argument("--workers", type=int, default=8)
    arguments = parser.parse_args()
    DATA = arguments.data
    Agreement.run(arguments.results, arguments.workers)
