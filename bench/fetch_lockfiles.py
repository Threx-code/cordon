"""Thousands of real lockfiles, across every registry, for the parsing comparison (`compare.py`).

The most-downloaded packages of each registry (packages.ecosyste.ms) lead to their source
repositories; each repository's lockfiles are listed by repos.ecosyste.ms and downloaded from the
repository as committed. Written to <data>/lockfiles-large/<registry>/<owner>__<repo>__<path>/<file>
with an index of what came from where. Run inside Docker only, network on (it fetches nothing it
runs):

    docker run --rm -v cordon-bench-data:/data --entrypoint python cordon-bench:dev /bench/fetch_lockfiles.py --per-registry 400
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PACKAGES = "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages?sort=downloads&order=desc&per_page=100&page={page}"
MANIFESTS = (
    "https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/{repo}/manifests?per_page=100"
)
RAW = "https://raw.githubusercontent.com/{repo}/HEAD/{path}"
REGISTRIES = (
    "npmjs.org",
    "pypi.org",
    "crates.io",
    "proxy.golang.org",
    "repo1.maven.org",
    "nuget.org",
    "rubygems.org",
    "packagist.org",
    "hex.pm",
    "pub.dev",
    "cocoapods.org",
    "cran.r-project.org",
    "hackage.haskell.org",
    "swiftpackageindex.com",
)
MAX_BYTES = 32 << 20
#: The manifest each lockfile is read beside: Go needs go.mod for go.sum, uv and Poetry need
#: pyproject.toml, and every tool reads direct dependencies from the manifest.
SIBLINGS = {
    "go.sum": ("go.mod",),
    "Cargo.lock": ("Cargo.toml",),
    "composer.lock": ("composer.json",),
    "uv.lock": ("pyproject.toml",),
    "poetry.lock": ("pyproject.toml",),
    "pdm.lock": ("pyproject.toml",),
    "Pipfile.lock": ("Pipfile",),
    "package-lock.json": ("package.json",),
    "npm-shrinkwrap.json": ("package.json",),
    "yarn.lock": ("package.json",),
    "pnpm-lock.yaml": ("package.json",),
    "Gemfile.lock": ("Gemfile",),
    "Podfile.lock": ("Podfile",),
    "pubspec.lock": ("pubspec.yaml",),
    "mix.lock": ("mix.exs",),
    "Package.resolved": ("Package.swift",),
    "stack.yaml.lock": ("stack.yaml",),
    "renv.lock": ("DESCRIPTION",),
    "gradle.lockfile": ("build.gradle", "build.gradle.kts"),
}


class Fetch:
    """Polite, bounded HTTP: one request at a time, a pause between them, and a size cap."""

    @staticmethod
    def get(url: str) -> bytes:
        request = urllib.request.Request(
            url, headers={"User-Agent": "cordon-bench (lockfile corpus)"}
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    data = response.read(MAX_BYTES + 1)
                time.sleep(0.2)
                if len(data) > MAX_BYTES:
                    raise ValueError("over the size cap")
                return data
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    raise
                time.sleep(5 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError):
                time.sleep(5 * (attempt + 1))
        raise TimeoutError(url)

    @staticmethod
    def json(url: str) -> Any:
        return json.loads(Fetch.get(url))


class Corpus:
    @staticmethod
    def repositories(registry: str, count: int) -> list[str]:
        """`owner/repo` on GitHub for the registry's most-downloaded packages, first seen first."""
        found: list[str] = []
        for page in range(1, count // 100 + 2):
            try:
                rows = Fetch.json(PACKAGES.format(registry=registry, page=page))
            except Exception as exc:
                print(f"{registry} page {page}: {exc}", file=sys.stderr)
                break
            for row in rows if isinstance(rows, list) else []:
                url = str(row.get("repository_url") or "")
                parts = urllib.parse.urlsplit(url)
                path = [p for p in parts.path.split("/") if p]
                if parts.netloc.lower() == "github.com" and len(path) >= 2:
                    repo = f"{path[0]}/{path[1].removesuffix('.git')}"
                    if repo.lower() not in {r.lower() for r in found}:
                        found.append(repo)
            if len(found) >= count:
                break
        return found[:count]

    @staticmethod
    def run(data: Path, per_registry: int) -> None:
        out = data / "lockfiles-large"
        out.mkdir(parents=True, exist_ok=True)
        index_path = out / "index.json"
        index: list[dict[str, str]] = (
            json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
        )
        done = {(entry["repo"], entry["path"]) for entry in index}
        seen_repos: set[str] = set()
        for registry in REGISTRIES:
            repositories = Corpus.repositories(registry, per_registry)
            print(f"{registry}: {len(repositories)} repositories", flush=True)
            for repo in repositories:
                if repo.lower() in seen_repos:
                    continue
                seen_repos.add(repo.lower())
                try:
                    manifests = Fetch.json(
                        MANIFESTS.format(repo=urllib.parse.quote(repo, safe="/"))
                    )
                except Exception as exc:
                    print(f"{repo}: {exc}", file=sys.stderr)
                    continue
                for manifest in manifests if isinstance(manifests, list) else []:
                    if manifest.get("kind") != "lockfile" or not manifest.get("filepath"):
                        continue
                    path = str(manifest["filepath"])
                    if (
                        (repo, path) in done
                        or "/node_modules/" in f"/{path}"
                        or "/vendor/" in f"/{path}"
                    ):
                        continue
                    try:
                        body = Fetch.get(RAW.format(repo=repo, path=urllib.parse.quote(path)))
                    except Exception as exc:
                        print(f"{repo}/{path}: {exc}", file=sys.stderr)
                        continue
                    folder = (
                        out / registry / f"{repo.replace('/', '__')}__{path.replace('/', '__')}"
                    )
                    folder.mkdir(parents=True, exist_ok=True)
                    (folder / Path(path).name).write_bytes(body)
                    index.append(
                        {
                            "registry": registry,
                            "ecosystem": str(manifest.get("ecosystem")),
                            "repo": repo,
                            "path": path,
                            "folder": folder.relative_to(out).as_posix(),
                        }
                    )
                    done.add((repo, path))
                index_path.write_text(json.dumps(index, indent=1), encoding="utf-8")
            print(
                f"{registry}: {sum(1 for e in index if e['registry'] == registry)} lockfiles so far",
                flush=True,
            )
        print(f"lockfiles: {len(index)}")


class Siblings:
    @staticmethod
    def run(data: Path) -> None:
        """For each lockfile already fetched, the manifest beside it in the same commit's tree."""
        out = data / "lockfiles-large"
        index = json.loads((out / "index.json").read_text(encoding="utf-8"))
        added = 0
        for entry in index:
            lockfile = Path(entry["path"])
            for name in SIBLINGS.get(lockfile.name, ()):
                folder = out / entry["folder"]
                if (folder / name).exists():
                    break
                sibling = (lockfile.parent / name).as_posix()
                try:
                    body = Fetch.get(
                        RAW.format(repo=entry["repo"], path=urllib.parse.quote(sibling))
                    )
                except Exception:
                    continue
                (folder / name).write_bytes(body)
                added += 1
                break
        print(f"siblings: {added} manifests added")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--per-registry", type=int, default=400)
    parser.add_argument(
        "--siblings", action="store_true", help="only add each fetched lockfile's manifest"
    )
    arguments = parser.parse_args()
    if arguments.siblings:
        Siblings.run(arguments.data)
    else:
        Corpus.run(arguments.data, arguments.per_registry)
