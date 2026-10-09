"""Dependency extraction against each ecosystem's own tool, for the ecosystems no other scanner reads.

The parsing comparison (`compare.py`) measures Cordon against Trivy for the registries Trivy reads.
Twelve ecosystems had no comparison at all -- Actions, Ansible, Bazel, Conan, Conda, Helm,
Homebrew, Julia, Nix, OPAM, Terraform, vcpkg -- so for each, real files from real repositories
are read by the ecosystem's own tool and by Cordon, and the two dependency lists compared:

    collect      real repositories' dependency files, into <data>/tool-agreement/<eco>/<repo>/
                 (the most-downloaded packages' repositories from ecosyste.ms, or GitHub's topic
                 search where a registry lists none: dotfiles, flakes, collections, C++ projects)
    reference    bench/tool_reference/run.sh: each tool, in its own image, writes what it read
                 beside the files (.reference/)
    compare      Cordon reads the same files; per ecosystem, the names both found, the names only
                 one found, repository by repository, every difference kept

Nothing collected is executed. Collection keeps dependency files from repository tarballs as
bytes; every reference tool reads files without building or running them. That rules two out:
Homebrew Bundle reads a Brewfile by evaluating it as Ruby, and Conan a conanfile.py by importing
it, so Homebrew has no comparison and Conan's covers conanfile.txt and conan.lock only. Where a
tool cannot see what Cordon reads -- a flake without its lock, offline; a MODULE.bazel below the
root -- the comparison covers what both read.

    docker volume create cordon-tool-agreement
    docker run --rm -v cordon-tool-agreement:/data -v "$PWD/bench:/bench:ro" python:3.12-slim \
        python /bench/tool_agreement.py collect --data /data/tool-agreement
    sh bench/tool_reference/run.sh
    docker run --rm -v cordon-tool-agreement:/data <an image with cordon-scanner installed> \
        python bench/tool_agreement.py compare --data /data/tool-agreement --results <dir>
"""

from __future__ import annotations

import argparse
import fnmatch
import io
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

PACKAGES = "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages?sort=downloads&order=desc&per_page=100&page={page}"
SEARCH = "https://api.github.com/search/repositories?{query}"
TARBALL = "https://codeload.github.com/{repo}/tar.gz/HEAD"
MAX_TARBALL = 256 << 20
MAX_FILE = 4 << 20


@dataclass(frozen=True)
class Ecosystem:
    id: str
    patterns: tuple[str, ...]
    """Basename globs of the files kept (and the directories they sit in, for siblings)."""
    registry: str | None = None
    searches: tuple[str, ...] = ()
    per: int = 30
    siblings: tuple[str, ...] = ()


ECOSYSTEMS: dict[str, Ecosystem] = {
    e.id: e
    for e in (
        Ecosystem("terraform", ("*.tf", ".terraform.lock.hcl"), registry="registry.terraform.io"),
        Ecosystem(
            "helm", ("Chart.yaml", "Chart.lock", "requirements.yaml"), registry="artifacthub.io"
        ),
        Ecosystem("julia", ("Project.toml", "Manifest.toml"), registry="juliahub.com"),
        Ecosystem("opam", ("*.opam", "opam", "*.opam.locked"), registry="opam.ocaml.org"),
        Ecosystem(
            "bazel",
            ("MODULE.bazel", "MODULE.bazel.lock", ".bazelversion"),
            registry="registry.bazel.build",
        ),
        Ecosystem("actions", ("*.yml", "*.yaml"), registry="github actions"),
        Ecosystem(
            "nix",
            ("flake.nix", "flake.lock"),
            searches=("topic:nix-flake stars:>40", "topic:nixos-configuration stars:>40"),
        ),
        Ecosystem(
            "ansible",
            ("requirements.yml", "requirements.yaml", "galaxy.yml"),
            searches=("topic:ansible-collection stars:>20", "topic:ansible-role stars:>200"),
        ),
        Ecosystem(
            "vcpkg",
            ("vcpkg.json", "vcpkg-configuration.json"),
            searches=("topic:vcpkg stars:>10", "vcpkg in:readme stars:>500"),
        ),
        Ecosystem(
            "conan",
            ("conanfile.txt", "conan.lock"),
            searches=("topic:conan stars:>10", "conan in:readme language:C++ stars:>300"),
        ),
        Ecosystem(
            "cran",
            ("renv.lock",),
            searches=(
                "topic:renv stars:>3",
                "renv.lock in:readme stars:>20",
                "topic:shiny-apps stars:>30",
            ),
        ),
        Ecosystem(
            "conda",
            ("environment.yml", "environment.yaml"),
            searches=("topic:conda stars:>50", "environment.yml in:readme stars:>500"),
        ),
    )
}


class Http:
    @staticmethod
    def get(url: str, *, accept: str = "application/json", limit: int = 64 << 20) -> bytes:
        request = urllib.request.Request(
            url, headers={"User-Agent": "cordon-bench", "Accept": accept}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError("larger than the limit")
        return body

    @staticmethod
    def json(url: str) -> Any:
        return json.loads(Http.get(url))


class Repositories:
    @staticmethod
    def from_registry(registry: str, want: int) -> Iterator[str]:
        seen: set[str] = set()
        for page in range(1, 11):
            try:
                packages = Http.json(
                    PACKAGES.format(registry=urllib.parse.quote(registry), page=page)
                )
            except (urllib.error.URLError, OSError, ValueError):
                return
            if not packages:
                return
            for package in packages:
                url = str(package.get("repository_url") or "")
                found = re.match(r"https://github\.com/([^/]+/[^/#?]+)", url)
                if found:
                    repo = found.group(1).removesuffix(".git")
                    if repo.lower() not in seen:
                        seen.add(repo.lower())
                        yield repo
                        if len(seen) >= want * 4:
                            return

    @staticmethod
    def from_search(queries: tuple[str, ...], want: int) -> Iterator[str]:
        seen: set[str] = set()
        for query in queries:
            for page in range(1, 4):
                url = SEARCH.format(
                    query=urllib.parse.urlencode(
                        {"q": query, "sort": "stars", "per_page": 100, "page": page}
                    )
                )
                try:
                    body = Http.json(url)
                except (urllib.error.URLError, OSError, ValueError):
                    break
                time.sleep(7)  # the anonymous search limit is ten a minute
                for item in body.get("items") or ():
                    repo = str(item.get("full_name") or "")
                    if repo and repo.lower() not in seen:
                        seen.add(repo.lower())
                        yield repo
                if len(seen) >= want * 4:
                    return


class Collector:
    @staticmethod
    def wanted(ecosystem: Ecosystem, path: str) -> bool:
        name = PurePosixPath(path).name
        if ecosystem.id == "actions":
            return "/.github/workflows/" in f"/{path}" or name in ("action.yml", "action.yaml")
        return any(fnmatch.fnmatchcase(name, p) for p in ecosystem.patterns)

    @staticmethod
    def files(ecosystem: Ecosystem, repo: str) -> dict[str, bytes]:
        """The repository's dependency files, by path, from its tarball. Never extracted to disk
        as a tree, never run: each member is read, checked and kept as bytes."""
        try:
            data = Http.get(TARBALL.format(repo=repo), accept="*/*", limit=MAX_TARBALL)
        except (urllib.error.URLError, OSError, ValueError):
            return {}
        out: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile() or member.size > MAX_FILE:
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                if ".." in PurePosixPath(path).parts or path.startswith("/"):
                    continue
                if any(
                    part in ("node_modules", "vendor", ".git") for part in PurePosixPath(path).parts
                ):
                    continue
                if not Collector.wanted(ecosystem, path):
                    continue
                handle = archive.extractfile(member)
                if handle is not None:
                    out[path] = handle.read()
        return out

    @staticmethod
    def collect(ecosystem: Ecosystem, root: Path) -> dict[str, Any]:
        folder = root / ecosystem.id
        folder.mkdir(parents=True, exist_ok=True)
        source = (
            Repositories.from_registry(ecosystem.registry, ecosystem.per)
            if ecosystem.registry
            else Repositories.from_search(ecosystem.searches, ecosystem.per)
        )
        kept: list[dict[str, Any]] = []
        for repo in source:
            if len(kept) >= ecosystem.per:
                break
            files = Collector.files(ecosystem, repo)
            if not files:
                continue
            target = folder / repo.replace("/", "__")
            for path, data in files.items():
                out = target / path
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
            kept.append({"repo": repo, "files": sorted(files)})
            print(f"  {ecosystem.id}: {repo} ({len(files)} file(s))", flush=True)
        (folder / "index.json").write_text(json.dumps(kept, indent=1), encoding="utf-8")
        return {"ecosystem": ecosystem.id, "repositories": len(kept)}


class Reference:
    """What each ecosystem's own tool said, as `{repo directory: set of dependency names}`."""

    @staticmethod
    def _lines(path: Path) -> list[str]:
        return (
            path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
        )

    @staticmethod
    def terraform(repo: Path) -> set[str] | None:
        modules = repo / ".reference" / "modules.tsv"
        if not modules.exists():
            return None
        names: set[str] = set()
        for line in Reference._lines(modules):
            _directory, _, file = line.partition("\t")
            try:
                data = json.loads((repo / ".reference" / file).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for local, provider in (data.get("required_providers") or {}).items():
                source = (provider or {}).get("source") or f"hashicorp/{local}"
                parts = source.lower().split("/")
                if parts[-2:] == ["hashicorp", "terraform"] or "builtin" in parts:
                    continue  # the built-in provider (terraform_remote_state): never downloaded
                names.add("/".join(parts[-2:]))
            for call in (data.get("module_calls") or {}).values():
                source = str(call.get("source") or "")
                # Registry modules only: `<namespace>/<name>/<provider>`, maybe behind a host.
                parts = source.split("//")[0].split("/")
                if (
                    len(parts) in (3, 4)
                    and not source.startswith(
                        (".", "/", "git", "github.com", "bitbucket.org", "s3::", "gcs::", "http")
                    )
                    and "::" not in source
                ):
                    names.add("/".join(parts[-3:]).lower())
        return names

    @staticmethod
    def helm(repo: Path) -> set[str] | None:
        lines = Reference._lines(repo / ".reference" / "helm.txt")
        if not lines:
            return None
        names = set()
        for line in lines:
            fields = line.split()
            if not fields or line.startswith(("###", "NAME", "WARNING", "Error")):
                continue
            if len(fields) >= 3 and fields[2].startswith("file://"):
                continue  # a chart in this repository, as Cordon's own path dependencies are
            names.add(fields[0].lower())
        return names

    @staticmethod
    def julia(repo: Path) -> set[str] | None:
        lines = Reference._lines(repo / ".reference" / "julia.tsv")
        if not lines:
            return set() if (repo / ".reference" / "julia.tsv").exists() else None
        # Registered packages: a standard library ships with Julia and a path source is this
        # repository's own code, as Cordon's platform and path dependencies are.
        return {
            fields[2].lower()
            for fields in (line.split("\t") for line in lines)
            if len(fields) >= 5 and fields[1] in ("deps", "manifest") and fields[4] == "registry"
        }

    @staticmethod
    def opam(repo: Path) -> set[str] | None:
        text = "\n".join(Reference._lines(repo / ".reference" / "opam.txt"))
        if not text:
            return None
        # Each entry of the formula is a quoted package name, optionally followed by a
        # `{...}` filter whose strings are versions and variables, not packages.
        bare = re.sub(r"\{[^{}]*\}", " ", text)
        names: set[str] = set()
        for line in bare.splitlines():
            if line.startswith(("###", "@@")):
                continue  # a file's header, and the line opam.sh writes before its depopts
            names.update(name.lower() for name in re.findall(r'"([A-Za-z0-9_+.-]+)"', line))
            # A list opam prints bare: `iter`, `base-unix, ctypes, lwt` (opam's warnings go to
            # opam.err, so a line of bare words here is names).
            if re.fullmatch(r"\s*[A-Za-z0-9_+.-]+(?:[\s,]+[A-Za-z0-9_+.-]+)*\s*", line):
                names.update(word.lower() for word in re.split(r"[\s,]+", line.strip()))
        return names

    @staticmethod
    def conda(repo: Path) -> set[str] | None:
        path = repo / ".reference" / "conda.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            entry["name"].lower()
            for file in data.values()
            for entry in file.get("conda", ())
            if entry.get("name")
        }

    @staticmethod
    def ansible(repo: Path) -> set[str] | None:
        path = repo / ".reference" / "ansible.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for file in data.values():
            for collection in file.get("collections", ()):
                if collection.get("type") == "galaxy":
                    names.add(str(collection["name"]).lower())
            for role in file.get("roles", ()):
                if role.get("name"):
                    names.add(str(role["name"]).lower())
        return names

    @staticmethod
    def _indexed(repo: Path, index: str) -> list[Any]:
        """The JSON documents an index of `<directory>\t<file>` lines names."""
        out = []
        for line in Reference._lines(repo / ".reference" / index):
            _directory, _, file = line.partition("\t")
            try:
                out.append(json.loads((repo / ".reference" / file).read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return out

    @staticmethod
    def directories(repo: Path, ecosystem: str) -> set[str] | None:
        """The directories the reference read, where it read some and not others: Nix reads a
        flake with its lock (offline, it cannot lock one)."""
        if ecosystem == "bazel":
            return {""}  # `bazel mod graph` runs on the root module
        if ecosystem != "nix":
            return None
        out = set()
        for line in Reference._lines(repo / ".reference" / "flakes.tsv"):
            directory = line.partition("\t")[0]
            if directory.startswith("/"):  # the repository's own root, written whole
                directory = directory.split(f"/{repo.name}", 1)[-1]
            out.add(directory.strip("/"))
        return out

    @staticmethod
    def nix(repo: Path) -> set[str] | None:
        if not (repo / ".reference" / "flakes.tsv").exists():
            return None
        names: set[str] = set()
        for metadata in Reference._indexed(repo, "flakes.tsv"):
            nodes = (metadata.get("locks") or {}).get("nodes") or {}
            root = (metadata.get("locks") or {}).get("root", "root")
            for key, node in nodes.items():
                locked = node.get("locked") or {}
                if key == root or not locked:
                    continue
                kind = locked.get("type")
                if kind in ("github", "gitlab", "sourcehut"):
                    names.add(f"{locked['owner']}/{locked['repo']}".lower())
                elif kind == "path":
                    continue  # this repository's own code, as Cordon's path inputs are
                else:
                    names.add(Source.identity(str(locked.get("url") or key)))
        return names

    @staticmethod
    def conan(repo: Path) -> set[str] | None:
        path = repo / ".reference" / "conan.json"
        if not path.exists():
            return None
        names: set[str] = set()
        for file in json.loads(path.read_text(encoding="utf-8")).values():
            for key in (
                "requires",
                "tool_requires",
                "test_requires",
                "build_requires",
                "python_requires",
            ):
                for reference in file.get(key, ()):
                    names.add(str(reference).split("/", 1)[0].lower())
        return names

    @staticmethod
    def vcpkg(repo: Path) -> set[str] | None:
        if not (repo / ".reference" / "manifests.tsv").exists():
            return None
        names: set[str] = set()

        def add(entries: Any) -> None:
            for entry in entries or ():
                name = entry if isinstance(entry, str) else (entry or {}).get("name")
                if name:
                    names.add(str(name).lower())

        for manifest in Reference._indexed(repo, "manifests.tsv"):
            add(manifest.get("dependencies"))
            for feature in (manifest.get("features") or {}).values():
                add((feature or {}).get("dependencies"))
        return names

    @staticmethod
    def actions(repo: Path) -> set[str] | None:
        path = repo / ".reference" / "sbom.json"
        if not path.exists():
            return None
        packages = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(packages, list) or not packages:
            return None  # the dependency graph is off, or has not read this repository
        names: set[str] = set()
        for package in packages:
            for ref in package.get("externalRefs", ()):
                locator = str(ref.get("referenceLocator", ""))
                if locator.startswith("pkg:githubactions/"):
                    # `github/codeql-action/analyze`, a reusable workflow's path: the repository.
                    path = locator.removeprefix("pkg:githubactions/").split("@", 1)[0]
                    names.add("/".join(path.split("/")[:2]).lower())
        return names

    #: Modules inside Bazel itself: listed by `mod graph --include_builtin`, never downloaded.
    BAZEL_BUILTIN: ClassVar[frozenset[str]] = frozenset({"bazel_tools", "local_config_platform"})

    @staticmethod
    def bazel(repo: Path) -> set[str] | None:
        path = repo / ".reference" / "graph.json"
        try:
            graph = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not (repo / "MODULE.bazel.lock").exists():
            # Without a lock, the file holds the direct bazel_deps only; resolution is Bazel's.
            direct = (
                str(d.get("name") or str(d.get("key", "")).split("@")[0])
                for d in graph.get("dependencies", ())
            )
            return {name.lower() for name in direct if name and name not in Reference.BAZEL_BUILTIN}
        names: set[str] = set()
        stack = list(graph.get("dependencies", ()))
        while stack:
            node = stack.pop()
            # Older Bazels print `key` (`bazel_skylib@1.9.2`) and no `name`.
            name = str(node.get("name") or str(node.get("key", "")).split("@")[0])
            if name and name not in Reference.BAZEL_BUILTIN:
                names.add(name.lower())
            stack.extend(node.get("dependencies", ()))
            stack.extend(node.get("indirectDependencies", ()))
        return names

    @staticmethod
    def cran(repo: Path) -> set[str] | None:
        lines = Reference._lines(repo / ".reference" / "renv.tsv")
        if not lines:
            return None
        return {
            fields[1].lower()
            for fields in (line.split("\t") for line in lines)
            if len(fields) >= 4 and fields[0] != "error"
        }


#: Ecosystems whose own tool lists the platform as a package like any other: opam's `ocaml`
#: and `base-unix` are packages in the opam repository.
PLATFORM_PACKAGES = frozenset({"opam"})


class Source:
    """One identity for a source URL, whichever side wrote it: `owner/repo` on the forges both
    tools name that way, the bare URL elsewhere."""

    FORGES = ("github.com", "gitlab.com", "git.sr.ht")

    @staticmethod
    def identity(url: str) -> str:
        bare = re.sub(r"[#?].*$", "", url.removeprefix("git+")).removesuffix(".git").rstrip("/")
        parts = urllib.parse.urlsplit(bare)
        if parts.hostname in Source.FORGES:
            segments = [p for p in parts.path.split("/") if p]
            if len(segments) >= 2:
                return "/".join(segments[:2]).lower()
        return bare.lower()


class Cordon:
    #: The files of an ecosystem the reference can read. Conan reads a conanfile.py only by
    #: executing it, which this comparison never does: there, the text formats only.
    FILES: ClassVar[dict[str, tuple[str, ...]]] = {"conan": ("conanfile.txt", "conan.lock")}

    @staticmethod
    def identity(ecosystem: str, dependency: Any) -> str:
        if ecosystem == "nix":
            url = dependency.resolved_from or ""
            if url.startswith(("git+", "http")):
                return Source.identity(url)
        return dependency.name.lower()

    @staticmethod
    def names(repo: Path, ecosystem: str, directories: set[str] | None = None) -> set[str]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        config = Config.default().with_overrides(
            use_cache=False, offline=True, exclude=(".reference/**",)
        )
        result = Scanner(config, detectors=()).scan(repo)
        files = Cordon.FILES.get(ecosystem)
        return {
            Cordon.identity(ecosystem, d)
            for d in result.dependencies
            if d.ecosystem == ecosystem
            and (files is None or d.declared_in.rsplit("/", 1)[-1] in files)
            and (directories is None or d.declared_in.rpartition("/")[0] in directories)
            and not (d.declared_spec or "").startswith(("path:", "file:"))
            # opam's depexts are system packages (apt, brew), not opam packages.
            and not d.name.startswith("depext:")
            # A platform requirement (Terraform's required_version, Helm's kubeVersion, Julia's
            # own compat) is not a package any tool lists as a dependency.
            and (d.scope.value != "platform" or ecosystem in PLATFORM_PACKAGES)
            # Inside another archive (a Julia standard library inside Julia): not downloaded.
            and not d.bundled
        }


class Comparison:
    @staticmethod
    def run(ecosystem: str, root: Path) -> dict[str, Any]:
        reader = getattr(Reference, ecosystem)
        rows = []
        for repo in sorted(p for p in (root / ecosystem).iterdir() if p.is_dir()):
            reference = reader(repo)
            if reference is None:
                continue
            ours = Cordon.names(repo, ecosystem, Reference.directories(repo, ecosystem))
            rows.append(
                {
                    "repo": repo.name.replace("__", "/"),
                    "reference": len(reference),
                    "cordon": len(ours),
                    "agree": len(reference & ours),
                    "only_reference": sorted(reference - ours),
                    "only_cordon": sorted(ours - reference),
                }
            )
        total = {k: sum(r[k] for r in rows) for k in ("reference", "cordon", "agree")}
        precision = total["agree"] / total["cordon"] if total["cordon"] else 1.0
        recall = total["agree"] / total["reference"] if total["reference"] else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {
            "ecosystem": ecosystem,
            "repositories": len(rows),
            **total,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "repositories_in_full_agreement": sum(
                1 for r in rows if not r["only_reference"] and not r["only_cordon"]
            ),
            "rows": rows,
        }


class Main:
    @staticmethod
    def run() -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("stage", choices=("collect", "compare"))
        parser.add_argument("--results", type=Path, default=Path("/results"))
        parser.add_argument("--data", type=Path, default=Path("/data/tool-agreement"))
        parser.add_argument("--only", nargs="*", default=None)
        args = parser.parse_args()
        chosen = [ECOSYSTEMS[e] for e in (args.only or ECOSYSTEMS)]
        if args.stage == "collect":
            for ecosystem in chosen:
                print(json.dumps(Collector.collect(ecosystem, args.data)), flush=True)
            return 0
        args.results.mkdir(parents=True, exist_ok=True)
        summary = []
        for ecosystem in chosen:
            if not hasattr(Reference, ecosystem.id):
                continue
            result = Comparison.run(ecosystem.id, args.data)
            (args.results / f"{ecosystem.id}.json").write_text(
                json.dumps(result, indent=1), encoding="utf-8"
            )
            line = {k: v for k, v in result.items() if k != "rows"}
            summary.append(line)
            print(json.dumps(line), flush=True)
        (args.results / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        return 0


if __name__ == "__main__":
    sys.exit(Main.run())
