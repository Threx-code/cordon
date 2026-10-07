"""Every package Cordon and Trivy disagree on, after `parse_agreement.py`, sorted by cause.

The agreement figures are left raw. This answers the next question, which side each remaining
difference is on, by reading the lockfile itself for the shapes that account for most of them:

  go.mod hash only    a module go.sum records only by its go.mod's hash (`v1.2.0/go.mod h1:`).
                      Go read that file while selecting versions and never downloaded or built
                      the module. Trivy lists it for a pre-1.17 go.mod; Cordon does not.
  hex alias           a mix.lock entry whose key is not its package (`"chatterbox": {:hex,
                      :ts_chatterbox, ...}`). Cordon names the Hex package, which is what
                      advisories name; Trivy names the key.
  npm alias           an npm alias (`"string-width-cjs": "npm:string-width@4.2.3"`): Cordon names
                      the package installed, which is what advisories name; Trivy the alias.
  project's own       a package the project itself defines (an npm workspace, a `file:` or
                      `link:` dependency): not something installed from a registry.
  in the lock         a Cordon-only package written in the lockfile as that name and version,
                      which Trivy did not read.
  other               none of the above: read by hand, case by case.

Run after parse_agreement.py, inside the bench image, against the same data volume:

    docker run --rm --network none -v cordon-bench-data:/data:ro \\
      -v "$PWD/bench/results:/results" --entrypoint python cordon-bench:dev \\
      /bench/parse_gaps.py /results/<run>/parse-agreement.json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

DATA = Path("/data/lockfiles-large")
HEX_ENTRY = re.compile(r'"(?P<key>[^"]+)":\s*\{:hex,\s*:"?(?P<package>[\w.-]+)"?,\s*"(?P<version>[^"]+)"')


class Gaps:
    @staticmethod
    def go_sum(folder: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        """(modules with a code hash, modules with only a go.mod hash), versions without `v`."""
        code: set[tuple[str, str]] = set()
        planned: set[tuple[str, str]] = set()
        path = folder / "go.sum"
        if not path.is_file():
            return code, planned
        for line in path.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            if parts[1].endswith("/go.mod"):
                planned.add((parts[0], parts[1][: -len("/go.mod")].removeprefix("v")))
            else:
                code.add((parts[0], parts[1].removeprefix("v")))
        return code, planned - code

    @staticmethod
    def hex_entries(folder: Path) -> list[re.Match[str]]:
        path = folder / "mix.lock"
        return list(HEX_ENTRY.finditer(path.read_text(errors="replace"))) if path.is_file() else []

    @classmethod
    def classify(cls, row: dict) -> Counter[str]:
        folder = DATA / row["folder"]
        causes: Counter[str] = Counter()
        only_trivy = list(row["only_trivy"])
        only_cordon = list(row["only_cordon"])
        if row["registry"] == "proxy.golang.org":
            _, planned = cls.go_sum(folder)
            kept = []
            for entry in only_trivy:
                name, _, version = entry.rpartition("@")
                if (name, version) in planned:
                    causes["go.mod hash only (Trivy-side)"] += 1
                else:
                    kept.append(entry)
            only_trivy = kept
        if row["registry"] == "hex.pm":
            entries = cls.hex_entries(folder)
            aliases = {(m["key"].lower(), m["version"]): m["package"].lower() for m in entries if m["key"] != m["package"]}
            for entry in list(only_trivy):
                name, _, version = entry.rpartition("@")
                package = aliases.get((name.lower(), version))
                if package and f"{package}@{version}" in only_cordon:
                    only_trivy.remove(entry)
                    only_cordon.remove(f"{package}@{version}")
                    causes["hex alias (Trivy names the key)"] += 2
            locked = {(m["package"].lower(), m["version"]) for m in entries}
            for entry in list(only_cordon):
                name, _, version = entry.rpartition("@")
                if (name.lower(), version) in locked:
                    only_cordon.remove(entry)
                    causes["in the lock, unread by Trivy"] += 1
        if row["registry"] == "npmjs.org":
            only_trivy, only_cordon = cls._npm(folder, only_trivy, only_cordon, causes)
        causes["other, Trivy-only"] += len(only_trivy)
        causes["other, Cordon-only"] += len(only_cordon)
        return causes

    @staticmethod
    def _lock_text(folder: Path) -> str:
        for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
            if (folder / name).is_file():
                return (folder / name).read_text(errors="replace")
        return ""

    @staticmethod
    def _own_npm(folder: Path, text: str) -> set[str]:
        """Package names the project itself defines: package-lock entries outside node_modules,
        yarn `@workspace:` entries, and the root's own name."""
        own: set[str] = set()
        for name in ("package-lock.json", "npm-shrinkwrap.json"):
            if (folder / name).is_file():
                try:
                    packages = json.loads(text).get("packages", {})
                except ValueError:
                    packages = {}
                for key, entry in packages.items():
                    if "node_modules/" not in key and isinstance(entry, dict) and entry.get("name"):
                        own.add(entry["name"])
        own.update(m.group(1) for m in re.finditer(r'"?(@?[^@"\s]+)@workspace:', text))
        if (folder / "package.json").is_file():
            try:
                root = json.loads((folder / "package.json").read_text(errors="replace")).get("name")
            except ValueError:
                root = None
            if root:
                own.add(root)
        return own

    @classmethod
    def _npm(cls, folder: Path, only_trivy: list[str], only_cordon: list[str], causes: Counter[str]) -> tuple[list[str], list[str]]:
        text = cls._lock_text(folder)
        own = cls._own_npm(folder, text)
        for entry in list(only_trivy):
            name, _, version = entry.rpartition("@")
            twin = next((c for c in only_cordon if c.rpartition("@")[2] == version and f"npm:{c.rpartition('@')[0]}@" in text), None)
            if twin is not None and name in text:
                only_trivy.remove(entry)
                only_cordon.remove(twin)
                causes["npm alias (Trivy names the alias)"] += 2
            elif name in own:
                only_trivy.remove(entry)
                causes["project's own package (Trivy lists it)"] += 1
        for entry in list(only_cordon):
            name, _, version = entry.rpartition("@")
            if version.startswith(("file:", "link:", "workspace:")):
                only_cordon.remove(entry)
                causes["project's own package (Cordon lists it as local)"] += 1
            elif name in text and version in text:
                only_cordon.remove(entry)
                causes["in the lock, unread by Trivy"] += 1
        return only_trivy, only_cordon

    @classmethod
    def run(cls, results: Path) -> dict:
        document = json.loads(results.read_text())
        totals: Counter[str] = Counter()
        by_registry: dict[str, Counter[str]] = {}
        for row in document["lockfiles"]:
            if "f1" not in row:
                continue
            causes = cls.classify(row)
            totals.update(causes)
            by_registry.setdefault(row["registry"], Counter()).update(causes)
        disagreements = sum(totals.values())
        return {
            "disagreements": disagreements,
            "causes": dict(totals.most_common()),
            "by_registry": {k: dict(v.most_common()) for k, v in sorted(by_registry.items()) if sum(v.values())},
        }


if __name__ == "__main__":
    source = Path(sys.argv[1])
    report = Gaps.run(source)
    (source.parent / "parse-gaps.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))
