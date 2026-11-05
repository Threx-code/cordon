"""The index's shortcuts answer exactly what the linear scan answers.

Two were added when a warm 50,000-file scan went from 5.0s to 12.5s: each path's answer is
remembered, and a residual pattern is skipped when the file name cannot start and end the way
the pattern's last segment requires. Both are only safe if no answer changes, so this builds
names from every residual pattern -- matching ones, and near misses on each side -- and asks
both forms about each.
"""

from __future__ import annotations

import itertools

from cordon_scanner.ecosystems.registry import EcosystemRegistry, _GlobIndex

FILLERS = ("", "x", "dev", "a.b", "-", ".")
DIRECTORIES = ("", "src/", "a/b/", "k8s/", "deploy/prod/", ".github/workflows/")


class Corpus:
    @staticmethod
    def names(pattern: str) -> set[str]:
        last = pattern.rpartition("/")[2]
        found = {last}
        if "*" in last:
            for filler in FILLERS:
                found.add(last.replace("*", filler))
        # Near misses: the name with its first or last character changed.
        for name in list(found):
            if name:
                found.add("Z" + name[1:])
                found.add(name[:-1] + "Z")
                found.add(name + ".bak")
        return {n for n in found if n and "/" not in n}

    @staticmethod
    def paths() -> set[str]:
        patterns = [
            p
            for index in (EcosystemRegistry.manifest_index(), EcosystemRegistry.lockfile_index())
            for p, _ in index.residual
        ]
        paths: set[str] = {"index.js", "src/app/main.py", "README.md", "k8s/app.js"}
        for pattern in patterns:
            middle = pattern.removeprefix("**/").rpartition("/")[0]
            middle = middle.replace("**/", "").replace("**", "").replace("*", "x")
            for name, directory in itertools.product(Corpus.names(pattern), DIRECTORIES):
                paths.add(f"{directory}{middle + '/' if middle else ''}{name}")
                paths.add(f"{directory}{name}")
        return paths


class TestTheShortcutsChangeNoAnswer:
    def test_manifests(self) -> None:
        for path in sorted(Corpus.paths()):
            assert EcosystemRegistry.manifest_ecosystem(
                path
            ) == EcosystemRegistry.manifest_ecosystem_scan(path), path

    def test_lockfiles(self) -> None:
        for path in sorted(Corpus.paths()):
            assert EcosystemRegistry.lockfile_ecosystem(
                path
            ) == EcosystemRegistry.lockfile_ecosystem_scan(path), path

    def test_a_remembered_answer_is_the_same_answer(self) -> None:
        for path in sorted(Corpus.paths()):
            first = EcosystemRegistry.manifest_ecosystem(path)
            assert EcosystemRegistry.manifest_ecosystem(path) == first, path


class TestNameBounds:
    def test_what_a_last_segment_fixes(self) -> None:
        assert _GlobIndex._name_bounds("**/k8s/**/*.yaml") == ("", ".yaml")
        assert _GlobIndex._name_bounds("**/requirements*.txt") == ("requirements", ".txt")
        assert _GlobIndex._name_bounds("**/profiles/default") == ("default", "default")
        assert _GlobIndex._name_bounds("**/conan/profiles/*") == ("", "")
        assert _GlobIndex._name_bounds("**/a[bc]d.txt") == ("a", "d.txt")
