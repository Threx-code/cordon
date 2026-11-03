"""A manifest that only shares a malicious dependency's name does not make that dependency local
(notes/77-decoy-manifest-silences-dependency-intel.md).

`just-a-calculator` declared `node-calculator-x7k9 ^100.0.0`, every version of which is recorded as
malicious, and shipped `test-package/package.json` named `node-calculator-x7k9`. Any manifest's name
counted as a package the tree defines, so the dependency was marked local and no advisory was checked.
npm fetches that range from the registry, so the decoy changes nothing about what installs. Inert
manifests only.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase

EVIL = "evil-calc-x7k9"
KNOWN = "MALWARE.DEPENDENCY.KNOWN.001"
SHADOW = "SUSPECT.DEPENDENCY.LOCAL_SHADOW.001"


class DecoyKit:
    @staticmethod
    def advisory(name: str = EVIL) -> Advisory:
        """Every version of `name` recorded as malicious (an OSV MAL record with introduced 0)."""
        return Advisory(
            ecosystem="npm",
            name=name,
            versions=(),
            summary=f"Malicious code in {name} (npm)",
            identifier="MAL-2026-0077",
            severity="critical",
            malicious=True,
            introduced="0",
        )

    @staticmethod
    def manifest(name: str, version: str = "1.0.0", **extra: object) -> str:
        return json.dumps({"name": name, "version": version, **extra})

    @staticmethod
    def rules(target: Path) -> set[str]:
        config = Config.default().with_overrides(use_cache=False, offline=True)
        scanner = Scanner(
            config, detectors=(AdvisoryDetector(AdvisoryDatabase((DecoyKit.advisory(),))),)
        )
        return {f.rule_id for f in scanner.scan(target).findings}

    @staticmethod
    def tree(root: Path, files: dict[str, str]) -> Path:
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return root

    @staticmethod
    def package(tmp_path: Path, files: dict[str, str]) -> Path:
        """A published npm tarball holding `files` under `package/`."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for rel, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{rel}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / "calc-demo-1.0.1.tgz"
        path.write_bytes(buf.getvalue())
        return path

    @staticmethod
    def root(dependency_spec: str = "^100.0.0", **extra: object) -> str:
        return DecoyKit.manifest(
            "calc-demo", "1.0.1", dependencies={EVIL: dependency_spec}, **extra
        )


class TestInAPublishedPackage:
    def test_a_decoy_manifest_named_for_the_dependency_does_not_silence_it(self, tmp_path) -> None:
        tgz = DecoyKit.package(
            tmp_path,
            {
                "package.json": DecoyKit.root(),
                "test-package/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )
        assert KNOWN in DecoyKit.rules(tgz)

    def test_nor_does_the_package_declaring_the_decoy_a_workspace(self, tmp_path) -> None:
        # A published package's own `workspaces` is the attacker's text, and no install of it as a
        # dependency resolves workspaces: the consumer fetches the range from the registry.
        tgz = DecoyKit.package(
            tmp_path,
            {
                "package.json": DecoyKit.root(workspaces=["test-package"]),
                "test-package/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )
        assert KNOWN in DecoyKit.rules(tgz)

    def test_a_path_spec_stays_local_and_is_named_for_its_malicious_namesake(
        self, tmp_path
    ) -> None:
        tgz = DecoyKit.package(
            tmp_path,
            {
                "package.json": DecoyKit.root("file:./test-package"),
                "test-package/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )
        rules = DecoyKit.rules(tgz)
        assert KNOWN not in rules and SHADOW in rules


class TestInARepository:
    def test_a_stray_manifest_does_not_silence_it(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root(),
                "test-package/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )
        assert KNOWN in DecoyKit.rules(tmp_path)

    def test_a_declared_member_that_satisfies_the_range_is_local_and_named(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root(workspaces=["packages/*"]),
                "packages/calc/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )
        rules = DecoyKit.rules(tmp_path)
        assert KNOWN not in rules and SHADOW in rules

    def test_a_declared_member_outside_the_range_is_fetched_and_reported(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root(workspaces=["packages/*"]),
                "packages/calc/package.json": DecoyKit.manifest(EVIL, "1.0.0"),
            },
        )
        assert KNOWN in DecoyKit.rules(tmp_path)

    def test_a_pnpm_workspace_member_is_local(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root("*"),
                "pnpm-workspace.yaml": "packages:\n  - 'libs/*'\n",
                "libs/calc/package.json": DecoyKit.manifest(EVIL, "3.0.0"),
            },
        )
        rules = DecoyKit.rules(tmp_path)
        assert KNOWN not in rules and SHADOW in rules

    def test_a_lerna_member_is_local(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root("*"),
                "lerna.json": json.dumps({"packages": ["modules/*"]}),
                "modules/calc/package.json": DecoyKit.manifest(EVIL, "3.0.0"),
            },
        )
        assert KNOWN not in DecoyKit.rules(tmp_path)

    def test_an_excluded_directory_is_no_member(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root("*", workspaces=["packages/*", "!packages/calc"]),
                "packages/calc/package.json": DecoyKit.manifest(EVIL, "3.0.0"),
            },
        )
        assert KNOWN in DecoyKit.rules(tmp_path)

    def test_a_nested_root_with_its_own_lockfile_does_not_silence_it(self, tmp_path) -> None:
        # A directory with its own lockfile is a standalone workspace to its package manager, but
        # nothing at the root resolves to it: the range is still fetched from the registry.
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.root(),
                "examples/demo/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
                "examples/demo/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
            },
        )
        assert KNOWN in DecoyKit.rules(tmp_path)

    def test_an_ordinary_workspace_stays_quiet(self, tmp_path) -> None:
        DecoyKit.tree(
            tmp_path,
            {
                "package.json": DecoyKit.manifest(
                    "app", workspaces=["packages/*"], dependencies={"core": "*"}
                ),
                "packages/core/package.json": DecoyKit.manifest("core", "2.0.0"),
            },
        )
        rules = DecoyKit.rules(tmp_path)
        assert KNOWN not in rules and SHADOW not in rules


class TestAPathSpecInARepository:
    """A repository's dependency declared by path resolves inside the tree and never from the
    registry, so its malicious namesake cannot be what installs: no shadow warning (rushstack's
    `workspace:*`, nx's `link:`, measured 194 of 195 on the 31-repo pair). Any other spec stays said."""

    @staticmethod
    def member_tree(root: Path, spec: str) -> Path:
        return DecoyKit.tree(
            root,
            {
                "package.json": DecoyKit.root(spec, workspaces=["packages/*"]),
                "packages/calc/package.json": DecoyKit.manifest(EVIL, "100.0.2"),
            },
        )

    @pytest.mark.parametrize(
        "spec", ["workspace:*", "link:./packages/calc", "file:./packages/calc"]
    )
    def test_a_path_declared_member_is_not_warned(self, tmp_path, spec) -> None:
        rules = DecoyKit.rules(TestAPathSpecInARepository.member_tree(tmp_path, spec))
        assert KNOWN not in rules and SHADOW not in rules

    # A URL or git spec names no registry release, so the registry record raises nothing on it before
    # or after this change; the predicate test below keeps it outside the quieting.
    @pytest.mark.parametrize("spec", [f"npm:{EVIL}@100.0.2", "catalog:", "^100.0.0"])
    def test_a_spec_that_resolves_from_the_registry_is_still_said(self, tmp_path, spec) -> None:
        rules = DecoyKit.rules(TestAPathSpecInARepository.member_tree(tmp_path, spec))
        assert rules & {KNOWN, SHADOW}

    @pytest.mark.parametrize(
        ("spec", "by_path"),
        [
            ("workspace:*", True),
            ("workspace:^1.0.0", True),
            ("link:../x", True),
            ("file:./x", True),
            ("portal:./x", True),
            ("https://example.invalid/x.tgz", False),
            ("http://example.invalid/x.tgz", False),
            ("git+ssh://example.invalid/x.git", False),
            ("git://example.invalid/x.git", False),
            ("github:o/r", False),
            ("npm:other@1.0.0", False),
            ("catalog:", False),
            ("^1.0.0", False),
            ("", False),
            (None, False),
            ("  workspace:*", False),
            ("filed:x", False),
        ],
    )
    def test_the_predicate_matches_only_the_four_path_prefixes(self, spec, by_path) -> None:
        assert AdvisoryDetector.declared_by_path(spec) is by_path
