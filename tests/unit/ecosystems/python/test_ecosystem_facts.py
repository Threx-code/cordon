"""Each ecosystem's declared facts (`foundation.dependencies` naming, versions, traits) answer exactly
what the 14-branch chain in DependencyIdentity.namespace and the inline version rules did."""

from __future__ import annotations

import re
from typing import ClassVar

from cordon_scanner.foundation.dependencies import DependencyIdentity, EcosystemFactsProvider


class OldChain:
    """DependencyIdentity.namespace as it was (0f52b160), kept here as the reference."""

    @staticmethod
    def namespace(ecosystem: str, name: str) -> str | None:
        if not name:
            return None
        if ecosystem == "npm":
            return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None
        if ecosystem in ("maven", "gradle"):
            return name.split(":", 1)[0] if ":" in name else None
        if ecosystem == "composer":
            return name.split("/", 1)[0] if "/" in name else None
        if ecosystem in ("gomod", "swift", "nix"):
            return name.rsplit("/", 1)[0] if "/" in name else None
        if ecosystem == "actions":
            return name.split("/", 1)[0] if "/" in name else None
        if ecosystem in ("ansible", "vscode"):
            return name.split(".", 1)[0] if "." in name else None
        if ecosystem == "terraform":
            parts = name.split("/")
            return parts[-2] if len(parts) >= 2 else None
        if ecosystem == "image":
            return name.rsplit("/", 1)[0] if "/" in name else None
        if ecosystem == "homebrew":
            return name.rsplit("/", 1)[0] if name.count("/") >= 2 else None
        if ecosystem == "conda":
            return name.split("::", 1)[0] if "::" in name else None
        if ecosystem == "hex":
            return name.split("/", 1)[0] if "/" in name else None
        return None


class FactsKit:
    ECOSYSTEMS: ClassVar[tuple[str, ...]] = (
        "npm",
        "maven",
        "gradle",
        "composer",
        "gomod",
        "swift",
        "nix",
        "actions",
        "ansible",
        "vscode",
        "terraform",
        "image",
        "homebrew",
        "conda",
        "hex",
        "pypi",
        "cargo",
        "nuget",
        "rubygems",
        "unknown-eco",
        "",
    )
    NAMES: ClassVar[tuple[str, ...]] = (
        "",
        "plain",
        "@scope/pkg",
        "@scope",
        "group:artifact",
        "a:b:c",
        "vendor/pkg",
        "github.com/owner/repo",
        "github.com/owner/repo/v2",
        "owner/repo",
        "owner/repo/path",
        "pub.name",
        "a.b.c",
        "hashicorp/aws",
        "registry/ns/name",
        "user/tap/formula",
        "conda-forge::numpy",
        "org/pkg",
        "steps-build",
        "x/steps-y",
    )


class TestTheDeclaredFacts:
    def test_namespace_is_the_old_chain_for_every_ecosystem_and_name(self) -> None:
        naming = EcosystemFactsProvider.naming()
        for eco in FactsKit.ECOSYSTEMS:
            for name in FactsKit.NAMES:
                want = OldChain.namespace(eco, name)
                assert naming.namespace(eco, name) == want, (eco, name)
                assert DependencyIdentity.namespace(eco, name) == want, (eco, name)

    def test_a_homebrew_tap_comes_from_the_alias(self) -> None:
        naming = EcosystemFactsProvider.naming()
        # results.Dependency.namespace used the alias for homebrew only, when one was set.
        for eco in FactsKit.ECOSYSTEMS:
            for name in FactsKit.NAMES:
                for alias in (None, "", "user/tap/formula"):
                    used = alias if eco == "homebrew" and alias else name
                    assert naming.namespace(eco, name, alias) == OldChain.namespace(eco, used)

    def test_the_version_and_trait_rules(self) -> None:
        versions = EcosystemFactsProvider.versions()
        traits = EcosystemFactsProvider.traits()
        naming = EcosystemFactsProvider.naming()
        for eco in FactsKit.ECOSYSTEMS:
            assert versions.pinned_by_digest(eco) == (eco == "image")
            for version in ("1.0", "1.0-SNAPSHOT", "1.0-snapshot", "SNAPSHOT"):
                assert versions.is_mutable_version(eco, version) == (
                    eco in ("maven", "gradle") and version.upper().endswith("-SNAPSHOT")
                )
            for spec in ("", "1.2.3", "[1.2.3]", "[1.0,2.0)"):
                assert versions.admits_lowest(eco, spec) == (
                    eco == "nuget" and bool(spec) and not spec.startswith("[")
                )
            for version in ("0.0.1-security", "1.2.3-security", "1.2.3", "0.0.1-security.1", ""):
                old = eco == "npm" and bool(re.match(r"^\d+\.\d+\.\d+-security$", version))
                assert versions.is_held_version(eco, version) == old
            assert traits.has_install_scripts(eco) == (eco == "npm")
            assert traits.has_scoped_names(eco) == (eco == "npm")
            assert traits.squat_comparisons(eco) == (
                ("pypi", "rubygems", "cargo") if eco == "npm" else ("npm", "cargo")
            )
            for name in FactsKit.NAMES:
                assert traits.is_ci_step(eco, name) == (
                    eco == "actions" and name.startswith("steps-")
                )
                assert naming.is_builtin(eco, name) == (eco == "gomod" and name == "stdlib")
            assert naming.is_builtin("gomod", "stdlib")
            assert naming.coordinate_separator(eco) == (":" if eco in ("maven", "gradle") else None)
