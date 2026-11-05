"""Published packages with nothing in them but a name (review 98, REC-4).

Fixtures are inert: install hooks only echo, hosts are reserved names, nothing would run.
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.detect.supply.name_risk import (
    RULE,
    NameRisk,
    NameSignals,
    PackageIdentity,
)
from cordon_scanner.foundation.config.settings import Config


class Identities:
    """An ordinary, well-described release, changed only where a test says so."""

    @staticmethod
    def of(**overrides: object) -> PackageIdentity:
        base = PackageIdentity(
            ecosystem="npm",
            name="harmless-widget",
            version="1.2.3",
            description="Draws a widget",
            has_source=True,
            hooks=(),
            code_files=5,
            hook_runs_file=False,
        )
        return replace(base, **overrides)


class Releases:
    """Build a published npm tarball or Python sdist in a temporary directory, and scan it."""

    @staticmethod
    def tarball(tmp_path: Path, files: dict[str, str], name: str = "pkg-1.0.0.tgz") -> Path:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / name
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def npm(
        tmp_path: Path, manifest: dict[str, object], extra: dict[str, str] | None = None
    ) -> Path:
        files = {"package/package.json": json.dumps(manifest), **(extra or {})}
        return Releases.tarball(tmp_path, files)

    @staticmethod
    def findings(target: Path) -> list:
        config = Config.default().with_overrides(use_cache=False)
        return [f for f in Scanner(config).scan(target).findings if f.rule_id == RULE]

    @staticmethod
    def blocked(target: Path) -> bool:
        config = Config.default().with_overrides(use_cache=False)
        report = Scanner(config).scan(target)
        return any(f.rule_id == RULE for f in PolicyGate.evaluate(report, config.policy).triggering)


class TestConfusionVersion:
    @pytest.mark.parametrize(
        "version", ["99.0.0", "999.9.9", "1000.0.16", "9999.1.0", "11.11.11", "7.7.7", "9.9.0"]
    )
    def test_versions_chosen_to_outrank_a_private_registry(self, version: str) -> None:
        assert NameSignals.confusion_version(version) is not None

    @pytest.mark.parametrize(
        "version", ["1.0.0", "2.2.2", "3.3.3", "10.1.0", "2024.10.1", "202606.4.3555", "0.0.1"]
    )
    def test_ordinary_and_calendar_versions_are_not(self, version: str) -> None:
        assert NameSignals.confusion_version(version) is None


class TestTheTable:
    def test_a_confusion_probe_with_nothing_in_it_blocks(self) -> None:
        # The shape of DataDog's `@rb3ca/domains` 11.11.11 and `agora-node-rtm` 7.7.7.
        probe = Identities.of(
            name="@example-corp/domains",
            version="11.11.11",
            description="",
            has_source=False,
            hooks=(("preinstall", 'echo "poc possible by example"'),),
            code_files=0,
        )
        verdict = NameRisk.assess(probe)
        assert verdict is not None and verdict.blocks
        assert {"confusion-version", "says-research", "hook-only-prints", "empty"} <= {
            s.id for s in verdict.signals
        }

    def test_a_strong_name_with_code_in_it_only_warns(self) -> None:
        # The name is suspicious, but the package has code: the content rules judge that code.
        verdict = NameRisk.assess(Identities.of(version="99.0.0", has_source=False, code_files=12))
        assert verdict is None or not verdict.blocks

    def test_a_named_source_keeps_it_below_the_gate(self) -> None:
        verdict = NameRisk.assess(Identities.of(version="99.0.0", code_files=0, description=""))
        assert verdict is not None and not verdict.blocks

    def test_a_defensive_placeholder_is_not_blocked(self) -> None:
        holder = Identities.of(
            version="99.0.0",
            description="Reserved to prevent dependency confusion",
            has_source=False,
            code_files=0,
        )
        verdict = NameRisk.assess(holder)
        assert verdict is None or not verdict.blocks

    @pytest.mark.parametrize(
        "description",
        [
            "Tombstone, project withdrawn from public distribution.",
            "REMOVED - this package was published in error",
            "This package is no longer maintained or supported.",
            "Migration package.",
            "For questions reach out to security@example.com",
        ],
    )
    def test_a_name_its_owner_retired_is_not_blocked(self, description: str) -> None:
        retired = Identities.of(
            version="9999.0.0", description=description, has_source=False, code_files=0
        )
        verdict = NameRisk.assess(retired)
        assert verdict is None or not verdict.blocks

    def test_an_install_hook_that_sends_the_installer_to_a_private_registry(self) -> None:
        # The company's own guard: installing from the public registry fails on purpose.
        guard = Identities.of(
            name="example-corp-internal-api",
            version="0.0.0",
            description="",
            has_source=False,
            hooks=(("postinstall", "echo please use the private registry && exit 1"),),
            code_files=0,
        )
        verdict = NameRisk.assess(guard)
        assert verdict is None or not verdict.blocks

    def test_a_placeholder_in_the_name_is_a_holding_claim(self) -> None:
        held = Identities.of(
            name="@example-wms-internal/placeholder",
            version="1.0.0",
            description="",
            has_source=False,
            code_files=0,
        )
        verdict = NameRisk.assess(held)
        assert verdict is None or not verdict.blocks

    def test_a_probe_that_names_itself_a_placeholder_still_blocks(self) -> None:
        # Only the description outranks a probe's own words; a name or a hook does not.
        probe = Identities.of(
            name="@example-corp/placeholder",
            version="11.11.11",
            description="dependency confusion poc",
            has_source=False,
            hooks=(("preinstall", 'echo "poc possible by example"'),),
            code_files=0,
        )
        verdict = NameRisk.assess(probe)
        assert verdict is not None and verdict.blocks

    def test_npm_security_placeholders_are_left_to_the_release_check(self) -> None:
        holding = Identities.of(
            version="0.0.1-security",
            description="security holding package",
            has_source=False,
            code_files=0,
            placeholder=True,
        )
        assert NameRisk.assess(holding) is None

    def test_an_ordinary_package_says_nothing(self) -> None:
        assert NameRisk.assess(Identities.of()) is None

    def test_a_meta_package_is_not_empty(self) -> None:
        meta = Identities.of(version="99.0.0", has_source=False, code_files=0, dependencies=3)
        verdict = NameRisk.assess(meta)
        assert verdict is None or not verdict.blocks

    def test_an_organisations_name_outside_its_scope_counts_as_name_evidence(self) -> None:
        squat = Identities.of(name="shopify-internal-widget-helpers")
        ids = {s.id for s in NameRisk.signals(squat)}
        assert "organisation-name" in ids and "internal-name" in ids

    def test_a_typosquat_of_a_popular_name_is_name_evidence(self) -> None:
        ids = {s.id for s in NameRisk.signals(Identities.of(name="lodahs"))}
        assert "typosquat-deliberate" in ids

    def test_a_plugin_naming_convention_is_not_an_organisation(self) -> None:
        # `babel-preset-*` is how Babel's ecosystem names plugins, not a squat of `@babel`.
        ids = {s.id for s in NameRisk.signals(Identities.of(name="babel-preset-widget"))}
        assert "organisation-name" not in ids

    def test_the_weights_are_the_documented_table(self) -> None:
        # Every signal the code can raise has a weight, so the table is the whole story.
        raised = {
            s.id
            for s in NameRisk.signals(
                Identities.of(
                    name="shopify-internal-widget",
                    version="99.0.0",
                    description="",
                    has_source=False,
                    code_files=0,
                    hooks=(("postinstall", "echo hi"),),
                )
            )
        }
        assert raised <= set(NameRisk.WEIGHTS)


class TestPublishedPackages:
    def test_an_inert_confusion_probe_tarball_is_blocked(self, tmp_path: Path) -> None:
        target = Releases.npm(
            tmp_path,
            {
                "name": "@example-corp/domains",
                "version": "11.11.11",
                "scripts": {"preinstall": 'echo "poc possible by example"'},
            },
        )
        found = Releases.findings(target)
        assert [f.severity.name for f in found] == ["HIGH"]
        assert Releases.blocked(target)

    def test_a_real_looking_package_with_code_is_not_reported(self, tmp_path: Path) -> None:
        target = Releases.npm(
            tmp_path,
            {
                "name": "harmless-widget",
                "version": "1.2.3",
                "description": "Draws a widget",
                "repository": "https://example.invalid/widget.git",
            },
            {"package/index.js": "module.exports = 1;\n", "package/lib/a.js": "exports.a = 1;\n"},
        )
        assert Releases.findings(target) == []

    def test_a_working_tree_is_never_a_release(self, tmp_path: Path) -> None:
        # The same manifest as a project's own, in a directory being developed: an empty new
        # project is not a probe, and only releases are read.
        root = tmp_path / "project"
        (root / ".git").mkdir(parents=True)
        (root / "package.json").write_text(
            json.dumps({"name": "@example-corp/domains", "version": "11.11.11"}), encoding="utf-8"
        )
        assert Releases.findings(root) == []

    def test_an_sdist_is_read_from_its_pkg_info(self, tmp_path: Path) -> None:
        pkg_info = (
            "Metadata-Version: 2.1\nName: example-corp-internal-tools\nVersion: 99.0.0\n"
            "Summary: \n\n"
        )
        target = Releases.tarball(
            tmp_path,
            {
                "example-corp-internal-tools-99.0.0/PKG-INFO": pkg_info,
                "example-corp-internal-tools-99.0.0/setup.py": (
                    "from setuptools import setup\n"
                    "setup(name='example-corp-internal-tools', version='99.0.0')\n"
                ),
            },
            name="example-corp-internal-tools-99.0.0.tar.gz",
        )
        found = Releases.findings(target)
        assert [f.severity.name for f in found] == ["HIGH"]
