"""npm manifest confusion: the registry's manifest against the tarball's own package.json.

And the release comparison's fetches, which take a URL the packument chose and so must stay on
the registry's own file hosts.
"""

from __future__ import annotations

import argparse
import io
import json
import tarfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.core.manifest_confusion import RULE_ID, ManifestConfusion
from cordon_scanner.core.models import Severity
from cordon_scanner.intel.registry_client import RegistryClient, RegistryError
from cordon_scanner.sources.previous import Identity, PreviousRelease


class Tarballs:
    BASE: ClassVar[dict[str, Any]] = {
        "name": "left-pad",
        "version": "1.3.0",
        "dependencies": {"a": "^1.0.0"},
    }

    @staticmethod
    def write(path: Path, members: dict[str, bytes]) -> Path:
        with tarfile.open(path, "w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    @classmethod
    def npm(cls, tmp_path: Path, manifest: dict[str, Any]) -> Path:
        return cls.write(
            tmp_path / "left-pad-1.3.0.tgz",
            {
                "package/package.json": json.dumps(manifest).encode(),
                "package/index.js": b"module.exports=1",
            },
        )


class TestDifferences:
    def test_identical_manifests_agree(self):
        assert ManifestConfusion.differences(dict(Tarballs.BASE), dict(Tarballs.BASE)) == []

    def test_an_install_script_only_the_tarball_has_is_reported(self):
        packaged = {**Tarballs.BASE, "scripts": {"postinstall": "node steal.js", "test": "jest"}}
        found = ManifestConfusion.differences(dict(Tarballs.BASE), packaged)
        assert [d.field for d in found] == ["scripts.postinstall"]
        assert found[0].packaged == "node steal.js" and found[0].registry == ""

    def test_scripts_that_do_not_run_at_install_are_not_compared(self):
        packaged = {**Tarballs.BASE, "scripts": {"test": "jest", "prepare": "tsc"}}
        assert ManifestConfusion.differences(dict(Tarballs.BASE), packaged) == []

    def test_a_dependency_only_the_registry_names_is_reported(self):
        registry = {**Tarballs.BASE, "dependencies": {"a": "^1.0.0", "evil": "1.0.0"}}
        assert [d.field for d in ManifestConfusion.differences(registry, dict(Tarballs.BASE))] == [
            "dependencies"
        ]

    def test_a_changed_registry_range_is_reported(self):
        registry = {**Tarballs.BASE, "dependencies": {"a": "^2.0.0"}}
        assert ManifestConfusion.differences(registry, dict(Tarballs.BASE))

    def test_name_and_version_disagreements_are_reported(self):
        packaged = {**Tarballs.BASE, "name": "left-pad-real", "version": "9.9.9"}
        assert {d.field for d in ManifestConfusion.differences(dict(Tarballs.BASE), packaged)} == {
            "name",
            "version",
        }

    def test_npms_injected_node_gyp_install_is_not_a_disagreement(self):
        registry = {**Tarballs.BASE, "scripts": {"install": "node-gyp rebuild"}, "gypfile": True}
        assert ManifestConfusion.differences(registry, dict(Tarballs.BASE)) == []

    def test_a_different_install_script_beside_gyp_still_counts(self):
        registry = {**Tarballs.BASE, "scripts": {"install": "node-gyp rebuild"}}
        packaged = {**Tarballs.BASE, "scripts": {"install": "curl x | sh"}}
        assert [d.field for d in ManifestConfusion.differences(registry, packaged)] == [
            "scripts.install"
        ]

    def test_a_bin_string_and_its_normalised_object_agree(self):
        packaged = {**Tarballs.BASE, "bin": "./cli.js"}
        registry = {**Tarballs.BASE, "bin": {"left-pad": "cli.js"}}
        assert ManifestConfusion.differences(registry, packaged) == []

    def test_a_scoped_bin_string_is_named_after_the_bare_name(self):
        packaged = {"name": "@acme/tool", "version": "1.0.0", "bin": "bin/tool.js"}
        registry = {"name": "@acme/tool", "version": "1.0.0", "bin": {"tool": "bin/tool.js"}}
        assert ManifestConfusion.differences(registry, packaged) == []

    def test_an_extra_command_on_the_path_is_reported(self):
        registry = {**Tarballs.BASE, "bin": {"left-pad": "cli.js"}}
        packaged = {**Tarballs.BASE, "bin": {"left-pad": "cli.js", "npm": "hijack.js"}}
        assert [d.field for d in ManifestConfusion.differences(registry, packaged)] == ["bin"]

    def test_optional_dependencies_merged_into_dependencies_agree(self):
        packaged = {**Tarballs.BASE, "optionalDependencies": {"fsevents": "^2.0.0"}}
        registry = {
            **Tarballs.BASE,
            "dependencies": {"a": "^1.0.0", "fsevents": "^2.0.0"},
            "optionalDependencies": {"fsevents": "^2.0.0"},
        }
        assert ManifestConfusion.differences(registry, packaged) == []

    def test_bundle_dependencies_true_names_every_dependency(self):
        packaged = {**Tarballs.BASE, "bundleDependencies": True}
        registry = {**Tarballs.BASE, "bundleDependencies": ["a"]}
        assert ManifestConfusion.differences(registry, packaged) == []

    def test_a_leading_v_and_git_shorthand_rewrites_agree(self):
        packaged = {"name": "x", "version": "v1.0.0", "dependencies": {"g": "acme/g"}}
        registry = {"name": "x", "version": "1.0.0", "dependencies": {"g": "github:acme/g"}}
        assert ManifestConfusion.differences(registry, packaged) == []

    @pytest.mark.parametrize("garbage", [None, 7, "text", ["a"], {"scripts": "nope"}])
    def test_malformed_fields_never_raise(self, garbage):
        registry = {
            "name": "x",
            "version": "1",
            "scripts": garbage,
            "dependencies": garbage,
            "bin": garbage,
        }
        ManifestConfusion.differences(registry, {"name": "x", "version": "1"})


class TestPackaged:
    def test_reads_the_top_level_package_json(self, tmp_path):
        assert ManifestConfusion.packaged(Tarballs.npm(tmp_path, Tarballs.BASE)) == Tarballs.BASE

    def test_ignores_a_nested_package_json(self, tmp_path):
        path = Tarballs.write(
            tmp_path / "x.tgz",
            {"package/node_modules/y/package.json": b'{"name":"y","version":"1"}'},
        )
        assert ManifestConfusion.packaged(path) is None

    def test_refuses_an_oversized_manifest(self, tmp_path):
        path = Tarballs.write(tmp_path / "x.tgz", {"package/package.json": b" " * ((1 << 20) + 1)})
        assert ManifestConfusion.packaged(path) is None

    @pytest.mark.parametrize("body", [b"not json", b"[1,2]"])
    def test_an_unreadable_manifest_is_none(self, tmp_path, body):
        assert (
            ManifestConfusion.packaged(
                Tarballs.write(tmp_path / "x.tgz", {"package/package.json": body})
            )
            is None
        )

    def test_a_non_tarball_and_a_corrupt_one_are_none(self, tmp_path):
        (tmp_path / "x.whl").write_bytes(b"PK")
        (tmp_path / "y.tgz").write_bytes(b"\x1f\x8bnot really")
        assert ManifestConfusion.packaged(tmp_path / "x.whl") is None
        assert ManifestConfusion.packaged(tmp_path / "y.tgz") is None


class TestCheck:
    def test_a_hidden_install_script_is_critical(self, tmp_path, monkeypatch):
        asked: list[str] = []
        monkeypatch.setattr(
            RegistryClient,
            "_fetch",
            staticmethod(lambda url, **_: asked.append(url) or dict(Tarballs.BASE)),
        )
        path = Tarballs.npm(tmp_path, {**Tarballs.BASE, "scripts": {"preinstall": "node x.js"}})
        [finding] = ManifestConfusion.check(path)
        assert finding.rule_id == RULE_ID and finding.severity is Severity.CRITICAL
        assert finding.location.path == "left-pad-1.3.0.tgz!package/package.json"
        assert "node x.js" in finding.message
        assert asked == ["https://registry.npmjs.org/left-pad/1.3.0"]

    def test_a_dependency_difference_is_high(self, tmp_path, monkeypatch):
        registry = {**Tarballs.BASE, "dependencies": {}}
        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(lambda url, **_: registry))
        [finding] = ManifestConfusion.check(Tarballs.npm(tmp_path, Tarballs.BASE))
        assert finding.severity is Severity.HIGH

    def test_agreement_and_an_unanswered_registry_report_nothing(self, tmp_path, monkeypatch):
        path = Tarballs.npm(tmp_path, Tarballs.BASE)
        monkeypatch.setattr(
            RegistryClient, "_fetch", staticmethod(lambda url, **_: dict(Tarballs.BASE))
        )
        assert ManifestConfusion.check(path) == []

        def refuse(url, **_):
            raise RegistryError("HTTP 503")

        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(refuse))
        assert ManifestConfusion.check(path) == []

    def test_a_scoped_name_is_asked_with_its_scope(self, tmp_path, monkeypatch):
        asked: list[str] = []
        manifest = {"name": "@acme/x", "version": "1.0.0"}
        monkeypatch.setattr(
            RegistryClient, "_fetch", staticmethod(lambda url, **_: asked.append(url) or manifest)
        )
        ManifestConfusion.check(Tarballs.npm(tmp_path, manifest))
        assert asked == ["https://registry.npmjs.org/@acme/x/1.0.0"]

    def test_the_check_runs_only_online(self, tmp_path):
        from cordon_scanner.cli.main import CommandLine

        result = object()
        args = argparse.Namespace(online=False, offline=False)
        assert (
            CommandLine._with_manifest_confusion(
                args, Tarballs.npm(tmp_path, Tarballs.BASE), result, None
            )
            is result
        )


class TestPreviousReleaseFetches:
    def test_a_tarball_url_off_the_registry_hosts_is_refused_before_any_request(self):
        with pytest.raises(ValueError, match="allowlist"):
            PreviousRelease._artefact("https://attacker.example/left-pad.tgz", "npm")
        with pytest.raises(ValueError, match="allowlist"):
            PreviousRelease._artefact("http://registry.npmjs.org/left-pad.tgz", "npm")

    def test_a_release_with_only_a_legacy_sha1_is_not_trusted(self, tmp_path, monkeypatch):
        packument = {
            "time": {"1.0.0": "2020-01-01T00:00:00Z", "1.1.0": "2021-01-01T00:00:00Z"},
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                        "shasum": "0" * 40,
                    }
                },
                "1.1.0": {"dist": {}},
            },
        }
        monkeypatch.setattr(PreviousRelease, "_document", staticmethod(lambda url: packument))
        monkeypatch.setattr(PreviousRelease, "_artefact", staticmethod(lambda url, eco: b"blob"))
        with pytest.raises(ValueError, match="sha512"):
            PreviousRelease.fetch_previous(Identity("npm", "x", "1.1.0"), tmp_path)

    def test_a_registry_chosen_filename_stays_inside_the_workspace(self):
        assert "/" not in PreviousRelease._safe("../../etc/evil.whl")
        assert PreviousRelease._safe("../../etc/evil.whl").endswith(".whl")
