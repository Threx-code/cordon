"""A published package that installs a dependency from a URL (review 98, REC-3: PhantomRaven)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

SUSPECT = "SUSPECT.DEPENDENCY.REMOTE_TARBALL.001"
MALWARE = "MALWARE.DEPENDENCY.REMOTE_TARBALL.001"


class TarballKit:
    @staticmethod
    def manifest(spec: str) -> str:
        return json.dumps({"name": "p", "version": "1.0.0", "dependencies": {"helper": spec}})

    @staticmethod
    def published(tmp_path: Path, spec: str) -> set[str]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("package/package.json", TarballKit.manifest(spec)),
                ("package/index.js", "module.exports = 1;\n"),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return TarballKit.rules(target)

    @staticmethod
    def rules(target: Path) -> set[str]:
        return {f.rule_id for f in TarballKit.findings(target)}

    @staticmethod
    def findings(target: Path) -> list:
        return list(Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings)

    @staticmethod
    def severity(tmp_path: Path, spec: str) -> str | None:
        TarballKit.published(tmp_path, spec)
        found = [
            f
            for f in TarballKit.findings(tmp_path / "p-1.0.0.tgz")
            if f.rule_id in (SUSPECT, MALWARE)
        ]
        return found[0].severity.name if found else None


class TestRemoteTarball:
    def test_a_url_on_an_unknown_host_is_suspect(self, tmp_path: Path) -> None:
        rules = TarballKit.published(tmp_path, "https://files.example.invalid/helper.tgz")
        assert SUSPECT in rules and MALWARE not in rules

    def test_a_raw_address_is_malware(self, tmp_path: Path) -> None:
        assert MALWARE in TarballKit.published(tmp_path, "http://203.0.113.7/helper.tgz")

    def test_a_git_dependency_is_not_this_rule(self, tmp_path: Path) -> None:
        rules = TarballKit.published(tmp_path, "git+https://github.com/example/helper.git")
        assert not {SUSPECT, MALWARE} & rules

    def test_a_repository_keeps_the_policy_rule_for_a_release(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            TarballKit.manifest("https://cdn.example.invalid/helper-1.2.3.tgz"), encoding="utf-8"
        )
        rules = TarballKit.rules(tmp_path)
        assert "POLICY.DEPENDENCY.SOURCE.001" in rules and not {SUSPECT, MALWARE} & rules

    def test_a_repository_warns_on_the_malware_shape(self, tmp_path: Path) -> None:
        # A server cloned and run from its source: a version-less endpoint off any code host is
        # what the host serves on each install, a warning one step below the published grade.
        (tmp_path / "package.json").write_text(
            TarballKit.manifest("https://files.example.invalid/helper.tgz"), encoding="utf-8"
        )
        found = [f for f in TarballKit.findings(tmp_path) if f.rule_id == SUSPECT]
        assert [f.severity.name for f in found] == ["MEDIUM"]
        assert "every install of this project fetches it" in found[0].message

    def test_a_repository_on_a_drop_point_host_is_high_not_malware(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            TarballKit.manifest("http://203.0.113.7/npm/helper"), encoding="utf-8"
        )
        found = [f for f in TarballKit.findings(tmp_path) if f.rule_id in (SUSPECT, MALWARE)]
        assert [(f.rule_id, f.severity.name) for f in found] == [(SUSPECT, "HIGH")]

    def test_a_python_project_warns_on_the_malware_shape(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "p"\nversion = "1.0"\n'
            'dependencies = ["helper @ https://packages.example.invalid/pypi/helper"]\n',
            encoding="utf-8",
        )
        assert SUSPECT in TarballKit.rules(tmp_path)

    def test_a_version_less_endpoint_blocks(self, tmp_path: Path) -> None:
        # PhantomRaven: whatever the host serves for that name, fresh on every install.
        assert TarballKit.severity(tmp_path, "http://packages.example.invalid/npm/helper") == "HIGH"

    def test_a_release_tarball_on_a_vendor_cdn_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        spec = "https://cdn.example.invalid/xlsx-0.20.3/xlsx-0.20.3.tgz"
        assert TarballKit.severity(tmp_path, spec) == "MEDIUM"

    def test_a_source_archive_on_a_code_host_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        spec = "https://github.com/example/react-native/archive/sdk-36.0.0.tar.gz"
        assert TarballKit.severity(tmp_path, spec) == "MEDIUM"

    def test_an_example_project_inside_the_package_is_not_its_manifest(
        self, tmp_path: Path
    ) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("package/package.json", json.dumps({"name": "p", "version": "1.0.0"})),
                ("package/example/package.json", TarballKit.manifest("http://203.0.113.7/x")),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        assert not {SUSPECT, MALWARE} & TarballKit.rules(target)

    def test_a_self_hosted_code_host_archive_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        spec = "http://gitlab.example.invalid/fex/node-x/repository/archive.tar.gz?ref=v0.0.0"
        assert TarballKit.severity(tmp_path, spec) == "MEDIUM"


class TestForeignCommit:
    """A dependency installed from a commit of a repository that is not its own (review 98: a
    2026 campaign shipping `"@antv/setup": "github:antvis/G2#<sha>"` in compromised releases)."""

    RULE = "SUSPECT.DEPENDENCY.FOREIGN_COMMIT.001"
    SHA = "1916faa365f2788b6e193514872d51a242876569"

    def test_another_projects_commit_under_a_borrowed_name(self, tmp_path: Path) -> None:
        assert self.RULE in TarballKit.published(tmp_path, f"github:example/charts#{self.SHA}")

    def test_the_url_form_too(self, tmp_path: Path) -> None:
        spec = f"git+https://github.com/example/charts.git#{self.SHA}"
        assert self.RULE in TarballKit.published(tmp_path, spec)

    def test_a_fork_of_the_dependency_itself_is_not_this(self, tmp_path: Path) -> None:
        # `helper` from someone's `helper` fork: the name and the repository agree.
        assert self.RULE not in TarballKit.published(tmp_path, f"github:someone/helper#{self.SHA}")

    def test_a_branch_or_a_short_hash_is_not_this(self, tmp_path: Path) -> None:
        assert self.RULE not in TarballKit.published(tmp_path, "github:example/charts#v1.0.0")
        assert self.RULE not in TarballKit.published(tmp_path, "github:example/charts#1916faa")

    def test_a_repository_manifest_is_not_this(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            TarballKit.manifest(f"github:example/charts#{self.SHA}"), encoding="utf-8"
        )
        assert self.RULE not in TarballKit.rules(tmp_path)


class TestUnknownHost:
    """A project's git dependency, or Go module replaced by another host's, from neither a registry nor a code host."""

    RULE = "SUSPECT.DEPENDENCY.UNKNOWN_HOST.001"

    @staticmethod
    def cargo(tmp_path: Path, git: str) -> set[str]:
        (tmp_path / "Cargo.toml").write_text(
            f'[package]\nname = "p"\nversion = "0.1.0"\n\n[dependencies]\nhelper = {{ git = "{git}" }}\n',
            encoding="utf-8",
        )
        return TarballKit.rules(tmp_path)

    @staticmethod
    def go_mod(tmp_path: Path, replacement: str) -> set[str]:
        (tmp_path / "go.mod").write_text(
            "module example.invalid/p\n\ngo 1.22\n\nrequire github.com/mark3labs/mcp-go v0.32.0\n\n"
            f"replace github.com/mark3labs/mcp-go => {replacement}\n",
            encoding="utf-8",
        )
        return TarballKit.rules(tmp_path)

    def test_a_git_dependency_on_an_unknown_host(self, tmp_path: Path) -> None:
        assert self.RULE in self.cargo(tmp_path, "https://packages.example.invalid/helper")

    def test_a_git_dependency_on_a_code_host_is_the_policy_rule_only(self, tmp_path: Path) -> None:
        assert self.RULE not in self.cargo(tmp_path, "https://github.com/example/helper")

    def test_a_go_module_replaced_from_another_host(self, tmp_path: Path) -> None:
        assert self.RULE in self.go_mod(tmp_path, "packages.example.invalid/mcp-go v0.32.1")

    def test_a_fork_on_the_same_host_is_not(self, tmp_path: Path) -> None:
        assert self.RULE not in self.go_mod(tmp_path, "github.com/example/mcp-go v0.32.1")

    def test_a_published_package_is_not_judged_here(self, tmp_path: Path) -> None:
        rules = TarballKit.published(tmp_path, "git+https://packages.example.invalid/helper.git")
        assert self.RULE not in rules
