"""Editor extensions, release identity, GitHub Actions and repository-sourced code.

Every name and version here comes from a published record in the bundled advisory data (OSV's
malicious-package and GitHub Actions records). The fixtures are manifests -- a name and a
version -- and carry no package code.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cloud import device
from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Severity
from cordon_scanner.ecosystems.others import GitHubActionsEcosystem
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories import AdvisoryDatabase
from cordon_scanner.intel.osv_import import OsvImport


class CoverageHelpers:
    """Helpers for test_extension_and_repository_coverage.py."""

    @staticmethod
    def scan(tmp_path: Path, files: dict[str, str | bytes]):
        for name, body in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body if isinstance(body, bytes) else body.encode())
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

    @staticmethod
    def rules(result) -> dict[str, list]:
        out: dict[str, list] = {}
        for finding in result.findings:
            out.setdefault(finding.rule_id, []).append(finding)
        return out

    @staticmethod
    def zipped(members: dict[str, str]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, text in members.items():
                archive.writestr(name, text)
        return buffer.getvalue()

    @staticmethod
    def tarred(members: dict[str, str]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def workflow(*uses: str) -> str:
        steps = "".join(f"      - uses: {u}\n" for u in uses)
        return f"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


class TestEditorExtensionRecords:
    """OSV's VSCode records (Marketplace and Open VSX) wherever an extension is named."""

    def test_the_records_are_bundled(self) -> None:
        records = AdvisoryDatabase.bundled().for_package("vscode", "ellacrity.recoil")
        assert any(a.malicious for a in records)

    def test_a_recommended_malicious_extension(self, tmp_path) -> None:
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(
                tmp_path, {".vscode/extensions.json": '{"recommendations": ["ellacrity.recoil"]}'}
            )
        )
        [hit] = found["MALWARE.EXTENSION.KNOWN.001"]
        assert hit.severity is Severity.CRITICAL
        assert "every release" in hit.message

    def test_the_publisher_and_name_are_case_insensitive(self, tmp_path) -> None:
        doc = '{"recommendations": ["CodeInKlingon.Git-Worktree-Menu"]}'
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {".vscode/extensions.json": doc})
        )
        assert found["MALWARE.EXTENSION.KNOWN.001"]

    def test_a_pinned_affected_release(self, tmp_path) -> None:
        doc = '{"customizations": {"vscode": {"extensions": ["checkmarx.ast-results@2.56.0"]}}}'
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {".devcontainer/devcontainer.json": doc})
        )
        assert found["MALWARE.EXTENSION.KNOWN.001"]

    def test_a_pinned_clean_release_is_quiet(self, tmp_path) -> None:
        doc = '{"customizations": {"vscode": {"extensions": ["checkmarx.ast-results@2.58.0"]}}}'
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {".devcontainer/devcontainer.json": doc})
        )
        assert not [rule for rule in found if "EXTENSION" in rule]

    def test_an_unpinned_extension_with_some_bad_releases_is_only_a_note(self, tmp_path) -> None:
        """A legitimate extension whose publisher was compromised for a few releases is not
        malware by name; blocking on it would be noise."""
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(
                tmp_path,
                {".vscode/extensions.json": '{"recommendations": ["checkmarx.ast-results"]}'},
            )
        )
        assert "MALWARE.EXTENSION.KNOWN.001" not in found
        [hit] = found["SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001"]
        assert hit.severity is Severity.LOW

    def test_a_workspace_file_recommends_too(self, tmp_path) -> None:
        doc = json.dumps(
            {"folders": [{"path": "."}], "extensions": {"recommendations": ["ellacrity.recoil"]}}
        )
        found = CoverageHelpers.rules(CoverageHelpers.scan(tmp_path, {"team.code-workspace": doc}))
        assert found["MALWARE.EXTENSION.KNOWN.001"]

    def test_gitpod_installs_from_open_vsx(self, tmp_path) -> None:
        doc = (
            "tasks:\n  - init: make\nvscode:\n  extensions:\n    - ms-python.python\n"
            "    - ellacrity.recoil@0.7.4\n    - https://example.com/some.vsix\n"
        )
        found = CoverageHelpers.rules(CoverageHelpers.scan(tmp_path, {".gitpod.yml": doc}))
        [hit] = found["MALWARE.EXTENSION.KNOWN.001"]
        assert "ellacrity.recoil" in hit.message

    def test_ordinary_recommendations_stay_quiet(self, tmp_path) -> None:
        doc = '{"recommendations": ["ms-python.python", "golang.go", "esbenp.prettier-vscode"]}'
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {".vscode/extensions.json": doc})
        )
        assert not [rule for rule in found if "EXTENSION" in rule]


class TestReleaseIdentity:
    """A package file is matched by the name and version its own manifest declares."""

    def test_a_vendored_vsix_is_reported_once(self, tmp_path) -> None:
        manifest = '{"publisher": "ellacrity", "name": "recoil", "version": "0.7.4"}'
        archive = CoverageHelpers.zipped({"extension/package.json": manifest})
        found = CoverageHelpers.rules(CoverageHelpers.scan(tmp_path, {"tools/x.vsix": archive}))
        [hit] = found["MALWARE.PACKAGE.KNOWN.001"]
        assert "ellacrity.recoil 0.7.4" in hit.message
        assert "MALWARE.EXTENSION.KNOWN.001" not in found, "one package, one finding"

    def test_a_crate(self, tmp_path) -> None:
        toml = '[package]\nname = "littest"\nversion = "0.3.1"\nedition = "2021"\n'
        archive = CoverageHelpers.tarred({"littest-0.3.1/Cargo.toml": toml})
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {"vendor/littest-0.3.1.crate": archive})
        )
        assert found["MALWARE.PACKAGE.KNOWN.001"]

    def test_a_nuget_package(self, tmp_path) -> None:
        nuspec = (
            '<?xml version="1.0"?><package><metadata><id>Bunifu.Form</id>'
            "<version>1.0.1</version></metadata></package>"
        )
        archive = CoverageHelpers.zipped({"Bunifu.Form.nuspec": nuspec})
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {"packages/bunifu.form.1.0.1.nupkg": archive})
        )
        assert found["MALWARE.PACKAGE.KNOWN.001"]

    def test_a_repository_nuspec_is_not_a_release(self, tmp_path) -> None:
        """Only a manifest inside a package file names a release; a project's own .nuspec is
        the project, whatever it calls itself."""
        nuspec = (
            "<package><metadata><id>Bunifu.Form</id><version>1.0.1</version></metadata></package>"
        )
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {"Bunifu.Form.nuspec": nuspec})
        )
        assert "MALWARE.PACKAGE.KNOWN.001" not in found


class TestGitHubActions:
    """`uses:` references are dependencies, matched against OSV's GitHub Actions records."""

    @pytest.mark.parametrize(
        ("line", "name", "spec"),
        [
            ("tj-actions/changed-files@v45.0.7", "tj-actions/changed-files", "45.0.7"),
            ("tj-actions/changed-files@v45", "tj-actions/changed-files", "ref:v45"),
            ("github/codeql-action/init@v3.28.0", "github/codeql-action", "3.28.0"),
            (
                "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
                "actions/checkout",
                "4.2.2",
            ),
            (
                "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                "actions/checkout",
                "sha:11bd71901bbe5b1630ceea73d27597364c9af683",
            ),
            ("actions/checkout@main", "actions/checkout", "ref:main"),
        ],
    )
    def test_the_reference_forms(self, line, name, spec) -> None:
        from cordon_scanner.core.content import FileContent

        text = CoverageHelpers.workflow(line)
        raw = text.encode()
        manifest = GitHubActionsEcosystem().parse_manifest(
            FileContent(path=".github/workflows/ci.yml", raw=raw, size=len(raw))
        )
        assert [(d.name, d.spec) for d in manifest.dependencies] == [(name, spec)]

    def test_local_and_docker_references_are_told_apart(self) -> None:
        """A local action is the repository's own code (read as source); a `docker://` image is a
        container image, graphed as one -- neither is an action from a repository."""
        from cordon_scanner.core.content import FileContent

        raw = CoverageHelpers.workflow("./.github/actions/setup", "docker://alpine:3.20").encode()
        manifest = GitHubActionsEcosystem().parse_manifest(
            FileContent(path=".github/workflows/ci.yml", raw=raw, size=len(raw))
        )
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["./.github/actions/setup"].spec == "path:./.github/actions/setup"
        assert (by_name["alpine"].ecosystem, by_name["alpine"].spec) == ("image", "3.20")

    def test_workflows_and_composite_actions_are_manifests(self) -> None:
        for path in (".github/workflows/ci.yml", "tools/setup/action.yml"):
            assert EcosystemRegistry.manifest_ecosystem(path) == "actions"

    def test_an_affected_release_is_reported(self, tmp_path) -> None:
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(
                tmp_path,
                {
                    ".github/workflows/ci.yml": CoverageHelpers.workflow(
                        "tj-actions/changed-files@v45.0.7"
                    )
                },
            )
        )
        hits = found.get("VULNERABLE.DEPENDENCY.KNOWN.001", []) + found.get(
            "VULNERABLE.DEPENDENCY.EXPLOITED.001", []
        )
        assert any("tj-actions/changed-files" in (h.location.package or "") for h in hits)

    def test_a_fixed_release_and_a_moving_tag_are_quiet(self, tmp_path) -> None:
        workflow = CoverageHelpers.workflow(
            "tj-actions/changed-files@v46.0.1", "actions/checkout@v4", "actions/setup-node@v4"
        )
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(tmp_path, {".github/workflows/ci.yml": workflow})
        )
        assert not [
            r for r in found if r.startswith(("VULNERABLE.DEPENDENCY", "MALWARE.DEPENDENCY"))
        ]

    def test_an_action_one_edit_from_a_popular_one(self, tmp_path) -> None:
        found = CoverageHelpers.rules(
            CoverageHelpers.scan(
                tmp_path,
                {".github/workflows/ci.yml": CoverageHelpers.workflow("actons/checkout@v4")},
            )
        )
        assert found["SUSPECT.DEPENDENCY.TYPOSQUAT.001"]


class TestRepositorySourcedCode:
    """Code fetched straight from a repository is matched by the repository."""

    @pytest.mark.parametrize(
        "spelling",
        [
            "https://github.com/boltdb-go/bolt.git",
            "git+https://github.com/boltdb-go/bolt.git#v1.3.1",
            "git+ssh://git@github.com/boltdb-go/bolt.git",
            "git@github.com:boltdb-go/bolt.git",
            "github:boltdb-go/bolt",
            "github.com/boltdb-go/bolt",
            "github.com/BoltDB-Go/Bolt/v2",
        ],
    )
    def test_every_spelling_names_one_repository(self, spelling) -> None:
        assert OsvImport.repository_key(spelling) == "github.com/boltdb-go/bolt"

    def test_a_registry_name_is_not_a_repository(self) -> None:
        assert OsvImport.repository_key("left-pad") is None
        assert OsvImport.repository_key("^1.2.3") is None

    @pytest.mark.conformance("x", "x.malicious")
    def test_a_git_dependency_on_a_malicious_repository(self, tmp_path) -> None:
        manifest = json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"bolt": "git+https://github.com/boltdb-go/bolt.git"},
            }
        )
        found = CoverageHelpers.rules(CoverageHelpers.scan(tmp_path, {"package.json": manifest}))
        [hit] = found["MALWARE.DEPENDENCY.KNOWN.001"]
        assert hit.severity is Severity.CRITICAL

    def test_a_git_dependency_on_an_ordinary_repository_is_quiet(self, tmp_path) -> None:
        manifest = json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"bolt": "git+https://github.com/boltdb/bolt.git"},
            }
        )
        found = CoverageHelpers.rules(CoverageHelpers.scan(tmp_path, {"package.json": manifest}))
        assert "MALWARE.DEPENDENCY.KNOWN.001" not in found


class TestInstalledExtensions:
    """`cordon agent`: every VS Code-family editor's installed extensions, judged."""

    @pytest.fixture
    def home(self, tmp_path, monkeypatch) -> Path:
        root = tmp_path / "home"
        manifests = {
            ".cursor/extensions/ellacrity.recoil-0.7.4/package.json": {
                "publisher": "ellacrity",
                "name": "recoil",
                "version": "0.7.4",
                "main": "./out/extension.js",
            },
            ".vscode/extensions/ms-python.python-2025.2.0/package.json": {
                "publisher": "ms-python",
                "name": "python",
                "version": "2025.2.0",
            },
            ".vscode-server/extensions/checkmarx.ast-results-2.58.0/package.json": {
                "publisher": "checkmarx",
                "name": "ast-results",
                "version": "2.58.0",
            },
        }
        for name, body in manifests.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(body), encoding="utf-8")
        # An extension whose manifest is missing is still named, from its folder.
        (root / ".windsurf/extensions/golang.go-0.46.1-darwin-arm64").mkdir(parents=True)
        # Extension code is never read.
        (root / ".cursor/extensions/ellacrity.recoil-0.7.4/out").mkdir()
        (root / ".cursor/extensions/ellacrity.recoil-0.7.4/out/extension.js").write_text(
            "x", encoding="utf-8"
        )
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(root / ".config"))
        return root

    def test_every_editor_is_inventoried(self, home) -> None:
        installed = device.DeviceInventory.installed_extensions(home)
        assert {(e["editor"], e["id"], e["version"]) for e in installed} == {
            ("cursor", "ellacrity.recoil", "0.7.4"),
            ("vscode", "ms-python.python", "2025.2.0"),
            ("vscode-server", "checkmarx.ast-results", "2.58.0"),
            ("windsurf", "golang.go", "0.46.1"),
        }

    def test_a_malicious_installed_release_is_a_finding(self, home) -> None:
        payload = device.DeviceInventory.collect(home)
        hits = [f for f in payload["findings"] if f["rule_id"] == "MALWARE.EXTENSION.KNOWN.001"]
        assert [h["path"] for h in hits] == ["extensions/cursor:ellacrity.recoil@0.7.4"]
        assert hits[0]["severity"] == "critical"

    def test_clean_releases_are_quiet(self, home) -> None:
        payload = device.DeviceInventory.collect(home)
        flagged = {f["path"] for f in payload["findings"] if "EXTENSION" in f["rule_id"]}
        assert flagged == {"extensions/cursor:ellacrity.recoil@0.7.4"}

    def test_the_payload_names_versions_and_editors_but_no_code(self, home) -> None:
        payload = device.DeviceInventory.collect(home)
        assert {"cursor", "vscode", "windsurf"} <= set(payload["inventory"]["tools"])
        assert "ellacrity.recoil-0.7.4" in payload["inventory"]["extensions"]
        assert "./out/extension.js" not in json.dumps(payload)
        assert str(home) not in json.dumps(payload)
