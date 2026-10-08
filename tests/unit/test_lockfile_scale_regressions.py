"""Lockfile readings the comparison with Trivy over 1,796 real lockfiles found wrong
(`bench/parse_agreement.py`), each with its probe."""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

PNPM_TWO_DOCUMENTS = """---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 10.12.1
        version: 10.12.1

packages:

  '@pnpm/exe@10.12.1':
    resolution: {integrity: sha512-AAAA}

  pnpm@10.12.1:
    resolution: {integrity: sha512-BBBB}

snapshots:

  '@pnpm/exe@10.12.1': {}

  pnpm@10.12.1: {}

---
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      ms:
        specifier: ^2.1.3
        version: 2.1.3
    devDependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-CCCC}

  ms@2.1.3:
    resolution: {integrity: sha512-DDDD}

snapshots:

  left-pad@1.3.0: {}

  ms@2.1.3: {}
"""


class TestNpmLinkedDirectories:
    def test_a_linked_directory_without_a_name_is_named_by_its_link(self, tmp_path) -> None:
        """Kotlin/JS's kotlin-js-store links node_modules/kase-core to a directory whose entry
        has no `name`; it was reported as a package called `3.2.3`."""
        import json

        lock = {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "workspaces": ["packages_imported/*/*"]},
                "node_modules/kase-core": {
                    "resolved": "packages_imported/kase-core/3.2.3",
                    "link": True,
                },
                "packages_imported/kase-core/3.2.3": {"version": "3.2.3"},
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        names = {
            (d.name, d.version)
            for d in Scanner(Config.default().with_overrides(use_cache=False), detectors=())
            .scan(tmp_path)
            .dependencies
        }
        assert ("kase-core", "3.2.3") in names and not any(n == "3.2.3" for n, _ in names)


class TestGoBeforeOneSeventeen:
    GO_SUM = (
        "github.com/pkg/errors v0.8.1 h1:aaaa=\n"
        "github.com/pkg/errors v0.9.1 h1:bbbb=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:cccc=\n"
        "golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f h1:dddd=\n"
        "github.com/direct/one v1.2.0 h1:eeee=\n"
    )

    def graph(self, tmp_path, language: str):
        (tmp_path / "go.mod").write_text(
            f"module example.com/app\n\ngo {language}\n\nrequire github.com/direct/one v1.2.0\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(self.GO_SUM, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=()).scan(
            tmp_path
        )
        return {
            (d.name, d.version, d.direct)
            for d in result.dependencies
            if d.name not in ("stdlib", "go")
        }

    def test_go_sum_names_the_indirect_modules_an_old_go_mod_leaves_out(self, tmp_path) -> None:
        """Before Go 1.17, go.mod lists direct requirements only; 32 of 193 real go.sum files
        compared with Trivy lost their whole indirect graph."""
        assert self.graph(tmp_path, "1.13") == {
            ("github.com/direct/one", "v1.2.0", True),
            ("github.com/pkg/errors", "v0.9.1", False),
            ("golang.org/x/sys", "v0.0.0-20200930185726-fdedc70b468f", False),
        }

    def test_a_go_sum_on_its_own_is_the_build_record(self, tmp_path) -> None:
        (tmp_path / "go.sum").write_text(self.GO_SUM, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=()).scan(
            tmp_path
        )
        assert {(d.name, d.version) for d in result.dependencies} == {
            ("github.com/pkg/errors", "v0.9.1"),
            ("golang.org/x/sys", "v0.0.0-20200930185726-fdedc70b468f"),
            ("github.com/direct/one", "v1.2.0"),
        }

    def test_from_one_seventeen_a_tidied_go_mod_is_the_build_list(self, tmp_path) -> None:
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/direct/one v1.2.0\n"
            "\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(self.GO_SUM, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=()).scan(
            tmp_path
        )
        assert {
            (d.name, d.version, d.direct)
            for d in result.dependencies
            if d.name not in ("stdlib", "go")
        } == {
            ("github.com/direct/one", "v1.2.0", True),
            ("github.com/pkg/errors", "v0.9.1", False),
        }

    def test_an_untidied_one_seventeen_go_mod_is_completed_too(self, tmp_path) -> None:
        """A `go 1.17` line over requirements with no `// indirect` among them: 20 of 186 real
        go.sum files compared with Trivy, the build list was the direct modules alone."""
        assert self.graph(tmp_path, "1.21") == {
            ("github.com/direct/one", "v1.2.0", True),
            ("github.com/pkg/errors", "v0.9.1", False),
            ("golang.org/x/sys", "v0.0.0-20200930185726-fdedc70b468f", False),
        }


class TestPnpmTen:
    def test_the_project_document_after_the_environment_is_read(self, tmp_path) -> None:
        """pnpm 10 writes its own environment first and the project after `---`; only the first
        was read, so 12 of 62 real pnpm lockfiles lost their whole tree."""
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_TWO_DOCUMENTS, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=()).scan(
            tmp_path
        )
        found = {(d.name, d.version, d.scope.value) for d in result.dependencies}
        assert ("ms", "2.1.3", "runtime") in found and ("left-pad", "1.3.0", "dev") in found
        # The package manager pnpm installs itself with is the tool, not the project's dependency.
        assert not [n for n, _, _ in found if n in ("pnpm", "@pnpm/exe")]

    def test_a_windows_checkout_with_crlf_line_endings(self, tmp_path) -> None:
        """`---\r` was not a document break, so on Windows the project's whole tree was lost."""
        (tmp_path / "pnpm-lock.yaml").write_bytes(PNPM_TWO_DOCUMENTS.replace("\n", "\r\n").encode())
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=()).scan(
            tmp_path
        )
        found = {(d.name, d.version) for d in result.dependencies}
        assert ("ms", "2.1.3") in found and ("left-pad", "1.3.0") in found
