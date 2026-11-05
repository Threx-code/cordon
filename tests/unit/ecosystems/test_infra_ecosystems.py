"""P6: Terraform, Helm, Ansible Galaxy, Nix, vcpkg, Homebrew, Hackage, Julia and opam.

Each is graphed, and none reports a fact of its own format as an anomaly: a Helm lock records no
per-chart hash, a chart comes from its own repository, a Galaxy role from the Galaxy.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Scope

TERRAFORM_LOCK = """\
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:ltxyuBWIy9cq0kIKDJH1jeWJy/y7XJLjS4QrsQK4plA=",
    "zh:0cdb9c2083bf0902442384f7309367791e4640581652dda456f2d6d7abf0de8d",
  ]
}

provider "tf.example.invalid/acme/widgets" {
  version = "0.1.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  ]
}
"""

CHART_LOCK = """\
dependencies:
- name: postgresql
  repository: oci://registry-1.docker.io/bitnamicharts
  version: 15.5.38
- name: common
  repository: https://charts.bitnami.com/bitnami
  version: 2.27.0
- name: local-sub
  repository: file://../local-sub
  version: 0.1.0
digest: sha256:9e2f1a6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918
generated: "2025-01-01T00:00:00Z"
"""

GALAXY = """\
roles:
  - name: geerlingguy.java
    version: 1.9.6
  - src: https://git.example.invalid/ops/hardening.git
    scm: git
    version: main
collections:
  - name: community.general
    version: ">=7.0.0"
"""

FLAKE_LOCK = """\
{
  "nodes": {
    "nixpkgs": {
      "locked": {"type": "github", "owner": "NixOS", "repo": "nixpkgs",
                 "rev": "0123456789abcdef0123456789abcdef01234567",
                 "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
      "original": {"type": "github", "owner": "NixOS", "repo": "nixpkgs"}
    },
    "root": {"inputs": {"nixpkgs": "nixpkgs"}}
  },
  "root": "root",
  "version": 7
}
"""

JULIA_MANIFEST = """\
julia_version = "1.10.0"
manifest_format = "2.0"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers", "Unicode"]
git-tree-sha1 = "31e996f0a15c7b280ba9f76636b3ff9e2ae58c9a"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
"""


class InfraHelpers:
    @staticmethod
    def parse_lock(ecosystem: str, path: str, text: str):
        raw = text.encode()
        return EcosystemRegistry.get(ecosystem).parse_lockfile(
            FileContent(path=path, raw=raw, size=len(raw))
        )

    @staticmethod
    def parse_manifest(ecosystem: str, path: str, text: str):
        raw = text.encode()
        return EcosystemRegistry.get(ecosystem).parse_manifest(
            FileContent(path=path, raw=raw, size=len(raw))
        )

    @staticmethod
    def scan(tmp_path: Path, files: dict[str, str]):
        for name, body in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)


class TestClassification:
    @pytest.mark.parametrize(
        ("path", "manifest", "lockfile"),
        [
            ("infra/.terraform.lock.hcl", None, "terraform"),
            ("charts/api/Chart.yaml", "helm", None),
            ("charts/api/Chart.lock", None, "helm"),
            ("ansible/requirements.yml", "ansible", None),
            ("flake.lock", None, "nix"),
            ("vcpkg.json", "vcpkg", None),
            ("Brewfile", "homebrew", None),
            ("cabal.project.freeze", None, "hackage"),
            ("stack.yaml.lock", None, "hackage"),
            ("Manifest.toml", None, "julia"),
            ("app.opam", "opam", None),
            ("app.opam.locked", None, "opam"),
        ],
    )
    def test_each_file_is_its_ecosystem_s(self, path, manifest, lockfile) -> None:
        if manifest:
            assert EcosystemRegistry.manifest_ecosystem(path) == manifest
        if lockfile:
            assert EcosystemRegistry.lockfile_ecosystem(path) == lockfile


class TestParsing:
    def test_terraform_providers_with_their_hashes(self) -> None:
        graph = InfraHelpers.parse_lock("terraform", ".terraform.lock.hcl", TERRAFORM_LOCK)
        by_name = {e.name: e for e in graph.entries}
        assert by_name["hashicorp/aws"].version == "5.31.0"
        # A platform zip's hash, which the registry's SHA256SUMS can confirm (h1 it cannot).
        assert by_name["hashicorp/aws"].integrity.startswith("zh:")
        assert by_name["tf.example.invalid/acme/widgets"].resolved_from.startswith(
            "https://tf.example.invalid/"
        )

    def test_helm_dependencies(self) -> None:
        graph = InfraHelpers.parse_lock("helm", "Chart.lock", CHART_LOCK)
        assert {(e.name, e.version, e.local) for e in graph.entries} == {
            ("postgresql", "15.5.38", False),
            ("common", "2.27.0", False),
            ("local-sub", "0.1.0", True),
        }

    def test_galaxy_roles_and_collections(self) -> None:
        manifest = InfraHelpers.parse_manifest("ansible", "requirements.yml", GALAXY)
        specs = {d.name: d.spec for d in manifest.dependencies}
        assert specs["geerlingguy.java"] == "1.9.6"
        assert specs["hardening"].startswith("git+https://git.example.invalid/")
        assert specs["community.general"] == ">=7.0.0"

    def test_the_older_list_form(self) -> None:
        manifest = InfraHelpers.parse_manifest(
            "ansible", "roles/requirements.yml", "- src: geerlingguy.nginx\n  version: 3.1.4\n"
        )
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("geerlingguy.nginx", "3.1.4")]

    def test_another_tool_s_requirements_yml_is_not_a_parse_failure(self) -> None:
        manifest = InfraHelpers.parse_manifest("ansible", "requirements.yml", "python: ['3.12']\n")
        assert manifest.parse_error is None and manifest.dependencies == ()

    def test_flake_inputs(self) -> None:
        graph = InfraHelpers.parse_lock("nix", "flake.lock", FLAKE_LOCK)
        [entry] = graph.entries
        assert entry.name == "nixos/nixpkgs" and entry.direct
        # The repository at the commit the lock pins.
        assert (
            entry.resolved_from
            == "git+https://github.com/NixOS/nixpkgs#0123456789abcdef0123456789abcdef01234567"
        )

    def test_julia_packages_and_the_standard_library(self) -> None:
        graph = InfraHelpers.parse_lock("julia", "Manifest.toml", JULIA_MANIFEST)
        by_name = {e.name: e for e in graph.entries}
        assert by_name["JSON"].version == "0.21.4"
        assert by_name["Dates"].bundled, "a standard library ships with Julia"

    def test_cabal_and_stack(self) -> None:
        freeze = InfraHelpers.parse_lock(
            "hackage",
            "cabal.project.freeze",
            "constraints: any.aeson ==2.1.2.1,\n             any.text ==2.0.2\n",
        )
        assert {(e.name, e.version) for e in freeze.entries} == {
            ("aeson", "2.1.2.1"),
            ("text", "2.0.2"),
        }
        stack = InfraHelpers.parse_lock(
            "hackage",
            "stack.yaml.lock",
            "packages:\n- completed:\n    hackage: acme-missiles-0.3@sha256:" + "a" * 64 + ",613\n"
            "snapshots:\n- completed:\n    sha256: "
            + "b" * 64
            + "\n    size: 720001\n  original: lts-22.33\n",
        )
        assert [(e.name, e.version, e.integrity) for e in stack.entries] == [
            ("acme-missiles", "0.3", "sha256:" + "a" * 64)
        ]

    def test_opam(self) -> None:
        text = 'opam-version: "2.0"\ndepends: [\n  "ocaml" {>= "4.14"}\n  "dune" {>= "3.16"}\n  "lwt" {>= "5.6"}\n]\n'
        manifest = InfraHelpers.parse_manifest("opam", "app.opam", text)
        # The compiler is the switch: a platform requirement.
        assert {(d.name, d.scope) for d in manifest.dependencies} == {
            ("ocaml", Scope.PLATFORM),
            ("dune", Scope.RUNTIME),
            ("lwt", Scope.RUNTIME),
        }
        locked = InfraHelpers.parse_lock(
            "opam",
            "app.opam.locked",
            'opam-version: "2.0"\ndepends: [\n  "ocaml" {= "5.2.1"}\n  "dune" {= "3.16.0"}\n  "lwt" {= "5.7.0"}\n]\n',
        )
        assert [(e.name, e.version) for e in locked.entries if e.scope is not Scope.PLATFORM] == [
            ("dune", "3.16.0"),
            ("lwt", "5.7.0"),
        ]
        # `opam lock` writes only exact versions: anything else is not its output.
        assert InfraHelpers.parse_lock("opam", "app.opam.locked", text).parse_error

    @pytest.mark.parametrize("text", ["", "\n", "# nothing declared yet\n\n"])
    def test_an_opam_file_with_no_fields_declares_nothing(self, text: str) -> None:
        """An empty opam file is complete, not unparsed: @reason-native_console-0.1.0 ships eleven
        0-byte .opam files, and each was a gap that blocked the package (item 27's count)."""
        manifest = InfraHelpers.parse_manifest("opam", "pkg.opam", text)
        assert manifest.parse_error is None
        assert manifest.dependencies == () and manifest.hooks == ()

    def test_an_opam_file_with_fields_but_neither_key_stays_refused(self) -> None:
        """Its other fields can carry build: hooks, so it is not read as declaring nothing."""
        manifest = InfraHelpers.parse_manifest("opam", "pkg.opam", 'build: [["sh" "x.sh"]]\n')
        assert manifest.parse_error

    def test_homebrew_taps_are_sources(self) -> None:
        manifest = InfraHelpers.parse_manifest(
            "homebrew",
            "Brewfile",
            'tap "homebrew/cask"\ntap "acme/tools"\nbrew "jq"\ncask "firefox"\n',
        )
        specs = {d.name: d.spec for d in manifest.dependencies}
        # A Brewfile entry asks for whatever version is current: any version.
        assert specs == {
            "acme/tools": "https://github.com/acme/homebrew-tools",
            "jq": "*",
            "firefox": "*",
        }


class TestNoFormatNoise:
    def test_a_helm_chart_and_its_lock_are_quiet(self, tmp_path) -> None:
        chart = "apiVersion: v2\nname: api\nversion: 1.0.0\ndependencies:\n  - name: common\n    version: 2.27.0\n    repository: https://charts.bitnami.com/bitnami\n"
        result = InfraHelpers.scan(
            tmp_path, {"charts/api/Chart.yaml": chart, "charts/api/Chart.lock": CHART_LOCK}
        )
        assert not [
            f
            for f in result.findings
            if f.rule_id.startswith(("POLICY.LOCKFILE", "POLICY.DEPENDENCY", "SUSPECT.DEPENDENCY"))
        ]

    def test_a_terraform_provider_from_a_foreign_host_is_reported(self, tmp_path) -> None:
        result = InfraHelpers.scan(tmp_path, {"infra/.terraform.lock.hcl": TERRAFORM_LOCK})
        flagged = {
            f.location.package or ""
            for f in result.findings
            if "PROVENANCE" in f.rule_id or "REGISTRY" in f.rule_id or "SOURCE" in f.rule_id
        }
        assert any("widgets" in p for p in flagged)
        assert not any("hashicorp/aws" in p for p in flagged)

    @pytest.mark.parametrize(
        "name",
        [
            "Brewfile",
            # Found comparing with Homebrew Bundle on real dotfiles: by these names a Brewfile was
            # neither read nor checked for the extensions it installs.
            ".Brewfile",
            "Brewfile.txt",
            "Brewfile.local",
            "homebrew/Brewfile.symlink",
            "work.Brewfile",
        ],
    )
    def test_a_brewfile_extension_is_judged(self, tmp_path, name) -> None:
        result = InfraHelpers.scan(tmp_path, {name: 'brew "jq"\nvscode "ellacrity.recoil"\n'})
        assert any(f.rule_id == "MALWARE.EXTENSION.KNOWN.001" for f in result.findings)
        assert "jq" in {d.name for d in result.dependencies}


class TestTerraformParsedOnce:
    """A file's configuration is parsed once a scan (`TerraformConfiguration.blocks`): asked again
    it answers as a fresh parse would, a parse that fails included."""

    MAIN = 'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\nresource "google_storage_bucket" "b" {\n  name = "x"\n}\n'

    @staticmethod
    def content(path: str, text: str) -> FileContent:
        raw = text.encode()
        return FileContent(path=path, raw=raw, size=len(raw))

    def test_an_unreadable_tf_json_fails_alike_each_time_and_spares_its_siblings(self) -> None:
        from cordon_scanner.ecosystems.infra.terraform import TerraformConfiguration
        from cordon_scanner.foundation.collector import ScanCaches

        ecosystem = EcosystemRegistry.get("terraform")
        broken = self.content("mod/broken.tf.json", "{not json")
        main = self.content("mod/main.tf", self.MAIN)
        files = {c.path: c for c in (broken, main)}
        ScanCaches.after_scan()
        first = [ecosystem.parse_in_tree(c, files) for c in (main, broken)]
        again = [ecosystem.parse_in_tree(c, files) for c in (main, broken)]
        assert again == first  # the second read of each, from the kept parses, is the first's
        assert first[1].parse_error and not first[0].parse_error
        assert {d.name for d in first[0].dependencies} == {"hashicorp/aws", "hashicorp/google"}
        ScanCaches.after_scan()
        assert not TerraformConfiguration._parsed


class TestTerraformExpressionKeys:
    """An object's key may be an expression (HCL: a bare identifier is a literal name, anything
    else is evaluated). `local.suppliers[count.index] = ...` in a `data = { ... }` map made three
    files of ministryofjustice/cloud-platform-environments unreadable, and the scan incomplete
    (2026-10-31). A key's expression is read under the same bounds as a value's."""

    @staticmethod
    def blocks(text: str):
        from cordon_scanner.ecosystems.infra.terraform import TerraformConfiguration

        raw = text.encode()
        return TerraformConfiguration._blocks(FileContent(path="main.tf", raw=raw, size=len(raw)))

    @staticmethod
    def keys_of(text: str) -> set[str]:
        root = TestTerraformExpressionKeys.blocks(text)
        return set(root.blocks[0].attributes["data"])

    def test_a_traversal_key_with_an_index_parses(self) -> None:
        text = (
            'resource "kubernetes_secret" "apikeys" {\n'
            "  count = length(local.suppliers)\n"
            "  data = {\n"
            "    local.suppliers[count.index] = aws_api_gateway_api_key.api_keys[count.index].value\n"
            "  }\n"
            "}\n"
        )
        assert self.keys_of(text) == set()  # an evaluated key is not a name, as `(local.k)` is not

    @pytest.mark.parametrize(
        ("key", "stored"),
        [
            ("a", {"a"}),
            ('"a"', {"a"}),
            ("(var.k)", set()),
            ("local.m[0]", set()),
            ("a.b", set()),
        ],
    )
    def test_spec_shaped_keys(self, key: str, stored: set[str]) -> None:
        text = f'resource "x" "y" {{\n  data = {{\n    {key} = 1\n  }}\n}}\n'
        assert self.keys_of(text) == stored

    def test_a_name_at_the_end_of_the_file_fails_as_before(self) -> None:
        """A key name with nothing after it is not read as an expression key: the reader fails as
        it did before expression keys were read, from the same place and with the same words."""
        from cordon_scanner.ecosystems.infra.terraform import HclError

        with pytest.raises(HclError, match=r"^the file ends inside a block$"):
            self.blocks('resource "x" "y" {\n  data = {\n    a')

    def test_a_deep_parenthesised_key_never_recurses(self) -> None:
        from cordon_scanner.ecosystems.infra.terraform import HclError

        key = "(" * 10_000 + "x" + ")" * 10_000
        text = f'resource "x" "y" {{\n  data = {{\n    {key} = 1\n  }}\n}}\n'
        try:
            keys = self.keys_of(text)
        except HclError:
            return  # refused within the reader's bounds, by name
        assert keys == set()

    def test_a_deep_braced_key_is_refused_by_name(self) -> None:
        """Pins the bound a key shares with a value: a key opening with `{` recurses through
        `object` under MAX_DEPTH (64), refused by name, never a RecursionError. It holds before the
        change too: a bound kept, not a defect fixed."""
        from cordon_scanner.ecosystems.infra.terraform import HclError

        key = "{" * 100 + "}" * 100
        text = f'resource "x" "y" {{\n  data = {{\n    {key} = 1\n  }}\n}}\n'
        with pytest.raises(HclError, match="nested too deeply"):
            self.blocks(text)


# `requirements.lock` is Helm v2's lock only beside its chart's Chart.yaml; elsewhere it is Rye's
# pip-format lockfile, which Helm does not claim (item 27: faust-cchardet 3.2, stratos_lib 0.1).
PIP_LOCK = b"# generated by rye\n-e file:.\ncchardet==2.1.7\n"
UNPARSED = {"OPERATIONAL.LOCKFILE.UNPARSED", "OPERATIONAL.MANIFEST.UNPARSED"}


class HelmLockKit:
    @staticmethod
    def sdist(tmp_path, files: dict[str, bytes]):
        path = tmp_path / "pkg-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(f"pkg-1.0/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)


class TestRequirementsLock:
    def test_a_pip_lockfile_is_not_read_as_a_chart_lock(self, tmp_path) -> None:
        result = HelmLockKit.sdist(
            tmp_path, {"requirements.lock": PIP_LOCK, "setup.py": b"from setuptools import setup\n"}
        )
        assert not UNPARSED & {f.rule_id for f in result.findings}
        assert result.content_complete

    def test_a_chart_s_lock_that_does_not_read_still_fails_closed(self, tmp_path) -> None:
        chart = b"apiVersion: v1\nname: demo\nversion: 0.1.0\n"
        result = HelmLockKit.sdist(
            tmp_path, {"chart/Chart.yaml": chart, "chart/requirements.lock": PIP_LOCK}
        )
        assert UNPARSED & {f.rule_id for f in result.findings}
        assert not result.content_complete
