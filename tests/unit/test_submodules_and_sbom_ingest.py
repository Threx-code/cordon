"""Git submodules read beside the graph, and a bill of materials read as the inventory."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Scope
from cordon_scanner.core.sbom_ingest import PackageUrl, SbomDocument, SbomInventory
from cordon_scanner.core.submodules import GitModules, Submodules


class IngestHelpers:
    """Helpers for test_submodules_and_sbom_ingest.py."""

    @staticmethod
    def scan(target: Path):
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)

    @staticmethod
    def write(path: Path, body: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    @staticmethod
    def git(directory: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True)

    @staticmethod
    def cyclonedx(**fields) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"tools": {"components": [{"name": "maker", "version": "2"}]}},
            **fields,
        }


class TestSubmodules:
    @pytest.mark.conformance("x", "x.git")
    def test_sections_paths_urls_branches(self) -> None:
        manifest = GitModules.parse(
            FileContent.from_bytes(
                ".gitmodules",
                b'# vendored code\n[submodule "json"]\n\tpath = vendor/json\n\turl = https://github.com/nlohmann/json.git\n'
                b'[submodule "protos"]\n\tpath = protos\n\turl = git@github.com:Acme/Protos.git\n\tbranch = main\n',
            ),
            "git",
        )
        assert manifest.parse_error is None
        assert [(d.name, d.field_name, d.alias, d.platform) for d in manifest.dependencies] == [
            ("github.com/nlohmann/json", "submodule vendor/json", "json", ()),
            ("github.com/acme/protos", "submodule protos", None, ("tracks branch main",)),
        ]
        assert {d.scope for d in manifest.dependencies} == {Scope.BUILD}

    @pytest.mark.conformance("x", "x.git")
    @pytest.mark.parametrize(
        ("text", "error"),
        [
            (b'[submodule "a"]\n\turl = https://example.invalid/a.git\n', "has no path"),
            (b'[submodule "a"]\n\tpath = a\n', "has no url"),
            (b"path = a\n", "neither a section nor"),
            (b"# nothing\n", "without a submodule"),
            (b'[submodule "a"]\n\tpath = a\n\turl', "neither a section nor"),
        ],
    )
    def test_what_git_refuses_is_a_diagnostic(self, text, error) -> None:
        manifest = GitModules.parse(FileContent.from_bytes(".gitmodules", text), "git")
        assert manifest.parse_error and error in manifest.parse_error

    @pytest.mark.conformance("x", "x.git")
    @pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
    def test_a_checkout_pins_each_submodule_at_its_gitlink(self, tmp_path) -> None:
        IngestHelpers.git(tmp_path, "init", "-q")
        IngestHelpers.write(
            tmp_path / ".gitmodules",
            '[submodule "json"]\n\tpath = vendor/json\n\turl = https://github.com/nlohmann/json.git\n\tbranch = develop\n',
        )
        IngestHelpers.git(
            tmp_path,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03,vendor/json",
        )
        assert Submodules.gitlinks(tmp_path) == {
            "vendor/json": "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03"
        }
        [record] = [d for d in IngestHelpers.scan(tmp_path).dependencies if d.ecosystem == "git"]
        assert record.version == "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03"
        assert record.to_dict()["record"]["resolution_reason"] == "pinned to a commit"
        assert record.purl.startswith("pkg:generic/github.com/nlohmann/json@9cca280a")

    @pytest.mark.conformance("x", "x.git", "x.malicious")
    def test_a_submodule_on_a_malicious_repository(self, tmp_path) -> None:
        IngestHelpers.write(
            tmp_path / ".gitmodules",
            '[submodule "bolt"]\n\tpath = third_party/bolt\n\turl = https://github.com/boltdb-go/bolt.git\n',
        )
        found = [
            f
            for f in IngestHelpers.scan(tmp_path).findings
            if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"
        ]
        assert found and "github.com/boltdb-go/bolt" in found[0].message

    def test_an_unreadable_gitmodules_is_said(self, tmp_path) -> None:
        IngestHelpers.write(tmp_path / ".gitmodules", '[submodule "a"]\n\tpath = a\n')
        result = IngestHelpers.scan(tmp_path)
        assert any(
            f.rule_id == "OPERATIONAL.MANIFEST.UNPARSED" and f.location.path == ".gitmodules"
            for f in result.findings
        )
        assert result.complete is False


class TestSbomIngestion:
    @pytest.mark.conformance("x", "x.sbom")
    @pytest.mark.parametrize(
        ("purl", "ecosystem", "name", "version"),
        [
            ("pkg:npm/%40babel/core@7.26.0", "npm", "@babel/core", "7.26.0"),
            (
                "pkg:maven/org.apache.commons/commons-lang3@3.17.0?type=jar",
                "maven",
                "org.apache.commons:commons-lang3",
                "3.17.0",
            ),
            (
                "pkg:golang/github.com/google/uuid@v1.6.0",
                "gomod",
                "github.com/google/uuid",
                "v1.6.0",
            ),
            (
                "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12",
                "deb",
                "libssl3",
                "3.0.15-1~deb12u1",
            ),
            ("pkg:docker/library/python@3.12?repository_url=docker.io", "image", "python", "3.12"),
            (
                "pkg:docker/acme/app@1.0?repository_url=ghcr.io/acme",
                "image",
                "ghcr.io/acme/app",
                "1.0",
            ),
            ("pkg:github/actions/checkout@v4", "actions", "actions/checkout", "v4"),
        ],
    )
    def test_package_urls_name_packages_as_their_ecosystems_do(
        self, purl, ecosystem, name, version
    ) -> None:
        parsed = PackageUrl.parse(purl)
        assert parsed is not None and (parsed.ecosystem, parsed.package_name, parsed.version) == (
            ecosystem,
            name,
            version,
        )

    @pytest.mark.conformance("x", "x.sbom")
    def test_cyclonedx_hashes_licences_scope_and_graph(self) -> None:
        document = IngestHelpers.cyclonedx(
            metadata={
                "tools": [{"name": "legacy-tool", "version": "1"}],
                "component": {"bom-ref": "app"},
            },
            components=[
                {
                    "bom-ref": "a",
                    "name": "left-pad",
                    "version": "1.3.0",
                    "purl": "pkg:npm/left-pad@1.3.0",
                    "hashes": [
                        {"alg": "SHA-1", "content": "a" * 40},
                        {"alg": "SHA-512", "content": "b" * 128},
                    ],
                    "licenses": [{"license": {"id": "MIT"}}],
                },
                {
                    "bom-ref": "b",
                    "name": "is-number",
                    "version": "7.0.0",
                    "purl": "pkg:npm/is-number@7.0.0",
                    "scope": "optional",
                    "components": [
                        {"bom-ref": "c", "name": "kind-of", "purl": "pkg:npm/kind-of@6.0.3"}
                    ],
                },
            ],
            dependencies=[
                {"ref": "app", "dependsOn": ["a"]},
                {"ref": "a", "dependsOn": ["b"]},
                {"ref": "b", "dependsOn": ["c"]},
            ],
        )
        reading = SbomDocument.read(document)
        assert reading.problems == [] and reading.tool == "legacy-tool 1"
        records = {d.name: d for d in SbomInventory.dependencies("bom.json", reading)}
        assert (
            records["left-pad"].integrity == "sha512:" + "b" * 128
            and records["left-pad"].license == "MIT"
        )
        assert (
            records["left-pad"].direct,
            records["is-number"].depth,
            records["kind-of"].depth,
        ) == (True, 1, 2)
        assert records["is-number"].scope is Scope.OPTIONAL and records["kind-of"].parents == (
            "is-number",
        )
        assert (
            records["kind-of"].resolved_by
            == "the CycloneDX 1.6 SBOM bom.json (written by legacy-tool 1)"
        )

    @pytest.mark.conformance("x", "x.sbom")
    def test_spdx_relationships(self) -> None:
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"creators": ["Tool: maker-2"]},
            "packages": [
                {"SPDXID": "SPDXRef-root", "name": "app"},
                {
                    "SPDXID": "SPDXRef-a",
                    "name": "requests",
                    "versionInfo": "2.32.3",
                    "licenseConcluded": "Apache-2.0",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "c" * 64}],
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.32.3"}
                    ],
                },
                {
                    "SPDXID": "SPDXRef-b",
                    "name": "urllib3",
                    "versionInfo": "2.2.3",
                    "licenseConcluded": "NOASSERTION",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/urllib3@2.2.3"}
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-root",
                },
                {
                    "spdxElementId": "SPDXRef-root",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-a",
                },
                {
                    "spdxElementId": "SPDXRef-b",
                    "relationshipType": "DEPENDENCY_OF",
                    "relatedSpdxElement": "SPDXRef-a",
                },
                {
                    "spdxElementId": "SPDXRef-root",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-b",
                },
            ],
        }
        records = {
            d.name: d
            for d in SbomInventory.dependencies("app.spdx.json", SbomDocument.read(document))
        }
        assert set(records) == {"requests", "urllib3"}
        assert records["requests"].direct and records["requests"].integrity == "sha256:" + "c" * 64
        # CONTAINS is where a package is, not what depends on it.
        assert not records["urllib3"].direct and records["urllib3"].parents == ("requests",)
        assert records["urllib3"].license is None

    @pytest.mark.conformance("x", "x.sbom")
    @pytest.mark.parametrize(
        ("document", "problem"),
        [
            (IngestHelpers.cyclonedx(specVersion="2.0"), "not one this reads"),
            (IngestHelpers.cyclonedx(components=[{"bom-ref": "x", "version": "1"}]), "has no name"),
            (
                IngestHelpers.cyclonedx(components=[{"name": "a", "purl": "not a purl"}]),
                "does not parse",
            ),
            (IngestHelpers.cyclonedx(components=[{"name": "a"}]), "no Package URL"),
            (
                IngestHelpers.cyclonedx(components=[{"name": "a", "purl": "pkg:swid/a@1"}]),
                "no ecosystem here reads",
            ),
            (
                IngestHelpers.cyclonedx(
                    components=[
                        {"bom-ref": "d", "name": "a", "purl": "pkg:npm/a@1"},
                        {"bom-ref": "d", "name": "b", "purl": "pkg:npm/b@1"},
                    ]
                ),
                "names two components",
            ),
            (
                IngestHelpers.cyclonedx(
                    components=[{"bom-ref": "a", "name": "a", "purl": "pkg:npm/a@1"}],
                    dependencies=[{"ref": "a", "dependsOn": ["ghost"]}],
                ),
                "does not hold",
            ),
            ({"spdxVersion": "SPDX-3.0", "SPDXID": "SPDXRef-DOCUMENT"}, "not a version this reads"),
        ],
    )
    def test_what_cannot_be_believed_is_said(self, document, problem) -> None:
        assert any(problem in p for p in SbomDocument.read(document).problems)

    @pytest.mark.conformance("x", "x.sbom")
    def test_a_target_document_is_the_inventory_and_a_tree_one_is_not(self, tmp_path) -> None:
        document = IngestHelpers.cyclonedx(
            components=[{"name": "left-pad", "purl": "pkg:npm/left-pad@1.3.0"}]
        )
        target = IngestHelpers.write(tmp_path / "vendor.cdx.json", json.dumps(document))
        result = IngestHelpers.scan(target)
        assert [(d.ecosystem, d.name, d.version) for d in result.dependencies] == [
            ("npm", "left-pad", "1.3.0")
        ]
        assert result.target_kind == "sbom"
        # In a directory the same file is a claim to compare, not a second inventory.
        assert [d for d in IngestHelpers.scan(tmp_path).dependencies if d.name == "left-pad"] == []

    @pytest.mark.conformance("x", "x.sbom")
    def test_a_document_that_does_not_parse_is_said(self, tmp_path) -> None:
        target = IngestHelpers.write(
            tmp_path / "bom.json",
            '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [',
        )
        result = IngestHelpers.scan(target)
        assert result.dependencies == () and result.complete is False
        assert any(
            f.rule_id == "OPERATIONAL.SBOM.INVALID" and "not valid JSON" in f.message
            for f in result.findings
        )


class TestVulnerabilitiesAnSbomLists:
    @pytest.mark.conformance("x", "x.sbom")
    def test_listed_vulnerabilities_are_reported_where_matching_did_not_name_them(
        self, tmp_path
    ) -> None:
        document = IngestHelpers.cyclonedx(
            components=[
                {
                    "bom-ref": "a",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                },
                {
                    "bom-ref": "b",
                    "name": "left-pad",
                    "version": "1.3.0",
                    "purl": "pkg:npm/left-pad@1.3.0",
                },
            ],
            vulnerabilities=[
                {
                    "id": "CVE-2021-23337",
                    "ratings": [{"severity": "high"}],
                    "affects": [{"ref": "a"}],
                },
                {
                    "id": "CVE-2099-0001",
                    "ratings": [{"severity": "critical"}],
                    "affects": [{"ref": "b"}],
                    "source": {"url": "https://example.invalid/advisory"},
                },
                {
                    "id": "CVE-2099-0002",
                    "affects": [{"ref": "b"}],
                    "analysis": {"state": "not_affected"},
                },
            ],
        )
        result = IngestHelpers.scan(
            IngestHelpers.write(tmp_path / "bom.cdx.json", json.dumps(document))
        )
        listed = [f for f in result.findings if f.rule_id == "VULNERABLE.SBOM.LISTED.001"]
        # lodash's is the scan's own finding already; left-pad's rests on the document alone.
        assert [(f.location.package, f.severity.name) for f in listed] == [
            ("pkg:npm/left-pad@1.3.0", "CRITICAL")
        ]
        assert listed[0].references == ("https://example.invalid/advisory",)
        # The target's own "not affected" is not applied: it cannot vouch for itself.
        assert any(f.rule_id == "OPERATIONAL.SBOM.VEX_NOT_APPLIED" for f in result.findings)

    @pytest.mark.conformance("x", "x.sbom")
    def test_spdx_security_references(self) -> None:
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-a",
                    "name": "urllib3",
                    "versionInfo": "1.26.5",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/urllib3@1.26.5",
                        },
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "advisory",
                            "referenceLocator": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
                        },
                    ],
                }
            ],
        }
        [listed] = SbomDocument.read(document).vulnerabilities
        assert (listed.identifier, listed.affects, listed.reference) == (
            "CVE-2023-43804",
            ("SPDXRef-a",),
            "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
        )
