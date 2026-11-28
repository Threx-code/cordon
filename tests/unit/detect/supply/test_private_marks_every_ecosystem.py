"""How each ecosystem's manifest marks a package as not for publishing (`PrivateMark` / `NoPrivateMark`), read from real manifests.

A package so marked is no dependency of anyone, so its install-time commands are its own project's build (`LifecycleFindings`,
`InstallHookShapes`). The marked files are real (`private_mark_captures/CAPTURES.md`) and so is the repository's own npm case; the
unmarked files are the real published manifests of `own_name_captures`, which must read as publishable."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.install_marks import NoPrivateMark, PrivateMark
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from support import ROOT

MARKED = ROOT / "tests" / "unit" / "detect" / "supply" / "private_mark_captures"
PUBLISHED = ROOT / "tests" / "unit" / "detect" / "supply" / "own_name_captures"
NPM_CASE = ROOT / "tests" / "conformance" / "cases" / "npm" / "real-npm-v3" / "package.json"

#: (ecosystem, the path of the manifest, a real manifest that carries the mark, a real published manifest that does not)
CASES = [
    ("npm", "package.json", NPM_CASE, PUBLISHED / "cdxgen-package.json"),
    ("cargo", "Cargo.toml", MARKED / "tokio-benches-Cargo.toml", PUBLISHED / "serde-Cargo.toml"),
    (
        "pub",
        "pubspec.yaml",
        MARKED / "flutter-camera-example-pubspec.yaml",
        PUBLISHED / "http-1.2.2-pubspec.yaml",
    ),
    (
        "pypi",
        "pyproject.toml",
        MARKED / "flask-tutorial-pyproject.toml",
        MARKED / "requests-pyproject.toml",
    ),
    ("maven", "pom.xml", MARKED / "maven-resolver-demos-pom.xml", PUBLISHED / "gson-2.11.0.pom"),
    (
        "nuget",
        "Tests/Newtonsoft.Json.Tests.csproj",
        MARKED / "newtonsoft-json-tests.csproj",
        MARKED / "newtonsoft-json-library.csproj",
    ),
]


class Manifests:
    @staticmethod
    def content(path: str, source: object) -> FileContent:
        raw = source.read_bytes()  # type: ignore[attr-defined]
        return FileContent.from_bytes(path, raw)


class TestEveryEcosystemSaysHowItsManifestIsMarkedPrivate:
    def test_each_declares_a_mark_or_why_it_has_none(self) -> None:
        for adapter in EcosystemRegistry.all_ecosystems():
            declared = adapter.private_mark
            assert isinstance(declared, PrivateMark | NoPrivateMark), adapter.id
            if isinstance(declared, NoPrivateMark):
                assert len(declared.reason.split()) >= 10, adapter.id

    def test_the_ecosystems_with_a_mark_are_the_ones_a_real_manifest_proves(self) -> None:
        marked = {
            a.id
            for a in EcosystemRegistry.all_ecosystems()
            if isinstance(a.private_mark, PrivateMark)
        }
        assert marked == {c[0] for c in CASES}


class TestARealMarkedManifestIsUnpublishable:
    @pytest.mark.parametrize(
        ("ecosystem", "path", "marked", "plain"), CASES, ids=[c[0] for c in CASES]
    )
    def test_the_mark_is_read(
        self, ecosystem: str, path: str, marked: object, plain: object
    ) -> None:
        assert EcosystemRegistry.unpublishable(ecosystem, path, Manifests.content(path, marked))

    @pytest.mark.parametrize(
        ("ecosystem", "path", "marked", "plain"), CASES, ids=[c[0] for c in CASES]
    )
    def test_a_published_manifest_is_not(
        self, ecosystem: str, path: str, marked: object, plain: object
    ) -> None:
        assert not EcosystemRegistry.unpublishable(ecosystem, path, Manifests.content(path, plain))

    def test_a_file_that_is_not_the_manifest_is_not_read(self) -> None:
        content = Manifests.content("notes.txt", MARKED / "tokio-benches-Cargo.toml")
        assert not EcosystemRegistry.unpublishable("cargo", "notes.txt", content)

    def test_an_ecosystem_without_a_mark_never_reads_one(self) -> None:
        content = Manifests.content("go.mod", MARKED / "tokio-benches-Cargo.toml")
        assert not EcosystemRegistry.unpublishable("gomod", "go.mod", content)
