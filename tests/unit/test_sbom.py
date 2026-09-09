"""Reconciling a shipped bill of materials against what is actually resolved.

The comparison is one-directional, and that asymmetry is the design rather than
an omission. These tests are mostly about the direction it does *not* look, and
about the difference between a document that says nothing and one that could not
be read -- which would otherwise produce the same, very loud, result.
"""

from __future__ import annotations

import json

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.sbom import SbomDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet


def dependency(name: str) -> Dependency:
    return Dependency(
        purl=f"pkg:npm/{name}@1.0.0",
        ecosystem="npm",
        name=name,
        version="1.0.0",
        direct=True,
        scope=Scope.RUNTIME,
    )


def ids_for(document: str, *names: str, path: str = "bom.json") -> list[str]:
    ctx = ScanContext(
        config=Config.default(),
        rules=RuleSet(RuleLoader.load_builtin()),
        dependencies=tuple(dependency(n) for n in names),
    )
    unit = FileUnit(content=FileContent.from_bytes(path, document.encode("utf-8")))
    return [f.rule_id for f in SbomDetector().inspect(unit, ctx)]


def cyclonedx(*names: str) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": n, "purl": f"pkg:npm/{n}@1.0.0"} for n in names
            ],
        }
    )


def spdx(*names: str) -> str:
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": n,
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": f"pkg:npm/{n}@1.0.0"}
                    ],
                }
                for n in names
            ],
        }
    )


class TestDrift:
    def test_a_missing_component_is_reported(self) -> None:
        assert "SUSPECT.SBOM.DRIFT.001" in ids_for(cyclonedx("express"), "express", "lodash")

    def test_a_complete_document_is_silent(self) -> None:
        assert ids_for(cyclonedx("express", "lodash"), "express", "lodash") == []

    def test_spdx_is_read_too(self) -> None:
        assert ids_for(spdx("express"), "express", "lodash")
        assert ids_for(spdx("express", "lodash"), "express", "lodash") == []

    def test_the_count_and_some_names_are_given(self) -> None:
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            dependencies=(dependency("express"), dependency("lodash"), dependency("chalk")),
        )
        unit = FileUnit(content=FileContent.from_bytes("bom.json", cyclonedx("express").encode()))
        message = next(iter(SbomDetector().inspect(unit, ctx))).message
        assert "2 component(s)" in message
        assert "chalk" in message and "lodash" in message


class TestTheDirectionItDoesNotLook:
    def test_an_sbom_listing_more_than_the_scan_found_is_not_drift(self) -> None:
        """Ordinary: a document may cover another build stage, another
        platform's wheels, or a runtime dependency nothing here pins.
        Reporting it would make every accurate SBOM in a monorepo noisy."""
        assert ids_for(cyclonedx("express", "lodash", "windows-only"), "express", "lodash") == []


class TestUnreadableIsNotEmpty:
    def test_malformed_json_is_reported(self) -> None:
        assert ids_for("{ not json", "express") == ["OPERATIONAL.SBOM.UNREADABLE.001"]

    def test_a_document_with_no_recognised_components_is_reported(self) -> None:
        """An empty inventory and one in a shape this does not read would
        otherwise both report every dependency in the project as missing, which
        is a loud way of saying nothing."""
        assert ids_for(json.dumps({"bomFormat": "CycloneDX"}), "express") == [
            "OPERATIONAL.SBOM.UNREADABLE.001"
        ]

    def test_a_non_object_document_is_reported(self) -> None:
        assert ids_for("[1, 2, 3]", "express") == ["OPERATIONAL.SBOM.UNREADABLE.001"]

    def test_hostile_field_shapes_do_not_raise(self) -> None:
        """The document is written by whoever built the artefact, which for a
        dependency is not somebody this tool trusts."""
        document = json.dumps({"components": "not-a-list", "packages": [None, 5, {"name": 7}]})
        assert ids_for(document, "express") == ["OPERATIONAL.SBOM.UNREADABLE.001"]


class TestRecognition:
    @pytest.mark.parametrize(
        "name",
        ["bom.json", "sbom.json", "app.cdx.json", "release.spdx.json", "x.sbom.json"],
    )
    def test_conventional_names_are_recognised(self, name: str) -> None:
        assert SbomDetector.looks_like_sbom(name)

    @pytest.mark.parametrize("name", ["package.json", "tsconfig.json", "data.json"])
    def test_ordinary_json_is_not_an_sbom(self, name: str) -> None:
        assert not SbomDetector.looks_like_sbom(name)
        assert ids_for(cyclonedx("express"), "express", "lodash", path=name) == []
