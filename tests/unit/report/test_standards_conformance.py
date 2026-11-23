"""One recorded document of each supply-chain standard is read and checked clause by clause.

An in-toto statement and a SLSA provenance come from a genuine recorded attestation (the statement inside its signed
envelope); the Sigstore bundle is that attestation verified offline against the pinned trust root; a CycloneDX and an
SPDX document are invented fixtures. Each is read by the code that reads it for scans, and the two bills of materials
the scanner writes are held to the same clauses.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from cordon_scanner.engine.sbom_ingest import SbomDocument as Reader
from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.provenance.attest import Outcome, SigstoreVerification
from cordon_scanner.intel.provenance.sigstore_bundle import BundleVerifier
from support import ROOT

SIGSTORE = ROOT / "tests" / "unit" / "data" / "sigstore"
STANDARDS = ROOT / "tests" / "unit" / "data" / "standards"


class Recorded:
    @staticmethod
    def attestation() -> dict[str, Any]:
        return json.loads((SIGSTORE / "npm-provenance-dsse.json").read_text(encoding="utf-8"))

    @staticmethod
    def statement() -> dict[str, Any]:
        payload = Recorded.attestation()["bundle"]["dsseEnvelope"]["payload"]
        return json.loads(base64.b64decode(payload))

    @staticmethod
    def document(name: str) -> dict[str, Any]:
        return json.loads((STANDARDS / name).read_text(encoding="utf-8"))

    @staticmethod
    def written(kind: str) -> dict[str, Any]:
        from cordon_scanner.report import sbom

        graph = (
            Dependency(
                purl="pkg:npm/left-pad@1.3.0",
                ecosystem="npm",
                name="left-pad",
                version="1.3.0",
                direct=True,
                scope=Scope.RUNTIME,
            ),
            Dependency(
                purl="pkg:npm/right-pad@2.0.0",
                ecosystem="npm",
                name="right-pad",
                version="2.0.0",
                scope=Scope.RUNTIME,
                parents=("left-pad",),
            ),
        )
        make = (
            sbom.SbomDocument.cyclonedx_document
            if kind == "cyclonedx"
            else sbom.SbomDocument.spdx_document
        )
        return make(
            graph,
            root_name="app",
            root_version="1.0.0",
            tool_version="1.0.0",
            moment="2026-01-01T00:00:00Z",
        )


class TestAnInTotoStatement:
    def test_it_has_the_statement_v1_fields(self) -> None:
        statement = Recorded.statement()
        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        assert isinstance(statement["predicateType"], str) and isinstance(
            statement["predicate"], dict
        )

    def test_every_subject_has_a_name_and_a_hex_digest(self) -> None:
        subjects = Recorded.statement()["subject"]
        assert subjects
        for subject in subjects:
            assert subject["name"] and subject["digest"]
            for algorithm, value in subject["digest"].items():
                assert algorithm and int(value, 16) >= 0

    def test_the_scan_statement_the_scanner_writes_has_the_same_fields(self) -> None:
        from cordon_scanner.report.statement import PREDICATE_TYPE, STATEMENT_TYPE

        assert Recorded.statement()["_type"] == STATEMENT_TYPE
        assert PREDICATE_TYPE.startswith("https://")


class TestASlsaProvenance:
    def test_it_is_the_v1_predicate_with_its_two_required_parts(self) -> None:
        statement = Recorded.statement()
        assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
        assert set(statement["predicate"]) >= {"buildDefinition", "runDetails"}

    def test_the_build_definition_names_its_type_and_parameters(self) -> None:
        definition = Recorded.statement()["predicate"]["buildDefinition"]
        assert definition["buildType"].startswith("https://")
        assert isinstance(definition["externalParameters"], dict)

    def test_the_run_details_name_the_builder(self) -> None:
        assert Recorded.statement()["predicate"]["runDetails"]["builder"]["id"].startswith(
            "https://"
        )


class TestASigstoreBundle:
    def test_its_media_type_is_one_the_verifier_reads(self) -> None:
        assert Recorded.attestation()["bundle"]["mediaType"] in BundleVerifier.MEDIA_TYPES

    def test_it_carries_a_certificate_a_transparency_entry_and_an_envelope(self) -> None:
        bundle = Recorded.attestation()["bundle"]
        assert bundle["verificationMaterial"]["tlogEntries"]
        assert (
            "certificate" in bundle["verificationMaterial"]
            or "x509CertificateChain" in bundle["verificationMaterial"]
        )
        assert bundle["dsseEnvelope"]["signatures"]

    def test_it_verifies_offline_against_the_pinned_trust_root(self) -> None:
        recorded = Recorded.attestation()
        result = SigstoreVerification.verify_for_policy(
            json.dumps(recorded["bundle"]),
            digest_hex=recorded["subject_digest"]["sha512"],
            algorithm="sha512",
            allowed=[
                Recorded.statement()["predicate"]["buildDefinition"]["externalParameters"][
                    "workflow"
                ]["repository"].removeprefix("https://github.com/")
            ],
        )
        assert result.outcome is Outcome.VERIFIED, result.detail


class TestACycloneDxDocument:
    @pytest.mark.parametrize("source", ["recorded", "written"])
    def test_it_has_the_required_fields(self, source: str) -> None:
        document = (
            Recorded.document("cyclonedx-1.5.json")
            if source == "recorded"
            else Recorded.written("cyclonedx")
        )
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] in Reader.CYCLONEDX_VERSIONS
        assert document["serialNumber"].startswith("urn:uuid:") and document["version"] >= 1
        for component in document["components"]:
            assert component["type"] and component["name"]

    @pytest.mark.parametrize("source", ["recorded", "written"])
    def test_the_reader_finds_its_components_and_their_edges(self, source: str) -> None:
        document = (
            Recorded.document("cyclonedx-1.5.json")
            if source == "recorded"
            else Recorded.written("cyclonedx")
        )
        reading = Reader.read(document)
        assert reading.kind.startswith("CycloneDX") and not reading.problems
        assert sorted(c.name for c in reading.components) == ["left-pad", "right-pad"]
        assert all(c.purl for c in reading.components) and reading.graphed


class TestAnSpdxDocument:
    @pytest.mark.parametrize("source", ["recorded", "written"])
    def test_it_has_the_required_fields(self, source: str) -> None:
        document = (
            Recorded.document("spdx-2.3.json") if source == "recorded" else Recorded.written("spdx")
        )
        assert document["spdxVersion"] in Reader.SPDX_VERSIONS
        assert document["SPDXID"] == "SPDXRef-DOCUMENT" and document["documentNamespace"]
        assert document["creationInfo"]["created"] and document["creationInfo"]["creators"]
        for package in document["packages"]:
            assert package["SPDXID"].startswith("SPDXRef-") and package["name"]

    @pytest.mark.parametrize("source", ["recorded", "written"])
    def test_the_reader_finds_its_packages_and_their_edges(self, source: str) -> None:
        document = (
            Recorded.document("spdx-2.3.json") if source == "recorded" else Recorded.written("spdx")
        )
        reading = Reader.read(document)
        assert reading.kind.startswith("SPDX") and not reading.problems
        assert {"left-pad", "right-pad"} <= {c.name for c in reading.components}
        assert reading.graphed
