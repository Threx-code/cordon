"""CSAF 2.0 VEX documents applied with `--vex`, beside OpenVEX and CycloneDX."""

from __future__ import annotations

import pytest

from cordon_scanner.core.vex import VexDocuments, VexError


class CsafHelpers:
    """A CSAF VEX document the shape a vendor publishes: a product tree, then statuses."""

    @staticmethod
    def document(**vulnerability) -> dict:
        return {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "acme-app VEX",
                "publisher": {"name": "Acme"},
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Acme",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "1.0",
                                "product": {
                                    "product_id": "APP-1",
                                    "name": "acme-app 1.0",
                                    "product_identification_helper": {
                                        "purl": "pkg:npm/acme-app@1.0.0"
                                    },
                                },
                            },
                        ],
                    }
                ],
                "full_product_names": [
                    {
                        "product_id": "LODASH",
                        "name": "lodash 4.17.20",
                        "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.20"},
                    }
                ],
                "relationships": [
                    {
                        "category": "default_component_of",
                        "product_reference": "LODASH",
                        "relates_to_product_reference": "APP-1",
                        "full_product_name": {
                            "product_id": "APP-1:LODASH",
                            "name": "lodash in acme-app",
                        },
                    }
                ],
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "ids": [{"system_name": "GitHub", "text": "GHSA-35jh-r3h4-6jhm"}],
                    **vulnerability,
                }
            ],
        }


class TestCsaf:
    @pytest.mark.conformance("x", "x.policy")
    def test_known_not_affected_with_its_justification_and_impact(self) -> None:
        statements = VexDocuments.parse(
            CsafHelpers.document(
                product_status={
                    "known_not_affected": ["APP-1:LODASH"],
                    "under_investigation": ["APP-1"],
                },
                flags=[
                    {
                        "label": "vulnerable_code_not_in_execute_path",
                        "product_ids": ["APP-1:LODASH"],
                    }
                ],
                threats=[
                    {
                        "category": "impact",
                        "details": "_.template is never called",
                        "product_ids": ["APP-1:LODASH"],
                    }
                ],
            ),
            "acme.csaf.json",
        )
        ruled = [s for s in statements if s.status == "not_affected"]
        assert len(ruled) == 1
        statement = ruled[0]
        # The relationship's combined product stands for the component it names.
        assert statement.products == ("pkg:npm/lodash@4.17.20",)
        assert {"CVE-2021-23337", "GHSA-35JH-R3H4-6JHM"} <= statement.vulnerabilities
        assert (statement.justification, statement.detail) == (
            "vulnerable_code_not_in_execute_path",
            "_.template is never called",
        )
        assert statement.covers({"CVE-2021-23337"}, "pkg:npm/lodash@4.17.20")
        assert not statement.covers({"CVE-2021-23337"}, "pkg:npm/lodash@4.17.21")
        assert [s.status for s in statements if s.products == ("pkg:npm/acme-app@1.0.0",)] == [
            "under_investigation"
        ]

    def test_fixed_and_affected(self) -> None:
        statements = VexDocuments.parse(
            CsafHelpers.document(product_status={"fixed": ["LODASH"], "known_affected": ["APP-1"]}),
            "s",
        )
        assert sorted((s.status, s.products[0]) for s in statements) == [
            ("affected", "pkg:npm/acme-app@1.0.0"),
            ("fixed", "pkg:npm/lodash@4.17.20"),
        ]

    def test_a_product_with_no_purl_is_not_guessed(self) -> None:
        document = CsafHelpers.document(product_status={"known_not_affected": ["UNKNOWN-ID"]})
        assert VexDocuments.parse(document, "s") == []

    def test_an_unknown_document_is_refused(self) -> None:
        with pytest.raises(VexError, match="CSAF"):
            VexDocuments.parse({"document": {"csaf_version": "1.0"}}, "s")
