"""Generating CycloneDX and SPDX documents from a resolved dependency graph.

`detect/sbom.py` only ever compares an existing document against this same
graph; this is the generator that gives a project with none somewhere to
start. Fixtures build a small graph by hand -- a direct dependency with one
transitive child -- because the shape of the relationship graph is the part
worth getting right, not any one ecosystem's parsing.
"""

from __future__ import annotations

from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.report import sbom

FIXED_MOMENT = "2026-01-01T00:00:00Z"


def graph() -> tuple[Dependency, ...]:
    return (
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
            direct=False,
            scope=Scope.RUNTIME,
            parents=("left-pad",),
        ),
        Dependency(
            purl="pkg:npm/only-in-tests@1.0.0",
            ecosystem="npm",
            name="only-in-tests",
            version="1.0.0",
            direct=True,
            scope=Scope.TEST,
        ),
    )


class TestCycloneDx:
    def test_it_declares_the_format_and_spec_version(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == sbom.SPEC_VERSION_CYCLONEDX

    def test_every_dependency_becomes_one_component(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        names = {c["name"] for c in doc["components"]}
        assert names == {"left-pad", "right-pad", "only-in-tests"}

    def test_every_component_carries_its_purl(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        purls = {c["purl"] for c in doc["components"]}
        assert purls == {
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/right-pad@2.0.0",
            "pkg:npm/only-in-tests@1.0.0",
        }

    def test_a_direct_dependency_hangs_off_the_root(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        root_ref = doc["metadata"]["component"]["bom-ref"]
        root_edges = next(e for e in doc["dependencies"] if e["ref"] == root_ref)
        assert "pkg:npm/left-pad@1.3.0" in root_edges["dependsOn"]
        # A transitive child (right-pad) is not a direct edge of the root.
        assert "pkg:npm/right-pad@2.0.0" not in root_edges["dependsOn"]

    def test_a_transitive_dependency_hangs_off_its_parent(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        parent_edges = next(e for e in doc["dependencies"] if e["ref"] == "pkg:npm/left-pad@1.3.0")
        assert parent_edges["dependsOn"] == ["pkg:npm/right-pad@2.0.0"]

    def test_test_scope_is_excluded_not_required(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        test_component = next(c for c in doc["components"] if c["name"] == "only-in-tests")
        runtime_component = next(c for c in doc["components"] if c["name"] == "left-pad")
        assert test_component["scope"] == "excluded"
        assert runtime_component["scope"] == "required"

    def test_the_timestamp_is_used_verbatim_when_given(self) -> None:
        doc = sbom.cyclonedx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        assert doc["metadata"]["timestamp"] == FIXED_MOMENT

    def test_an_empty_graph_still_produces_a_valid_root_only_document(self) -> None:
        doc = sbom.cyclonedx_document(
            (), root_name="app", root_version="1.0.0", tool_version="0.4.0", moment=FIXED_MOMENT
        )
        assert doc["components"] == []
        assert doc["metadata"]["component"]["name"] == "app"


class TestSpdx:
    def test_it_declares_the_spec_version(self) -> None:
        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        assert doc["spdxVersion"] == sbom.SPEC_VERSION_SPDX

    def test_every_dependency_becomes_one_package(self) -> None:
        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        # +1 for the synthetic root package.
        assert len(doc["packages"]) == len(graph()) + 1

    def test_every_package_carries_its_purl_as_an_external_ref(self) -> None:
        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        locators = {
            ref["referenceLocator"]
            for package in doc["packages"]
            for ref in package.get("externalRefs", [])
        }
        assert "pkg:npm/left-pad@1.3.0" in locators
        assert "pkg:npm/right-pad@2.0.0" in locators

    def test_the_document_describes_the_root_package(self) -> None:
        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        describes = [r for r in doc["relationships"] if r["relationshipType"] == "DESCRIBES"]
        assert len(describes) == 1
        assert describes[0]["spdxElementId"] == "SPDXRef-DOCUMENT"

    def test_a_transitive_dependency_is_related_to_its_parent_not_the_root(self) -> None:
        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        left_pad_id = next(p["SPDXID"] for p in doc["packages"] if p.get("name") == "left-pad")
        right_pad_id = next(p["SPDXID"] for p in doc["packages"] if p.get("name") == "right-pad")
        depends = [
            r
            for r in doc["relationships"]
            if r["relationshipType"] == "DEPENDS_ON" and r["relatedSpdxElement"] == right_pad_id
        ]
        assert len(depends) == 1
        assert depends[0]["spdxElementId"] == left_pad_id

    def test_the_output_is_json_serialisable(self) -> None:
        import json

        doc = sbom.spdx_document(
            graph(),
            root_name="app",
            root_version="1.0.0",
            tool_version="0.4.0",
            moment=FIXED_MOMENT,
        )
        json.dumps(doc)  # must not raise
