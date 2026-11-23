"""An SPDX document round-trips to the component list and back.

The writer (`report/sbom.py`) makes an SPDX 2.3 document from a dependency graph; the reader (`engine/sbom_ingest.py`) turns an SPDX document into
a component list and its edges. The test sends a graph through both directions: graph, document, component list, graph, document. The second
document has the same packages (name, version, purl, licence, checksum) and the same relationships as the first, and a document written by
another tool in SPDX 2.2 reads to the same list.
"""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.engine.sbom_ingest import SbomDocument as Reader
from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.report import sbom

MOMENT = "2026-01-01T00:00:00Z"


class Graphs:
    @staticmethod
    def graph() -> tuple[Dependency, ...]:
        return (
            Dependency(
                purl="pkg:npm/left-pad@1.3.0",
                ecosystem="npm",
                name="left-pad",
                version="1.3.0",
                direct=True,
                scope=Scope.RUNTIME,
                integrity="sha512-AAAA",
            ),
            Dependency(
                purl="pkg:npm/right-pad@2.0.0",
                ecosystem="npm",
                name="right-pad",
                version="2.0.0",
                scope=Scope.RUNTIME,
                parents=("left-pad",),
            ),
            Dependency(
                purl="pkg:pypi/requests@2.32.0",
                ecosystem="pypi",
                name="requests",
                version="2.32.0",
                direct=True,
                scope=Scope.RUNTIME,
            ),
        )

    @staticmethod
    def write(graph: tuple[Dependency, ...]) -> dict[str, Any]:
        return sbom.SbomDocument.spdx_document(
            graph, root_name="app", root_version="1.0.0", tool_version="0.8.0", moment=MOMENT
        )

    @staticmethod
    def read(document: dict[str, Any]):
        return Reader.read(json.loads(json.dumps(document)))

    @staticmethod
    def graph_of(reading) -> tuple[Dependency, ...]:
        """The component list as a graph again: each component with the names of the components that list it as a dependency."""
        name_of = {component.key: component.name for component in reading.components}
        parents: dict[str, list[str]] = {}
        for parent, children in reading.edges.items():
            for child in children:
                if parent in name_of:
                    parents.setdefault(child, []).append(name_of[parent])
        return tuple(
            Dependency(
                purl=component.purl or "",
                ecosystem=component.ecosystem or "",
                name=component.name,
                version=component.version,
                direct=component.key in reading.roots,
                scope=component.scope,
                integrity=component.integrity,
                parents=tuple(sorted(parents.get(component.key, []))),
            )
            for component in reading.components
        )

    @staticmethod
    def shape(document: dict[str, Any]) -> tuple[list[tuple[Any, ...]], list[tuple[str, str, str]]]:
        """What a document says, without its synthetic ids: its packages, and its relationships by the package names."""
        name_of = {p["SPDXID"]: p["name"] for p in document["packages"]}
        packages = sorted(
            (
                p["name"],
                p["versionInfo"],
                p["externalRefs"][0]["referenceLocator"] if p.get("externalRefs") else None,
                p["licenseDeclared"],
                json.dumps(p.get("checksums"), sort_keys=True),
            )
            for p in document["packages"]
        )
        relationships = sorted(
            (
                name_of.get(r["spdxElementId"], r["spdxElementId"]),
                r["relationshipType"],
                name_of.get(r["relatedSpdxElement"], r["relatedSpdxElement"]),
            )
            for r in document["relationships"]
        )
        return packages, relationships


class TestTheRoundTrip:
    def test_the_component_list_is_what_the_graph_had(self) -> None:
        reading = Graphs.read(Graphs.write(Graphs.graph()))
        listed = {(c.name, c.version, c.purl) for c in reading.components}
        assert {
            ("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
            ("right-pad", "2.0.0", "pkg:npm/right-pad@2.0.0"),
            ("requests", "2.32.0", "pkg:pypi/requests@2.32.0"),
        } <= listed
        assert reading.problems == []

    def test_document_to_list_to_document_says_the_same(self) -> None:
        first = Graphs.write(Graphs.graph())
        again = Graphs.write(Graphs.graph_of(Graphs.read(first)))
        assert Graphs.shape(again) == Graphs.shape(first)

    def test_a_second_round_changes_nothing(self) -> None:
        first = Graphs.write(Graphs.graph())
        second = Graphs.write(Graphs.graph_of(Graphs.read(first)))
        third = Graphs.write(Graphs.graph_of(Graphs.read(second)))
        assert Graphs.shape(third) == Graphs.shape(second)

    def test_an_edge_is_kept_across_the_round(self) -> None:
        reading = Graphs.read(Graphs.write(Graphs.graph()))
        rebuilt = {d.name: d.parents for d in Graphs.graph_of(reading)}
        assert rebuilt["right-pad"] == ("left-pad",)
        assert rebuilt["left-pad"] == ()

    def test_a_document_of_spdx_2_2_reads_to_the_same_list(self) -> None:
        document = Graphs.write(Graphs.graph())
        old = {**document, "spdxVersion": "SPDX-2.2"}
        assert {(c.name, c.version, c.purl) for c in Graphs.read(old).components} == {
            (c.name, c.version, c.purl) for c in Graphs.read(document).components
        }

    def test_a_version_it_does_not_read_is_a_named_problem_not_a_silent_list(self) -> None:
        reading = Graphs.read({**Graphs.write(Graphs.graph()), "spdxVersion": "SPDX-3.0"})
        assert reading.problems
