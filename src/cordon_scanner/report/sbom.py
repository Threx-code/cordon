"""Generating a bill of materials from the resolved dependency graph.

The counterpart to `detect/sbom.py`, which only ever compares an existing
document against this same graph and never produces one -- so a project with
no SBOM of its own had nowhere to start, and "generate one" meant reaching for
Syft or `cdxgen`, both a runtime dependency this project's own governing
constraint (C1) refuses to add for itself. This module is the missing half:
`ScanResult.dependencies` in, a CycloneDX or SPDX document out.

**Deliberately the NTIA minimum elements, not the whole specification.**
CycloneDX and SPDX both support licence data, provenance attestations,
vulnerability annotations and a dozen other optional sections; emitting fields
this project cannot back with real data would be exactly the "confident
wrongness" `detect/sbom.py`'s own docstring warns a stale document produces.
What is emitted -- component name, version, package URL, a supplier-free
declaration, and the dependency graph's own parent/child edges -- is what a
consumer actually needs to identify a component and match it against a
vulnerability feed, which is the whole reason `Advisory.affects` and this
generator both exist.

Not byte-deterministic the way a scan result is (`core/engine.py`'s C5): a
timestamp and a fresh serial number/document namespace are part of both
formats' own specifications, the same way `scripts/generate_sbom.py` -- this
project's own release SBOM generator -- already includes them. The dependency
data itself is unchanged between two runs over identical input; only the
document's own identity fields differ, which is what those fields are for.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Dependency

SPEC_VERSION_CYCLONEDX = "1.5"
SPEC_VERSION_SPDX = "SPDX-2.3"

TOOL_NAME = "cordon-scanner"


def _component_type(dependency: Dependency) -> str:
    return "application" if dependency.local else "library"


def cyclonedx_document(
    dependencies: Sequence[Dependency],
    *,
    root_name: str,
    root_version: str,
    tool_version: str,
    moment: str | None = None,
) -> dict[str, Any]:
    """A CycloneDX 1.5 JSON document describing `dependencies`.

    `root_name`/`root_version` describe the scanned project itself, as the
    document's `metadata.component` -- the thing every other component is a
    dependency *of*. Every resolved `Dependency` becomes one entry in
    `components`, and `parents` (name-keyed, see `ecosystems/base.py`) becomes
    the `dependencies` graph's edges, translated to purls because that is
    CycloneDX's own reference form.
    """
    moment = moment or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    root_purl = f"pkg:generic/{root_name}@{root_version}"
    by_name = {d.name: d for d in dependencies}

    components = [
        {
            "type": _component_type(dependency),
            "bom-ref": dependency.purl,
            "name": dependency.name,
            "version": dependency.version or "",
            "purl": dependency.purl,
            "scope": "excluded" if dependency.scope.value in ("dev", "test") else "required",
        }
        for dependency in dependencies
    ]

    edges: dict[str, set[str]] = {root_purl: set()}
    for dependency in dependencies:
        edges.setdefault(dependency.purl, set())
        if not dependency.parents:
            edges[root_purl].add(dependency.purl)
        for parent_name in dependency.parents:
            parent = by_name.get(parent_name)
            parent_purl = parent.purl if parent is not None else root_purl
            edges.setdefault(parent_purl, set()).add(dependency.purl)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION_CYCLONEDX,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": moment,
            "tools": [{"name": TOOL_NAME, "version": tool_version}],
            "component": {
                "type": "application",
                "bom-ref": root_purl,
                "name": root_name,
                "version": root_version,
            },
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(edges.items())
        ],
    }


def spdx_document(
    dependencies: Sequence[Dependency],
    *,
    root_name: str,
    root_version: str,
    tool_version: str,
    moment: str | None = None,
) -> dict[str, Any]:
    """An SPDX-2.3 JSON document describing `dependencies`.

    SPDX identifies elements by `SPDXID`, not by purl, so each dependency gets
    a synthetic one (`SPDXRef-<index>`) and the purl travels as an
    `externalRefs` entry instead -- the same place `detect/sbom.py`'s own
    reader already looks for it.
    """
    moment = moment or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    root_id = "SPDXRef-Package-root"

    spdx_id_by_name: dict[str, str] = {}
    packages = []
    for index, dependency in enumerate(dependencies):
        spdx_id = f"SPDXRef-Package-{index}"
        spdx_id_by_name[dependency.name] = spdx_id
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": dependency.name,
                "versionInfo": dependency.version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dependency.purl,
                    }
                ],
            }
        )

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for dependency in dependencies:
        child_id = spdx_id_by_name[dependency.name]
        if not dependency.parents:
            relationships.append(
                {
                    "spdxElementId": root_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": child_id,
                }
            )
        for parent_name in dependency.parents:
            parent_id = spdx_id_by_name.get(parent_name, root_id)
            relationships.append(
                {
                    "spdxElementId": parent_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": child_id,
                }
            )

    return {
        "spdxVersion": SPEC_VERSION_SPDX,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{root_name}-{root_version}",
        "documentNamespace": f"https://spdx.org/spdxdocs/{root_name}-{uuid.uuid4()}",
        "creationInfo": {
            "created": moment,
            "creators": [f"Tool: {TOOL_NAME}-{tool_version}"],
        },
        "packages": [
            {
                "SPDXID": root_id,
                "name": root_name,
                "versionInfo": root_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            },
            *packages,
        ],
        "relationships": relationships,
    }


__all__ = [
    "SPEC_VERSION_CYCLONEDX",
    "SPEC_VERSION_SPDX",
    "cyclonedx_document",
    "spdx_document",
]
