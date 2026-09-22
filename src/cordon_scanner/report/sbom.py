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

import os
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Dependency

SPEC_VERSION_CYCLONEDX = "1.5"
SPEC_VERSION_SPDX = "SPDX-2.3"

TOOL_NAME = "cordon-scanner"

#: Namespace for the deterministic document identity below. A fixed random
#: UUID, so the name this project derives cannot collide with one derived by
#: anything else from the same component list.
_NAMESPACE = uuid.UUID("6f1e4d2a-9c3b-4f27-8a15-0d8e7b6c5a94")


def _identity(root_purl: str, dependencies: Sequence[Dependency]) -> uuid.UUID:
    """A document id derived from what the document says.

    Both specifications want a unique identity per document, and `uuid4` gives
    one -- at the cost of making the only output of this tool that is not
    reproducible. Two runs over an unchanged tree produced two different
    documents, which breaks the invariant every other output holds to and makes
    an SBOM useless as a thing to diff or to sign.

    A version-5 name is unique per distinct content and identical for identical
    content, which is what the specifications actually need. Two SBOMs of the
    same graph now compare equal; adding one dependency changes the id.
    """
    material = "\n".join([root_purl, *sorted(d.purl for d in dependencies)])
    return uuid.uuid5(_NAMESPACE, material)


def _timestamp(moment: str | None) -> str:
    """The document's timestamp, honouring `SOURCE_DATE_EPOCH`.

    An explicit `moment` wins. Otherwise the reproducible-builds variable is
    read, because a caller who has set it has asked every artefact of this build
    to be reproducible and an SBOM is one of them. With neither, it is now.
    """
    if moment:
        return moment
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.strip().isdigit():
        return datetime.fromtimestamp(int(epoch.strip()), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _component_type(dependency: Dependency) -> str:
    return "application" if dependency.local else "library"


#: Digest length in hex characters, by algorithm, and the CycloneDX spelling of
#: each. A lockfile's integrity string is only emitted as a hash when its length
#: says it is one -- Yarn Berry's cache checksum and Go's `h1:` module digest
#: occupy the same field and are not artefact hashes.
_HASH_ALGORITHMS = {
    "md5": ("MD5", 32),
    "sha1": ("SHA-1", 40),
    "sha256": ("SHA-256", 64),
    "sha512": ("SHA-512", 128),
}


def _hash_of(dependency: Dependency) -> tuple[str, str] | None:
    """A dependency's artefact hash as `(algorithm, lowercase hex)`, or `None`.

    An SBOM without hashes names what is present and proves nothing about it,
    which is the same argument `POLICY.LOCKFILE.INTEGRITY.001` makes about a
    version pin. The data is already parsed from the lockfile; this is what puts
    it in the document.
    """
    from cordon_scanner.detect.registry import _canonical_digest

    parsed = _canonical_digest(dependency.integrity)
    if parsed is None:
        return None
    algorithm, digest = parsed
    spelling = _HASH_ALGORITHMS.get(algorithm)
    return (spelling[0], digest) if spelling else None


def _licence_of(dependency: Dependency) -> str | None:
    """The licence a lockfile recorded, if it recorded one.

    `None` means the format carried no licence offline, not that the dependency
    has none -- so SPDX gets `NOASSERTION` rather than a guess, which is the
    distinction that specification draws for exactly this case.
    """
    licence = (dependency.license or "").strip()
    return licence or None


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
    moment = _timestamp(moment)
    root_purl = f"pkg:generic/{root_name}@{root_version}"
    by_name = _index_by_name(dependencies)

    components = []
    for dependency in dependencies:
        component: dict[str, Any] = {
            "type": _component_type(dependency),
            "bom-ref": dependency.purl,
            "name": dependency.name,
            "version": dependency.version or "",
            "purl": dependency.purl,
            # `excluded` is CycloneDX's own word for this: the specification
            # defines it as documenting "component usage for test and other
            # non-runtime purposes", and says an excluded component is one not
            # reachable in a runtime call graph. `optional` means something
            # else -- installed and callable, just not required.
            "scope": "excluded" if dependency.scope.value in ("dev", "test") else "required",
        }
        digest = _hash_of(dependency)
        if digest is not None:
            component["hashes"] = [{"alg": digest[0], "content": digest[1]}]
        licence = _licence_of(dependency)
        if licence is not None:
            component["licenses"] = [{"license": {"name": licence}}]
        components.append(component)

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
        "serialNumber": f"urn:uuid:{_identity(root_purl, dependencies)}",
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
    moment = _timestamp(moment)
    root_id = "SPDXRef-Package-root"
    root_purl = f"pkg:generic/{root_name}@{root_version}"

    spdx_id_by_name: dict[str, str] = {}
    by_purl: dict[str, str] = {}
    packages = []
    for index, dependency in enumerate(dependencies):
        spdx_id = f"SPDXRef-Package-{index}"
        # Keyed by name for the edge lookup, which is all `parents` records, and
        # by purl so two versions of one package keep separate identities. A
        # name-only index let the later of the two overwrite the earlier and
        # attached every edge to whichever was written last.
        spdx_id_by_name.setdefault(dependency.name, spdx_id)
        by_purl[dependency.purl] = spdx_id
        licence = _licence_of(dependency)
        entry: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": dependency.name,
            "versionInfo": dependency.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            # Required on every package by SPDX 2.3. `NOASSERTION` is the
            # specification's own word for "this document does not say", which
            # is the honest answer when the lockfile carried no licence.
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": licence or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dependency.purl,
                }
            ],
        }
        digest = _hash_of(dependency)
        if digest is not None:
            entry["checksums"] = [
                {"algorithm": digest[0].replace("-", ""), "checksumValue": digest[1]}
            ]
        packages.append(entry)

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
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/{root_name}-{_identity(root_purl, dependencies)}"
        ),
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
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
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


def _index_by_name(dependencies: Sequence[Dependency]) -> dict[str, Dependency]:
    """Dependencies by name, shallowest first.

    `Dependency.parents` records names, so an edge can only be resolved by name
    -- and an npm tree routinely holds several versions of one. Keeping the
    shallowest makes the choice deterministic rather than a function of
    iteration order, which is what the deterministic-output invariant requires.
    """
    index: dict[str, Dependency] = {}
    for dependency in sorted(dependencies, key=lambda d: (d.depth, d.purl)):
        index.setdefault(dependency.name, dependency)
    return index
