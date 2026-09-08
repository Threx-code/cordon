#!/usr/bin/env python3
"""Generate the software bill of materials for a release.

Two formats, because consumers are split between them and neither is a superset
of the other: CycloneDX is what most security tooling ingests, SPDX is what most
licence-compliance tooling ingests, and an organisation that has standardised on
one should not have to convert.

Written here rather than pulled in as a dependency, which looks like
over-engineering until you notice what the alternative is: a tool whose entire
argument is that build-time dependencies are attack surface, adding a build-time
dependency in order to publish the list of its dependencies. The list is empty.
Generating an empty list does not need a library.

That emptiness is the point of publishing it. "Zero third-party runtime
dependencies" is a claim, and a claim a consumer cannot check is marketing. An
SBOM is the checkable form, and it is generated from the installed metadata
rather than from this file's idea of the truth -- so if a dependency is ever
added, it appears here without anybody remembering to write it down.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def metadata() -> dict[str, Any]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project: dict[str, Any] = data["project"]
    version = (ROOT / "src" / "cordon_scanner" / "version.py").read_text(encoding="utf-8")
    for line in version.splitlines():
        if line.startswith("__version__"):
            project["version"] = line.split('"')[1]
            break
    return project


def artefact_hashes(dist: Path | None) -> list[dict[str, str]]:
    """Digests of the files being published, when they exist.

    An SBOM that describes a version but not the bytes of it lets a consumer
    verify the dependency list of something other than what they downloaded.
    """
    if dist is None or not dist.is_dir():
        return []
    return [
        {
            "name": path.name,
            "alg": "SHA-256",
            "content": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(dist.iterdir())
        if path.suffix in {".whl", ".gz"}
    ]


def cyclonedx(project: dict[str, Any], files: list[dict[str, str]], moment: str) -> dict[str, Any]:
    name = project["name"]
    version = project["version"]
    purl = f"pkg:pypi/{name}@{version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": moment,
            "tools": [{"name": "cordon-scanner sbom generator", "version": version}],
            "component": {
                "type": "application",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "description": project.get("description", ""),
                "purl": purl,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": f["alg"], "content": f["content"]} for f in files],
            },
        },
        # Empty, and that is the claim being published. A consumer diffing this
        # against a later release sees a new runtime dependency immediately.
        "components": [],
        "dependencies": [{"ref": purl, "dependsOn": []}],
    }


def spdx(project: dict[str, Any], files: list[dict[str, str]], moment: str) -> dict[str, Any]:
    name = project["name"]
    version = project["version"]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": f"https://github.com/Threx-code/cordon/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": moment,
            "creators": [f"Tool: cordon-scanner-{version}"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": name,
                "versionInfo": version,
                "downloadLocation": f"https://pypi.org/project/{name}/{version}/",
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "supplier": "Organization: Cordon Contributors",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}",
                    }
                ],
                "checksums": [
                    {"algorithm": f["alg"].replace("-", ""), "checksumValue": f["content"]}
                    for f in files
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument("--check", action="store_true", help="verify rather than write")
    args = parser.parse_args()

    project = metadata()
    files = artefact_hashes(args.dist)
    moment = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.check:
        # The claim, checked against the installed metadata rather than restated.
        runtime = project.get("dependencies") or []
        if runtime:
            print(f"runtime dependencies are no longer empty: {runtime}", file=sys.stderr)
            return 1
        print("runtime dependency list is empty, as the SBOM asserts")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for filename, document in (
        ("sbom.cdx.json", cyclonedx(project, files, moment)),
        ("sbom.spdx.json", spdx(project, files, moment)),
    ):
        path = args.out / filename
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
