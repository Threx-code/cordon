"""A bill of materials, read as an inventory.

`cordon scan supplier.cdx.json` scans what a CycloneDX (JSON, 1.2 to 1.6) or SPDX (JSON, 2.2 and
2.3) document says an artefact contains: each component becomes a dependency record -- its
ecosystem from its Package URL, its version, its hashes as integrity, its licence, its place in the
document's dependency graph -- and every record says it came from that document and the tool that
wrote it. The advisory, malware, licence, policy and (with --online) registry checks then run on
the components as they would on a lockfile's.

A document is validated before it is believed: an unsupported format version, a component with no
name, a Package URL that does not parse, a dependency edge naming a component the document does not
hold -- each is reported, the scan marked incomplete, and nothing guessed. In a directory scan an
SBOM is compared with what the scan resolved instead (`detect/sbom.py`), so nothing is counted twice.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

from cordon_scanner.core.models import Dependency, Scope

MAX_COMPONENTS: Final = 50_000


@dataclass(frozen=True)
class PackageUrl:
    """`pkg:type/namespace/name@version?qualifiers#subpath`, decoded."""

    type: str
    namespace: str
    name: str
    version: str | None
    qualifiers: dict[str, str] = field(default_factory=dict)

    PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^pkg:([a-zA-Z][a-zA-Z0-9.+-]*)/([^@?#]+?)(?:@([^?#]+))?(?:\?([^#]*))?(?:#.*)?$"
    )

    #: Package URL types, as the ecosystems Cordon matches them under.
    ECOSYSTEMS: ClassVar[dict[str, str]] = {
        "npm": "npm",
        "pypi": "pypi",
        "cargo": "cargo",
        "golang": "gomod",
        "maven": "maven",
        "nuget": "nuget",
        "gem": "rubygems",
        "composer": "composer",
        "hex": "hex",
        "pub": "pub",
        "swift": "swift",
        "cocoapods": "cocoapods",
        "conda": "conda",
        "cran": "cran",
        "hackage": "hackage",
        "conan": "conan",
        "github": "actions",
        "githubactions": "actions",
        "docker": "image",
        "oci": "image",
        "deb": "deb",
        "apk": "apk",
        "rpm": "rpm",
        "brew": "homebrew",
        "bazel": "bazel",
        "julia": "julia",
        "opam": "opam",
        "vcpkg": "vcpkg",
    }

    @staticmethod
    def parse(text: str) -> PackageUrl | None:
        found = PackageUrl.PATTERN.match(text.strip()) if len(text) <= 2048 else None
        if found is None:
            return None
        kind, path, version, query = found.groups()
        parts = [urllib.parse.unquote(p) for p in path.strip("/").split("/") if p]
        if not parts:
            return None
        qualifiers = dict(urllib.parse.parse_qsl(query or "", keep_blank_values=False))
        return PackageUrl(
            kind.lower(),
            "/".join(parts[:-1]),
            parts[-1],
            urllib.parse.unquote(version) if version else None,
            qualifiers,
        )

    @property
    def ecosystem(self) -> str | None:
        return PackageUrl.ECOSYSTEMS.get(self.type)

    @property
    def package_name(self) -> str:
        """The name the ecosystem itself uses: `@scope/name`, `group:artifact`, a module path."""
        if not self.namespace:
            return self.name
        if self.type == "maven":
            return f"{self.namespace}:{self.name}"
        if self.type in (
            "deb",
            "apk",
            "rpm",
            "conda",
            "cran",
            "hackage",
            "cargo",
            "pypi",
            "gem",
            "nuget",
            "hex",
            "pub",
            "cocoapods",
            "conan",
            "brew",
        ):
            # The namespace is the distribution or channel; the package's own name is the name.
            return self.name
        if self.type in ("docker", "oci"):
            host = self.qualifiers.get("repository_url", "").split("/", 1)[0]
            return (
                f"{host}/{self.namespace}/{self.name}"
                if host and host not in ("docker.io", "index.docker.io")
                else f"{self.namespace}/{self.name}".removeprefix("library/")
            )
        return f"{self.namespace}/{self.name}"


@dataclass
class SbomComponent:
    key: str
    name: str
    version: str | None
    ecosystem: str | None
    purl: str | None
    integrity: str | None
    licence: str | None
    scope: Scope = Scope.RUNTIME


@dataclass(frozen=True)
class ListedVulnerability:
    """A vulnerability the document itself names, and the components it says it affects."""

    identifier: str
    aliases: frozenset[str]
    severity: str | None
    state: str | None
    """CycloneDX's analysis state: `not_affected`, `exploitable`, `in_triage`, ..."""
    affects: tuple[str, ...]
    reference: str | None


@dataclass
class SbomReading:
    """What a document says, and what in it could not be believed."""

    kind: str
    tool: str
    components: list[SbomComponent] = field(default_factory=list)
    vulnerabilities: list[ListedVulnerability] = field(default_factory=list)
    roots: set[str] = field(default_factory=set)
    edges: dict[str, list[str]] = field(default_factory=dict)
    graphed: bool = False
    problems: list[str] = field(default_factory=list)


class SbomDocument:
    """CycloneDX and SPDX JSON, read and validated."""

    CYCLONEDX_VERSIONS: ClassVar[frozenset[str]] = frozenset({"1.2", "1.3", "1.4", "1.5", "1.6"})
    SEVERITIES: ClassVar[tuple[str, ...]] = ("critical", "high", "medium", "low")
    ADVISORY: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d{1,7}|GO-\d{4}-\d{1,7}|RUSTSEC-\d{4}-\d{4})\b"
    )
    #: CycloneDX component types that describe the artefact's surroundings, not a package in it:
    #: the operating system (whose packages are listed in their own right), a file, data.
    NOT_PACKAGES: ClassVar[frozenset[str]] = frozenset(
        {"operating-system", "file", "data", "machine-learning-model", "cryptographic-asset"}
    )
    SPDX_VERSIONS: ClassVar[frozenset[str]] = frozenset({"SPDX-2.2", "SPDX-2.3"})
    HASHES: ClassVar[dict[str, str]] = {
        "SHA-1": "sha1",
        "SHA1": "sha1",
        "SHA-256": "sha256",
        "SHA256": "sha256",
        "SHA-384": "sha384",
        "SHA384": "sha384",
        "SHA-512": "sha512",
        "SHA512": "sha512",
    }
    #: Preferred when a component lists several: the strongest the format records.
    STRENGTH: ClassVar[tuple[str, ...]] = ("sha512", "sha384", "sha256", "sha1")

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def kind(data: Any) -> str | None:
        if not isinstance(data, dict):
            return None
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if isinstance(data.get("spdxVersion"), str) and isinstance(data.get("SPDXID"), str):
            return "spdx"
        return None

    @staticmethod
    def named(path: str) -> bool:
        """Named as a bill of materials is: `bom.json`, `sbom.json`, `*.cdx.json`, `*.spdx.json`."""
        from cordon_scanner.detect.sbom import SBOM_NAMES, SBOM_SUFFIXES

        base = path.rpartition("/")[2].rpartition("!")[2].lower()
        return base in SBOM_NAMES or base.endswith(SBOM_SUFFIXES)

    @staticmethod
    def recognise(text: str, path: str = "") -> tuple[Any, str | None]:
        """`(document, None)` for a bill of materials; `(None, why)` for a file that is named as
        one or begins like one and cannot be read; `(None, None)` for anything else."""
        looks = text.lstrip().startswith("{") and ('"bomFormat"' in text or '"spdxVersion"' in text)
        if not looks and not SbomDocument.named(path):
            return None, None
        try:
            data = json.loads(text)
        except ValueError as exc:
            return None, f"it is not valid JSON ({str(exc).split(':', 1)[0]})"
        if SbomDocument.kind(data) is None:
            return (
                None,
                "it is neither a CycloneDX document (`bomFormat`) nor an SPDX one (`spdxVersion`, `SPDXID`)",
            )
        return data, None

    @staticmethod
    def read(data: dict[str, Any]) -> SbomReading:
        if SbomDocument.kind(data) == "cyclonedx":
            return SbomDocument._cyclonedx(data)
        return SbomDocument._spdx(data)

    @staticmethod
    def _digest(hashes: list[tuple[str, str]]) -> str | None:
        found = {
            SbomDocument.HASHES.get(algorithm.upper()): value.lower()
            for algorithm, value in hashes
            if re.fullmatch(r"[0-9a-fA-F]{40,128}", value)
        }
        best = next((a for a in SbomDocument.STRENGTH if found.get(a)), None)
        return f"{best}:{found[best]}" if best else None

    @staticmethod
    def _component(
        key: str,
        name: Any,
        version: Any,
        purl_text: Any,
        hashes: list[tuple[str, str]],
        licence: str | None,
        scope: Scope,
        problems: list[str],
    ) -> SbomComponent | None:
        if not isinstance(name, str) or not name.strip():
            problems.append(f"a component ({key[:60]}) has no name")
            return None
        purl = PackageUrl.parse(purl_text) if isinstance(purl_text, str) and purl_text else None
        if isinstance(purl_text, str) and purl_text and purl is None:
            problems.append(f"{name[:60]}'s Package URL does not parse")
            return None
        if purl is None or purl.ecosystem is None:
            # No Package URL, or a type no ecosystem here reads: nothing to match it against, and
            # an ecosystem guessed from a name would be matched against the wrong advisories.
            problems.append(
                f"{name[:60]} has {'no Package URL' if purl is None else f'a Package URL of type {purl.type!r}, which no ecosystem here reads'}"
            )
            return None
        stated = version if isinstance(version, str) and version.strip() else None
        return SbomComponent(
            key=key,
            name=purl.package_name if purl else name.strip(),
            version=(purl.version if purl and purl.version else stated),
            ecosystem=purl.ecosystem if purl else None,
            purl=purl_text if purl else None,
            integrity=SbomDocument._digest(hashes),
            licence=licence,
            scope=scope,
        )

    @staticmethod
    def _cyclonedx(data: dict[str, Any]) -> SbomReading:
        metadata = SbomDocument._mapping(data.get("metadata"))
        tools = metadata.get("tools")
        names: list[str] = []
        entries = tools.get("components") if isinstance(tools, dict) else tools
        for tool in entries if isinstance(entries, list) else []:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                names.append(f"{tool['name']} {tool.get('version', '')}".strip())
        reading = SbomReading(
            kind=f"CycloneDX {data.get('specVersion', '?')}",
            tool=", ".join(names) or "an unnamed tool",
        )
        if str(data.get("specVersion")) not in SbomDocument.CYCLONEDX_VERSIONS:
            reading.problems.append(
                f"CycloneDX specVersion {str(data.get('specVersion'))[:20]!r} is not one this reads (1.2 to 1.6)"
            )
            return reading
        flat: list[dict[str, Any]] = []
        pending = [c for c in data.get("components") or [] if isinstance(c, dict)]
        while pending and len(flat) < MAX_COMPONENTS:
            component = pending.pop(0)
            flat.append(component)
            pending.extend(c for c in component.get("components") or [] if isinstance(c, dict))
        seen: set[str] = set()
        for index, component in enumerate(flat):
            if component.get("type") in SbomDocument.NOT_PACKAGES:
                continue
            key = str(component.get("bom-ref") or component.get("purl") or f"#{index}")
            if key in seen:
                reading.problems.append(f"the bom-ref {key[:60]!r} names two components")
                continue
            seen.add(key)
            hashes = [
                (str(h.get("alg", "")), str(h.get("content", "")))
                for h in component.get("hashes") or []
                if isinstance(h, dict)
            ]
            licences = [
                str(
                    (entry.get("license") or {}).get("id")
                    or (entry.get("license") or {}).get("name")
                    or entry.get("expression")
                    or ""
                )
                for entry in component.get("licenses") or []
                if isinstance(entry, dict)
            ]
            scope = {"optional": Scope.OPTIONAL, "excluded": Scope.DEV}.get(
                str(component.get("scope", "")), Scope.RUNTIME
            )
            parsed = SbomDocument._component(
                key,
                component.get("name"),
                component.get("version"),
                component.get("purl"),
                hashes,
                " AND ".join(x for x in licences if x) or None,
                scope,
                reading.problems,
            )
            if parsed is not None:
                reading.components.append(parsed)
        root = SbomDocument._mapping(metadata.get("component"))
        root_key = str(root.get("bom-ref") or root.get("purl") or "")
        dependencies = [
            d
            for d in data.get("dependencies") or []
            if isinstance(d, dict) and isinstance(d.get("ref"), str)
        ]
        if dependencies:
            reading.graphed = True
            known = {c.key for c in reading.components} | {root_key}
            for entry in dependencies:
                targets = [str(t) for t in entry.get("dependsOn") or [] if isinstance(t, str)]
                unknown = [t for t in targets if t not in known]
                if unknown:
                    reading.problems.append(
                        f"{entry['ref'][:60]} depends on {unknown[0][:60]!r}, which the document does not hold"
                    )
                reading.edges.setdefault(entry["ref"], []).extend(t for t in targets if t in known)
            reading.roots = set(reading.edges.get(root_key, [])) if root_key else set()
        for entry in [v for v in data.get("vulnerabilities") or [] if isinstance(v, dict)][
            :MAX_COMPONENTS
        ]:
            identifier = entry.get("id")
            if not isinstance(identifier, str) or not identifier.strip():
                reading.problems.append("a listed vulnerability has no id")
                continue
            affects = tuple(
                str(a.get("ref"))
                for a in entry.get("affects") or []
                if isinstance(a, dict) and isinstance(a.get("ref"), str)
            )
            ratings = [
                str(r.get("severity")).lower()
                for r in entry.get("ratings") or []
                if isinstance(r, dict) and isinstance(r.get("severity"), str)
            ]
            source = SbomDocument._mapping(entry.get("source"))
            aliases = frozenset(
                str(r.get("id"))
                for r in entry.get("references") or []
                if isinstance(r, dict) and isinstance(r.get("id"), str)
            )
            reading.vulnerabilities.append(
                ListedVulnerability(
                    identifier=identifier.strip()[:100],
                    aliases=aliases,
                    severity=next((r for r in ratings if r in SbomDocument.SEVERITIES), None),
                    state=str(SbomDocument._mapping(entry.get("analysis")).get("state") or "")
                    or None,
                    affects=affects,
                    reference=str(source.get("url"))
                    if isinstance(source.get("url"), str)
                    else None,
                )
            )
        return reading

    @staticmethod
    def _spdx(data: dict[str, Any]) -> SbomReading:
        info = SbomDocument._mapping(data.get("creationInfo"))
        creators = [
            str(c).removeprefix("Tool:").strip()
            for c in info.get("creators") or []
            if isinstance(c, str) and c.startswith("Tool:")
        ]
        reading = SbomReading(
            kind=str(data.get("spdxVersion"))[:20], tool=", ".join(creators) or "an unnamed tool"
        )
        if data.get("spdxVersion") not in SbomDocument.SPDX_VERSIONS:
            reading.problems.append(
                f"{reading.kind!r} is not a version this reads (SPDX-2.2, SPDX-2.3)"
            )
            return reading
        described = {str(d) for d in data.get("documentDescribes") or [] if isinstance(d, str)}
        relationships = [r for r in data.get("relationships") or [] if isinstance(r, dict)]
        for relation in relationships:
            if relation.get("relationshipType") == "DESCRIBES" and relation.get(
                "spdxElementId"
            ) == data.get("SPDXID"):
                described.add(str(relation.get("relatedSpdxElement")))
        packages = [p for p in data.get("packages") or [] if isinstance(p, dict)][:MAX_COMPONENTS]
        seen: set[str] = set()
        for index, package in enumerate(packages):
            key = str(package.get("SPDXID") or f"#{index}")
            if key in seen:
                reading.problems.append(f"the SPDXID {key[:60]!r} names two packages")
                continue
            seen.add(key)
            if key in described:
                continue  # The artefact the document describes, not one of its components.
            purl = next(
                (
                    str(ref.get("referenceLocator"))
                    for ref in package.get("externalRefs") or []
                    if isinstance(ref, dict) and ref.get("referenceType") == "purl"
                ),
                None,
            )
            hashes = [
                (str(c.get("algorithm", "")), str(c.get("checksumValue", "")))
                for c in package.get("checksums") or []
                if isinstance(c, dict)
            ]
            licence = next(
                (
                    str(package[k])
                    for k in ("licenseConcluded", "licenseDeclared")
                    if isinstance(package.get(k), str) and package[k] not in ("NOASSERTION", "NONE")
                ),
                None,
            )
            parsed = SbomDocument._component(
                key,
                package.get("name"),
                package.get("versionInfo"),
                purl,
                hashes,
                licence,
                Scope.RUNTIME,
                reading.problems,
            )
            if parsed is not None:
                reading.components.append(parsed)
                # SPDX names a package's advisories as SECURITY references.
                for ref in package.get("externalRefs") or []:
                    if not isinstance(ref, dict) or ref.get("referenceCategory") not in (
                        "SECURITY",
                        "SECURITY_OTHER",
                    ):
                        continue
                    locator = str(ref.get("referenceLocator") or "")
                    found = SbomDocument.ADVISORY.search(locator)
                    if found and ref.get("referenceType") in ("advisory", "url"):
                        reading.vulnerabilities.append(
                            ListedVulnerability(
                                found.group(0),
                                frozenset(),
                                None,
                                None,
                                (key,),
                                locator if locator.startswith("https://") else None,
                            )
                        )
        known = {c.key for c in reading.components} | described
        for relation in relationships:
            kind = relation.get("relationshipType")
            source, target = (
                str(relation.get("spdxElementId")),
                str(relation.get("relatedSpdxElement")),
            )
            # CONTAINS says a package is inside the artefact, not that anything depends on it.
            if kind == "DEPENDENCY_OF":
                source, target = target, source
            elif kind != "DEPENDS_ON":
                continue
            if source not in known or target not in known:
                reading.problems.append(
                    f"a {kind} relationship names {source if source not in known else target!r}, which the document does not hold"
                )
                continue
            reading.graphed = True
            reading.edges.setdefault(source, []).append(target)
        reading.roots = {t for root in described for t in reading.edges.get(root, [])}
        return reading


class SbomInventory:
    """A reading as dependency records, attributed to the document."""

    @staticmethod
    def dependencies(path: str, reading: SbomReading) -> tuple[Dependency, ...]:
        by_key = {c.key: c for c in reading.components}
        depth: dict[str, int] = {}
        parents: dict[str, set[str]] = {c.key: set() for c in reading.components}
        roots = [k for k in reading.roots if k in by_key] if reading.graphed else list(by_key)
        if reading.graphed and not roots:
            # A graph with no root named: what nothing depends on stands for it.
            required = {t for targets in reading.edges.values() for t in targets}
            roots = [k for k in by_key if k not in required]
        frontier = list(dict.fromkeys(roots))
        for key in frontier:
            depth[key] = 0
        while frontier:
            following: list[str] = []
            for key in frontier:
                for child in reading.edges.get(key, []):
                    if child in by_key:
                        parents[child].add(by_key[key].name)
                        if child not in depth:
                            depth[child] = depth[key] + 1
                            following.append(child)
            frontier = following
        attribution = f"the {reading.kind} SBOM {path} (written by {reading.tool})"
        out: list[Dependency] = []
        for component in reading.components:
            out.append(
                Dependency(
                    purl=component.purl or "",
                    ecosystem=component.ecosystem or "",
                    name=component.name,
                    version=component.version,
                    direct=depth.get(component.key, 1) == 0,
                    depth=depth.get(component.key, 1),
                    parents=tuple(sorted(parents[component.key])),
                    scope=component.scope,
                    integrity=component.integrity,
                    license=component.licence,
                    declared_in=path,
                    resolved_by=attribution,
                    resolution_note=None
                    if component.version
                    else f"listed without a version in {attribution}",
                )
            )
        return tuple(out)


__all__ = [
    "MAX_COMPONENTS",
    "ListedVulnerability",
    "PackageUrl",
    "SbomComponent",
    "SbomDocument",
    "SbomInventory",
    "SbomReading",
]
