"""The upstream of a Helm chart and of a container image: what each says it was built from.

* A chart states its application's version (`appVersion`) and where its source is (`sources`, `home`) in its own
  metadata: the repository's `index.yaml` entry for that chart version, or, for a chart served from an OCI registry
  (`oci://`), the chart's configuration blob, which is its Chart.yaml as JSON.
* An image states its source in its configuration's OCI labels: `org.opencontainers.image.source`, with
  `org.opencontainers.image.revision` (the commit it was built from) or `org.opencontainers.image.version`.

A commit is asked of OSV as it is; a version is looked up as a tag in the repository named (`Inference`). A chart or an
image that names no source is left unchecked, and says so. Read over HTTPS with the scan's `--online` only; an image's
manifest and configuration are fetched by digest and checked against it (`RegistryImage`).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.advisories.upstream.base import RepositoryArchive, Unnamed, Upstream
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import Inference

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import Dependency


class ImageName:
    """`registry` and `repository` of an image reference, as the image adapter splits them (`ImageReference`): a first
    part with a dot, a port or `localhost` is a registry; otherwise Docker Hub, `library/` for an official image."""

    HUB: ClassVar[str] = "registry-1.docker.io"
    HUB_NAMES: ClassVar[frozenset[str]] = frozenset(
        {"docker.io", "index.docker.io", "registry-1.docker.io"}
    )

    @classmethod
    def split(cls, name: str) -> tuple[str, str] | None:
        name = name.strip().lower()
        if (
            not name
            or len(name) > 255
            or not re.fullmatch(r"[a-z0-9._/:\-\[\]]+", name)
            or ".." in name
        ):
            return None
        first, slash, rest = name.partition("/")
        if slash and ("." in first or ":" in first or first == "localhost"):
            registry, repository = first, rest
        else:
            registry, repository = cls.HUB, name
        if registry in cls.HUB_NAMES:
            registry = cls.HUB
            if "/" not in repository:
                repository = f"library/{repository}"
        if not repository or any(p in ("", ".") for p in repository.split("/")):
            return None
        return registry, repository


class OciConfig:
    """An image's or an OCI chart's configuration blob, through its manifest (one platform of an index)."""

    MAX: ClassVar[int] = 4 << 20

    @classmethod
    def of(cls, registry: str, repository: str, reference: str) -> dict[str, Any]:
        from cordon_scanner.intel.registries.registry_image import Pull, RegistryImage

        image = RegistryImage(registry, repository)
        body, _media = image.manifest(reference)
        document = json.loads(body)
        if isinstance(document.get("manifests"), list):
            chosen = cls.platform(document["manifests"])
            if chosen is None:
                raise ValueError("the index lists no platform")
            document = json.loads(image.manifest(chosen)[0])
        digest = str((document.get("config") or {}).get("digest") or "")
        size = (document.get("config") or {}).get("size")
        if not digest or (isinstance(size, int) and size > cls.MAX):
            raise ValueError("the manifest names no readable configuration")
        config = json.loads(image.blob(digest, Pull()))
        if not isinstance(config, dict):
            raise ValueError("the configuration is not an object")
        return config

    @staticmethod
    def platform(manifests: list[Any]) -> str | None:
        """linux/amd64 when listed, else the first platform that is not an attestation."""
        listed = [m for m in manifests if isinstance(m, dict) and isinstance(m.get("digest"), str)]
        real = [m for m in listed if (m.get("platform") or {}).get("os") not in (None, "unknown")]
        for m in real:
            platform = m.get("platform") or {}
            if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                return str(m["digest"])
        return str((real or listed)[0]["digest"]) if (real or listed) else None


class ChartIndex:
    """One chart version's entry in a repository's `index.yaml`, read by its layout (no YAML library): under
    `entries:`, the chart's name, then a list of versions, each item a mapping whose keys sit two spaces inside its
    `- `. Only the item's own scalar keys and its `sources` list are read; nested mappings are passed over."""

    KEY: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z][\w-]*):(?:[ \t](.*))?$")

    @staticmethod
    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    @classmethod
    def entry(cls, text: str, name: str, version: str) -> dict[str, Any] | None:
        lines = text.splitlines()
        header = re.compile(rf"^(\s+){re.escape(name)}:\s*$")
        for start, line in enumerate(lines):
            found = header.match(line)
            if found is None:
                continue
            for item in cls.items(lines[start + 1 :], len(found.group(1))):
                fields = cls.fields(item)
                if str(fields.get("version", "")) == version:
                    return fields
        return None

    @classmethod
    def items(cls, lines: list[str], name_indent: int) -> list[list[str]]:
        """The chart's version items: each starts at a `- ` at the list's indent, and the list ends at a line no deeper
        than the chart's name."""
        items: list[list[str]] = []
        dash: int | None = None
        for line in lines:
            if not line.strip():
                continue
            depth = cls.indent(line)
            is_dash = line.lstrip(" ").startswith("- ")
            if dash is None:
                if not is_dash:
                    return []
                dash = depth
            if (
                depth < dash
                or (depth == dash and not is_dash)
                or (depth <= name_indent and not is_dash)
            ):
                break
            if depth == dash and is_dash:
                items.append([" " * (dash + 2) + line.lstrip(" ")[2:]])
            else:
                items[-1].append(line)
        return items

    @classmethod
    def fields(cls, item: list[str]) -> dict[str, Any]:
        """The item's own scalar keys (at its key indent), and its `sources` list."""
        fields: dict[str, Any] = {}
        key_indent = cls.indent(item[0])
        listing = False
        for line in item:
            depth, stripped = cls.indent(line), line.strip()
            if depth == key_indent and not stripped.startswith("- "):
                found = cls.KEY.match(stripped)
                value = (found.group(2) or "").strip() if found else ""
                listing = bool(found and found.group(1) == "sources" and not value)
                if found and value:
                    fields.setdefault(found.group(1), value.strip("'\""))
                if listing:
                    fields["sources"] = []
            elif listing and stripped.startswith("- ") and depth >= key_indent:
                fields["sources"].append(stripped[2:].strip().strip("'\""))
            elif depth <= key_indent:
                listing = False
        return fields


class ChartsImages:
    """What a chart and an image say they were built from."""

    #: The index a chart repository serves is one document for all its charts: tens of megabytes for a large one.
    MAX_INDEX: ClassVar[int] = 48 << 20

    @staticmethod
    def helm(dependency: Dependency) -> Upstream | Unnamed:
        repository = (dependency.resolved_from or "").strip()
        name, version = dependency.name, dependency.version or ""
        if repository.startswith("oci://"):
            host, _, path = repository.removeprefix("oci://").partition("/")
            config = OciConfig.of(host, f"{path.strip('/')}/{name}".strip("/"), version)
            fields: dict[str, Any] | None = config
        elif repository.startswith("https://"):
            text = Fetch.get(repository.rstrip("/") + "/index.yaml", ChartsImages.MAX_INDEX)
            fields = ChartIndex.entry(text.decode("utf-8", "replace"), name, version)
        else:
            return Unnamed("its chart repository is not named by an https or oci address")
        if not fields:
            return Unnamed(f"the repository does not list {name} {version}")
        listed = fields.get("sources")
        sources: list[Any] = listed if isinstance(listed, list) else []
        homes = [*sources, fields.get("home")]
        application = str(fields.get("appVersion") or "").strip()
        if not application:
            return Unnamed(
                "the chart names no application version", homes=tuple(str(h) for h in homes if h)
            )
        return Inference.inferred(
            Unnamed("the chart names its application's source, not a tag in it"),
            homes,
            application,
            (name,),
            f"the chart's record of {name} {version} (application {application})",
        )

    @staticmethod
    def image(dependency: Dependency) -> Upstream | Unnamed:
        split = ImageName.split(dependency.name)
        tag = dependency.version or ""
        if split is None or not tag:
            return Unnamed("it is not an image reference with a tag or digest")
        config = OciConfig.of(split[0], split[1], tag)
        labels = (config.get("config") or {}).get("Labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        source = str(labels.get("org.opencontainers.image.source") or "")
        revision = str(labels.get("org.opencontainers.image.revision") or "")
        release = str(labels.get("org.opencontainers.image.version") or "")
        how = f"the image's labels ({split[1]}:{tag})"
        repository = RepositoryArchive.repository(source) if source else None
        if repository and re.fullmatch(r"[0-9a-f]{40}", revision):
            return RepositoryArchive.upstream(repository, revision, how)
        if not source:
            return Unnamed("the image's configuration names no source")
        return Inference.inferred(
            Unnamed("the image names its source, not a commit"),
            [source],
            release or re.split(r"[-_]", tag, maxsplit=1)[0],
            (split[1].rsplit("/", 1)[-1],),
            how,
        )


__all__ = ["ChartIndex", "ChartsImages", "ImageName", "OciConfig"]
