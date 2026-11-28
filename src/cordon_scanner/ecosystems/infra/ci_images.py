"""The images a CI pipeline file runs its jobs in, and the Kubernetes manifests kept under chart folders.

```
  GitLab CI           top-level, `default:` and per-job `image:` and `services:` (a name, or a mapping with `name:`)
  Jenkinsfile         `docker { image '...' }`, `agent { docker '...' }`, `docker.image('...')`, and the
                      `image:` of a pod template written inline
  Azure Pipelines     `container:` (not a name declared under `resources.containers`), each of those
                      resources' `image:`, and a job's `services:`
  CircleCI            `docker:` executors' `image:` of every job and executor
  Bitbucket Pipelines the default and every step's `image:` (a name or a mapping with `name:`), and the
                      `definitions.services` images
  Buildkite           the Docker plugin's `image:` (`docker#v5.0.0:`), in every step and group
  Cloud Build         each step's `name:`, which is the builder image
  Drone, Woodpecker   every step's, service's and clone's `image:` (Drone files hold several documents)
  Kubernetes          `helm/`, `charts/`, `base/` YAML and `*.k8s.yaml`, read as the adapter reads any manifest
```

One table, `CiFiles.KINDS`, says which file is read by which reader; the adapter's globs come from it. A reference
written with a variable (`$CI_REGISTRY_IMAGE/app:$TAG`, `${{ matrix.image }}`) is not one the registry can be asked
about and is left out; a digest pins an image and a tag names one the registry can re-point, as everywhere else.
A pipeline's image is the environment its commands run in: its scope is the build's.
"""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple

from cordon_scanner.ecosystems.base import DeclaredDependency, Manifest
from cordon_scanner.ecosystems.infra.ci_yaml import CiYaml
from cordon_scanner.ecosystems.infra.references import ImageReference
from cordon_scanner.foundation.formats.datayaml import DataYaml, DataYamlError
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.content import FileContent


class CiKind(NamedTuple):
    """A kind of file: its base names, the folder it lives in (if any), and the reader that takes it."""

    reader: str
    names: tuple[str, ...]
    folder: str | None = None
    deep: bool = False
    """Anywhere below the folder, not only directly in it."""

    @property
    def globs(self) -> tuple[str, ...]:
        if self.folder is None:
            return tuple(f"**/{name}" for name in self.names)
        middle = "**/" if self.deep else ""
        return tuple(f"**/{self.folder}/{middle}{name}" for name in self.names)

    def holds(self, path: str) -> bool:
        parts = path.split("/")
        if not any(fnmatch.fnmatchcase(parts[-1], name) for name in self.names):
            return False
        if self.folder is None:
            return True
        return self.folder in parts[:-1] if self.deep else parts[-2:-1] == [self.folder]


class CiFiles:
    """Which file kind is read by which reader (`CiImages.<reader>`), `kubernetes` by the adapter."""

    KINDS: ClassVar[tuple[CiKind, ...]] = (
        CiKind("gitlab", (".gitlab-ci.yml", ".gitlab-ci.yaml")),
        CiKind("jenkins", ("Jenkinsfile", "Jenkinsfile.*")),
        CiKind("azure", ("azure-pipelines.yml", "azure-pipelines.yaml")),
        CiKind("azure", ("*.yml",), ".azure-pipelines"),
        CiKind("circleci", ("config.yml", "config.yaml"), ".circleci"),
        CiKind("bitbucket", ("bitbucket-pipelines.yml",)),
        CiKind("buildkite", ("*.yml", "*.yaml"), ".buildkite"),
        CiKind("cloudbuild", ("cloudbuild.yaml", "cloudbuild.yml")),
        CiKind("drone", (".drone.yml", ".woodpecker.yml")),
        CiKind("kubernetes", ("*.k8s.yaml",)),
        *(
            CiKind("kubernetes", ("*.yaml",), folder, deep=True)
            for folder in ("helm", "charts", "base")
        ),
    )

    @staticmethod
    def globs() -> tuple[str, ...]:
        return tuple(glob for kind in CiFiles.KINDS for glob in kind.globs)

    @staticmethod
    def reader(path: str) -> str | None:
        for kind in CiFiles.KINDS:
            if kind.holds(path):
                return kind.reader
        return None


class CiImages:
    """Each reader gives `(where, image)` for the references one kind of file writes."""

    MAX_DEPTH: ClassVar[int] = 24
    DOCUMENT_BREAK: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*(?:#[^\r\n]*)?\r?$")
    MAX_DOCUMENTS: ClassVar[int] = 200
    GROOVY: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = (
        ("docker image", re.compile(r"""\bimage[ \t]+(["'])([^"'\r\n]{1,300})\1""")),
        ("docker agent", re.compile(r"""\bdocker[ \t]+(["'])([^"'\r\n]{1,300})\1""")),
        ("docker.image", re.compile(r"""\bdocker\.image\([ \t]*(["'])([^"'\r\n]{1,300})\1""")),
        ("pod template", re.compile(r"""\bimage:[ \t]*(["']?)([^\s"'\r\n]{1,300})\1""")),
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str, reader: str) -> Manifest:
        dependencies: list[DeclaredDependency] = []
        for field_name, image in getattr(CiImages, reader)(content.text):
            declared = ImageReference.declare(
                image.strip(), scope=Scope.BUILD, field_name=f"{reader} {field_name}"
            )
            if declared is not None:
                dependencies.append(declared)
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=tuple(dependencies))

    @staticmethod
    def documents(text: str) -> Iterator[Any]:
        for chunk in CiImages.DOCUMENT_BREAK.split(text)[: CiImages.MAX_DOCUMENTS]:
            try:
                document = DataYaml.load(CiYaml.plain(chunk))
            except (DataYamlError, ValueError, RecursionError):
                continue
            if isinstance(document, dict):
                yield document

    @staticmethod
    def named(value: Any, *keys: str) -> str | None:
        """An image written as a string, or as a mapping that carries it under one of `keys`."""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in keys:
                if isinstance(value.get(key), str):
                    return str(value[key])
        return None

    @staticmethod
    def _each(value: Any, where: str, *keys: str) -> Iterator[tuple[str, str]]:
        """One image, or a list of them (a `services:` list)."""
        for index, item in enumerate(value if isinstance(value, list) else [value]):
            image = CiImages.named(item, *keys)
            if image is not None:
                yield (f"{where}[{index}]" if isinstance(value, list) else where), image

    @staticmethod
    def _images_key(node: Any, where: str, depth: int = 0) -> Iterator[tuple[str, str]]:
        """Every `image:` under a node, however deep the pipeline nests its steps."""
        if depth > CiImages.MAX_DEPTH:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("settings", "environment", "variables", "secrets"):
                    continue
                if key == "image":
                    yield from CiImages._each(value, f"{where} image", "name", "image")
                else:
                    yield from CiImages._images_key(value, f"{where} {key}", depth + 1)
        elif isinstance(node, list):
            for item in node:
                yield from CiImages._images_key(item, where, depth + 1)

    @staticmethod
    def gitlab(text: str) -> Iterator[tuple[str, str]]:
        """The top level and `default:` are scopes of their own; every other mapping with an `image` or
        `services` is a job."""
        for document in CiImages.documents(text):
            scopes = {"top": document}
            for key, value in document.items():
                if isinstance(value, dict) and key not in ("variables", "workflow"):
                    scopes[str(key)] = value
            for name, scope in scopes.items():
                for field in ("image", "services"):
                    yield from CiImages._each(scope.get(field), f"{name} {field}", "name", "image")

    @staticmethod
    def jenkins(text: str) -> Iterator[tuple[str, str]]:
        lines = (
            line for line in text.splitlines() if not line.lstrip().startswith(("//", "*", "/*"))
        )
        for number, line in enumerate(lines, 1):
            for where, pattern in CiImages.GROOVY:
                for match in pattern.finditer(line):
                    yield f"{where} (line {number})", match.group(2)

    @staticmethod
    def azure(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            declared: set[str] = set()
            resources = document.get("resources")
            containers = resources.get("containers") if isinstance(resources, dict) else None
            for container in containers if isinstance(containers, list) else []:
                if isinstance(container, dict):
                    if isinstance(container.get("container"), str):
                        declared.add(container["container"])
                    if isinstance(container.get("image"), str):
                        yield (
                            f"resources container {container.get('container', '')}",
                            container["image"],
                        )
            yield from CiImages._azure_uses(document, declared, 0)

    @staticmethod
    def _azure_uses(node: Any, declared: set[str], depth: int) -> Iterator[tuple[str, str]]:
        if depth > CiImages.MAX_DEPTH:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "container":
                    image = CiImages.named(value, "image")
                    if image is not None and image not in declared:
                        yield "container", image
                elif key == "services" and isinstance(value, dict):
                    for name, image in value.items():
                        if isinstance(image, str) and image not in declared:
                            yield f"services {name}", image
                elif key != "resources":
                    yield from CiImages._azure_uses(value, declared, depth + 1)
        elif isinstance(node, list):
            for item in node:
                yield from CiImages._azure_uses(item, declared, depth + 1)

    @staticmethod
    def circleci(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            for section in ("jobs", "executors"):
                entries = document.get(section)
                for name, entry in entries.items() if isinstance(entries, dict) else []:
                    if isinstance(entry, dict):
                        yield from CiImages._each(
                            entry.get("docker"), f"{section} {name} docker", "image"
                        )

    @staticmethod
    def bitbucket(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            yield from CiImages._images_key(document, "bitbucket")

    @staticmethod
    def buildkite(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            yield from CiImages._plugin_images(document, 0)

    @staticmethod
    def _plugin_images(node: Any, depth: int) -> Iterator[tuple[str, str]]:
        if depth > CiImages.MAX_DEPTH:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.startswith("docker#") and isinstance(value, dict):
                    image = CiImages.named(value.get("image"))
                    if image is not None:
                        yield f"plugin {key}", image
                else:
                    yield from CiImages._plugin_images(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                yield from CiImages._plugin_images(item, depth + 1)

    @staticmethod
    def cloudbuild(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            steps = document.get("steps")
            for index, step in enumerate(steps if isinstance(steps, list) else []):
                if isinstance(step, dict) and isinstance(step.get("name"), str):
                    yield f"steps[{step.get('id', index)}] name", step["name"]

    @staticmethod
    def drone(text: str) -> Iterator[tuple[str, str]]:
        for document in CiImages.documents(text):
            yield from CiImages._images_key(document, "pipeline")


__all__ = ["CiFiles", "CiImages", "CiKind"]
