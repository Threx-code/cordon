"""`cordon-scanner scan pkg:npm/name@version`: should I install this?

A package URL names a published artefact rather than a directory. It is resolved to the archive the
registry publishes, the bytes are checked against the digest the registry publishes for that
version, and the archive is scanned by the same archive reader `scan file.tgz` uses -- members are
read in memory, nothing is unpacked to disk, and nothing is installed or run.

Asking a registry is a network request, and the scanner is offline unless told otherwise (C2), so a
package URL needs `--online`. Without it the scan is refused rather than quietly scanning nothing.
The archive is written to a private temporary directory only so the archive reader can open it by
path, and that directory is removed when the scan ends, whatever the outcome.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from cordon_scanner.archive.safe import ArchiveReader
from cordon_scanner.core.trees import Trees


class PackageTargetError(ValueError):
    """A package URL that cannot be scanned, with the reason a user can act on."""


@dataclass(frozen=True, slots=True)
class PackageTarget:
    """One parsed package URL: the ecosystem it is asked of, the name, and the version (None = latest)."""

    ecosystem: str
    name: str
    version: str | None

    #: purl `type` to the scanner's ecosystem id, for the registries an archive can be fetched from.
    TYPES: ClassVar[dict[str, str]] = {
        "npm": "npm",
        "pypi": "pypi",
        "cargo": "cargo",
        "gem": "rubygems",
        "nuget": "nuget",
        "golang": "gomod",
        "hex": "hex",
        "pub": "pub",
        "maven": "maven",
        # A container image, pulled from its registry: `pkg:docker/nginx@1.27`,
        # `pkg:docker/ghcr.io/acme/app@sha256:...` (the registry host leads the name).
        "docker": "image",
        "oci": "image",
    }
    _NAME: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9@._~+-][A-Za-z0-9@._~+/-]{0,213}$")
    _VERSION: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._+~!-]{1,128}$")

    @staticmethod
    def is_package_url(target: str) -> bool:
        return target.startswith("pkg:")

    @classmethod
    def parse(cls, purl: str) -> PackageTarget:
        """`pkg:type/namespace/name@version`, per the purl spec, for the types `TYPES` names.

        Qualifiers and subpaths are refused rather than ignored: `?repository_url=` names another
        registry, and scanning the public one while the user meant theirs would answer a different
        question than the one asked.
        """
        if not cls.is_package_url(purl) or len(purl) > 512:
            raise PackageTargetError(f"not a package URL: {purl[:80]!r}")
        body = purl[len("pkg:") :].lstrip("/")
        if "?" in body or "#" in body:
            raise PackageTargetError(
                "package URL qualifiers and subpaths are not supported; name the package and version only"
            )
        kind, _, rest = body.partition("/")
        ecosystem = cls.TYPES.get(kind.lower())
        if ecosystem is None:
            raise PackageTargetError(
                f"cannot fetch {kind!r} packages; supported: {', '.join(sorted(cls.TYPES))}"
            )
        if ecosystem == "image":
            return cls._image(urllib.parse.unquote(rest))
        # The version follows the last `@` that does not begin a path segment: in
        # `pkg:npm/@scope/name@1.0.0` the first `@` is the scope and the second the version.
        split = rest.rfind("@")
        if split > 0 and rest[split - 1] != "/":
            path, version = rest[:split], urllib.parse.unquote(rest[split + 1 :]) or None
        else:
            path, version = rest, None
        name = urllib.parse.unquote(path).strip("/")
        if kind.lower() == "npm" and name.count("/") == 1 and not name.startswith("@"):
            # pkg:npm/%40scope/name decodes to @scope/name; pkg:npm/scope/name is the same package.
            name = f"@{name}"
        # A Go module path has as many segments as it has; a Maven purl's namespace is the group.
        segments = {"npm": 1, "maven": 1, "gomod": 16}.get(ecosystem, 0)
        if not name or not cls._NAME.match(name) or ".." in name or name.count("/") > segments:
            raise PackageTargetError(f"not a valid {ecosystem} package name: {name!r}")
        if ecosystem == "maven":
            if name.count("/") != 1:
                raise PackageTargetError(
                    f"a Maven package URL names group and artifact: pkg:maven/<group>/<artifact>@<version>, not {name!r}"
                )
            name = name.replace("/", ":")
        if version is not None and not cls._VERSION.match(version):
            raise PackageTargetError(f"not a valid version: {version!r}")
        return cls(ecosystem=ecosystem, name=name, version=version)

    @classmethod
    def _image(cls, rest: str) -> PackageTarget:
        """`name@tag` or `name@sha256:...`, the name led by its registry host where it is not
        Docker Hub's; validated as the Docker client validates a reference."""
        from cordon_scanner.ecosystems.image import ImageReference

        name, at, version = rest.rpartition("@")
        if not at:
            name, version = rest, ""
        written = (
            f"{name}@{version}"
            if version.startswith("sha256:")
            else f"{name}:{version or 'latest'}"
        )
        reference = ImageReference.parse(written)
        if reference is None:
            raise PackageTargetError(f"not a valid image reference: {rest[:120]!r}")
        full = (
            f"{reference.registry}/{reference.repository}"
            if reference.registry
            else reference.repository
        )
        return cls(
            ecosystem="image", name=full, version=reference.digest or reference.tag or "latest"
        )

    @property
    def label(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version or 'latest'}"

    @contextmanager
    def fetched(self) -> Iterator[Path]:
        """The verified archive on disk in a private directory for the length of the block."""
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        if self.ecosystem == "image":
            with self._pulled_image() as pulled:
                yield pulled
            return
        try:
            archive = RegistryClient.package_archive(self.ecosystem, self.name, self.version)
        except RegistryError as exc:
            raise PackageTargetError(f"could not fetch {self.label}: {exc}") from exc
        filename = PackageTarget.safe_filename(archive.filename, self.ecosystem)
        directory = Path(tempfile.mkdtemp(prefix="cordon-pkg-"))
        try:
            directory.chmod(stat.S_IRWXU)
            path = directory / filename
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(archive.data)
            yield path
        finally:
            Trees.remove(directory)

    @contextmanager
    def _pulled_image(self) -> Iterator[Path]:
        """The image as an OCI layout archive, every blob checked against its digest."""
        from cordon_scanner.ecosystems.image import ImageReference
        from cordon_scanner.intel.registry_image import RegistryImage, RegistryImageError

        reference = ImageReference.parse(self.name)
        if reference is None:
            raise PackageTargetError(f"not a valid image reference: {self.name!r}")
        try:
            data, _pull = RegistryImage(reference.registry, reference.repository).pull(
                self.version or "latest"
            )
        except RegistryImageError as exc:
            raise PackageTargetError(f"could not pull {self.label}: {exc}") from exc
        directory = Path(tempfile.mkdtemp(prefix="cordon-image-"))
        try:
            directory.chmod(stat.S_IRWXU)
            path = directory / "image.tar"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
            yield path
        finally:
            Trees.remove(directory)

    #: The archive suffix each ecosystem's artefact is read under, when the registry's own filename
    #: does not end in one the archive reader opens.
    _SUFFIX: ClassVar[dict[str, str]] = {
        "npm": ".tgz",
        "pypi": ".tar.gz",
        "cargo": ".crate",
        "rubygems": ".gem",
        "nuget": ".nupkg",
        "gomod": ".zip",
        "hex": ".tar",
        "pub": ".tar.gz",
        "maven": ".jar",
    }

    @classmethod
    def safe_filename(cls, filename: str, ecosystem: str) -> str:
        """The registry's filename reduced to one plain path component the archive reader opens.

        The registry chose it, so it is untrusted: separators, traversal and anything outside a
        conservative alphabet are dropped, and a name that does not end in a readable archive
        suffix is given the ecosystem's own.
        """
        base = re.sub(r"[^A-Za-z0-9._+-]", "_", filename.replace("\\", "/").rsplit("/", 1)[-1])[
            :200
        ]
        base = base.lstrip(".") or "package"
        if not ArchiveReader.is_archive(base):
            base = f"{base}{cls._SUFFIX.get(ecosystem, '.tar.gz')}"
        return base
