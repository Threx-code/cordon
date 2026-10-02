"""Image tarballs (`docker save` and OCI layout), squashed the way a container runtime would.

Each layer is applied over the last: a file replaces the earlier one, `.wh.<name>` deletes one, and
`.wh..wh..opq` empties a directory. Layers are streamed, never extracted to disk, and every size
and count is bounded. Two passes, both through `_squash`:

1. the package databases, their file lists and `os-release` -- the operating-system inventory, and
   which files the distribution's own packages account for;
2. the files the image ADDS beyond those packages -- what the image's author put there -- for the
   same detectors a repository gets, plus the metadata of the language packages it installed.

Language runtimes built into an image from source (CPython under `/usr/local/lib/python3.*`, Node,
Go, a JDK) and installed-library trees (`site-packages`, `node_modules`) are not content-scanned,
for the reason a repository's `node_modules` is not: their packages are judged by name and version
against advisories, and their code is not the image author's. What was skipped, and why, is counted.
"""

from __future__ import annotations

import gzip
import io
import json
import posixpath
import re
import struct
import tarfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import IO, Any, Final

from cordon_scanner.images import langpkgs
from cordon_scanner.images import packages as pkgdb

MAX_LAYERS: Final = 256
MAX_WANTED_BYTES: Final = 256 << 20
MAX_MEMBERS_PER_LAYER: Final = 2_000_000

DPKG_STATUS: Final = "var/lib/dpkg/status"
DPKG_STATUS_D: Final = "var/lib/dpkg/status.d/"
DPKG_INFO: Final = "var/lib/dpkg/info/"
APK_INSTALLED: Final = "lib/apk/db/installed"
RPM_SQLITE: Final = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
RPM_LEGACY: Final = (
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/Packages",
    "var/lib/rpm/Packages.db",
    "usr/lib/sysimage/rpm/Packages.db",
)
OS_RELEASE: Final = ("etc/os-release", "usr/lib/os-release")

_WANTED_EXACT: Final = frozenset(
    {
        DPKG_STATUS,
        APK_INSTALLED,
        *RPM_SQLITE,
        *(p + "-wal" for p in RPM_SQLITE),
        *RPM_LEGACY,
        *OS_RELEASE,
    }
)

#: Paths not content-scanned, and the reason a report gives for each.
RUNTIME_TREES: Final = (
    (re.compile(r"^usr/local/lib/python\d[\d.]*/"), "a Python runtime built into the image"),
    (re.compile(r"^usr/local/lib/libpython"), "a Python runtime built into the image"),
    (
        re.compile(r"^usr/local/bin/(?:python|pip|idle|pydoc)[\d.]*(?:-config)?$"),
        "a Python runtime built into the image",
    ),
    (re.compile(r"^usr/local/include/"), "language runtime headers"),
    (
        re.compile(r"^usr/local/(?:bin/(?:node|npm|npx|corepack|yarn|yarnpkg)|share/doc/node)"),
        "a Node.js runtime built into the image",
    ),
    (re.compile(r"^opt/yarn-[^/]+/"), "a Node.js runtime built into the image"),
    (re.compile(r"^usr/local/go/"), "a Go toolchain built into the image"),
    (
        re.compile(r"^(?:opt/java|usr/lib/jvm|usr/local/openjdk[^/]*|opt/openjdk[^/]*)/"),
        "a Java runtime built into the image",
    ),
    (re.compile(r"^usr/local/lib/ruby/"), "a Ruby runtime built into the image"),
    (
        re.compile(r"(?:^|/)(?:site-packages|dist-packages|node_modules|gems|bundle)/"),
        "installed language packages, matched by version instead",
    ),
    (re.compile(r"^(?:proc|sys|dev)/"), "a pseudo-filesystem"),
    (
        re.compile(
            r"^var/(?:cache|log)/|^var/lib/(?:apt/lists|dpkg|rpm|apk|yum|dnf|zypp|alternatives)/|^etc/alternatives/|^lib/apk/db/|^usr/lib/sysimage/rpm/"
        ),
        "package-manager state and caches",
    ),
    (re.compile(r"(?:^|/)__pycache__/|\.pyc$"), "compiled bytecode"),
    (
        re.compile(
            r"^usr/share/mime/|^usr/lib/locale/locale-archive$|^etc/ld\.so\.cache$|/gconv-modules\.cache$"
            r"|/fonts\.cache-\d+$|/icon-theme\.cache$|^usr/lib64/gio/modules/giomodule\.cache$"
            r"|^usr/share/glib-2\.0/schemas/gschemas\.compiled$|^etc/pki/ca-trust/extracted/|^var/lib/ca-certificates/"
            r"|^etc/ssl/certs/(?:ca-certificates\.crt|java/cacerts)$|^var/lib/systemd/catalog/database$"
        ),
        "caches the distribution's own install scripts generate",
    ),
)


OVERSIZE: Final = "larger than the per-file limit, so not examined"


@dataclass
class ImageInventory:
    release: pkgdb.OsRelease | None = None
    packages: list[pkgdb.OsPackage] = field(default_factory=list)
    language_packages: list[langpkgs.LanguagePackage] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    """Anything that stopped part of the image being read. Each makes the scan incomplete."""
    layers: int = 0
    owned: frozenset[str] = frozenset()
    """Paths the distribution's packages install; their content is the distribution's."""
    added_files: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    """Reason -> files not content-scanned for it."""


class ImageLayers:
    """An OCI or Docker image tarball, squashed to the files that matter."""

    @staticmethod
    def _normalise(name: str) -> str:
        return posixpath.normpath("/" + name).lstrip("/")

    @staticmethod
    def _wanted(path: str) -> bool:
        if path in _WANTED_EXACT:
            return True
        if path.startswith(DPKG_STATUS_D) and "/" not in path[len(DPKG_STATUS_D) :]:
            return True
        return path.startswith(DPKG_INFO) and path.endswith(".list")

    @staticmethod
    def is_image(archive: tarfile.TarFile) -> bool:
        names = {ImageLayers._normalise(m.name) for m in archive.getmembers()[:4096]}
        return "manifest.json" in names or ("oci-layout" in names and "index.json" in names)

    @staticmethod
    def _read_member(archive: tarfile.TarFile, name: str, limit: int = 16 << 20) -> bytes:
        member = archive.getmember(name)
        if not member.isfile() or member.size > limit:
            raise ValueError(f"{name} is not a readable file within limits")
        handle = archive.extractfile(member)
        if handle is None:
            raise ValueError(f"{name} could not be opened")
        return handle.read()

    @staticmethod
    def _members_by_path(archive: tarfile.TarFile) -> dict[str, str]:
        return {ImageLayers._normalise(m.name): m.name for m in archive.getmembers()}

    @staticmethod
    def _layer_paths(archive: tarfile.TarFile, problems: list[str]) -> list[str]:
        """The image's layer members, bottom first. The first image when a tarball holds several."""
        by_path = ImageLayers._members_by_path(archive)
        if "manifest.json" in by_path:
            manifest = json.loads(ImageLayers._read_member(archive, by_path["manifest.json"]))
            if isinstance(manifest, list) and manifest:
                if len(manifest) > 1:
                    problems.append(
                        f"the tarball holds {len(manifest)} images; only the first was inventoried"
                    )
                layers = manifest[0].get("Layers") or []
                return [
                    by_path.get(ImageLayers._normalise(str(layer)), str(layer)) for layer in layers
                ]
        index = json.loads(ImageLayers._read_member(archive, by_path["index.json"]))
        descriptor: Any = (index.get("manifests") or [{}])[0]
        for _ in range(4):  # an index may point at another index (a multi-platform image)
            digest = str(descriptor.get("digest", ""))
            algorithm, _, hexdigest = digest.partition(":")
            document = json.loads(
                ImageLayers._read_member(archive, by_path[f"blobs/{algorithm}/{hexdigest}"])
            )
            if "layers" in document:
                return [
                    by_path[
                        f"blobs/{d['digest'].partition(':')[0]}/{d['digest'].partition(':')[2]}"
                    ]
                    for d in document["layers"]
                ]
            manifests = document.get("manifests") or []
            if not manifests:
                break
            if len(manifests) > 1:
                problems.append(
                    f"the image index lists {len(manifests)} platforms; only the first was inventoried"
                )
            descriptor = manifests[0]
        raise ValueError("the OCI layout names no image manifest")

    @staticmethod
    def _open_layer(raw: IO[bytes]) -> tarfile.TarFile:
        head = raw.read(4)
        raw.seek(0)
        if head[:2] == b"\x1f\x8b":
            return tarfile.open(fileobj=gzip.GzipFile(fileobj=raw), mode="r|")
        if head == b"\x28\xb5\x2f\xfd":
            return tarfile.open(fileobj=ImageLayers._zstd_reader(raw), mode="r|")
        return tarfile.open(fileobj=raw, mode="r|")

    @staticmethod
    def _zstd_reader(raw: IO[bytes]) -> IO[bytes]:
        """A zstd decompressor from the standard library, which has one from Python 3.14."""
        try:
            import importlib

            zstd = importlib.import_module("compression.zstd")
        except ImportError as exc:
            raise ValueError(
                "zstd-compressed layer; reading one needs Python 3.14 or later"
            ) from exc
        reader: IO[bytes] = zstd.ZstdFile(raw)
        return reader

    @staticmethod
    def _apply_layer(
        layer: tarfile.TarFile, files: dict[str, bytes], keep: Keep, budget: list[int]
    ) -> None:
        for count, member in enumerate(layer):
            if count >= MAX_MEMBERS_PER_LAYER:
                raise ValueError("a layer has more members than the reader walks")
            path = ImageLayers._normalise(member.name)
            directory, base = posixpath.split(path)
            if base == ".wh..wh..opq":
                prefix = directory + "/" if directory else ""
                for known in [k for k in files if k.startswith(prefix)]:
                    del files[known]
                continue
            if base.startswith(".wh."):
                removed = posixpath.join(directory, base[len(".wh.") :])
                for known in [k for k in files if k == removed or k.startswith(removed + "/")]:
                    del files[known]
                continue
            if not member.isfile():
                files.pop(path, None)
                continue
            if not keep(path, member.size):
                files.pop(
                    path, None
                )  # replaced by something not kept: the earlier copy is gone too
                continue
            handle = layer.extractfile(member)
            if handle is None:
                continue
            previous = len(files.get(path, b""))
            budget[0] -= member.size - previous
            if budget[0] < 0:
                raise MemoryError("the image's files are larger than the reader keeps")
            files[path] = handle.read()

    @staticmethod
    def _squash(
        data: bytes, keep: Keep, budget: int, inventory: ImageInventory, *, count_layers: bool
    ) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        remaining = [budget]
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            paths = ImageLayers._layer_paths(archive, inventory.problems if count_layers else [])
            if len(paths) > MAX_LAYERS:
                raise ValueError(f"the image has more than {MAX_LAYERS} layers")
            for name in paths:
                if count_layers:
                    inventory.layers += 1
                member = archive.getmember(name)
                handle = archive.extractfile(member)
                if handle is None:
                    if count_layers:
                        inventory.problems.append(
                            f"layer {posixpath.basename(name)} could not be opened"
                        )
                    continue
                try:
                    with ImageLayers._open_layer(handle) as layer:
                        ImageLayers._apply_layer(layer, files, keep, remaining)
                except MemoryError as exc:
                    inventory.problems.append(
                        f"{exc}; the files after that point were not examined"
                    )
                    break
                except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
                    if count_layers:
                        inventory.problems.append(
                            f"layer {posixpath.basename(name)[:24]} was not read ({exc})"
                        )
        return files

    @staticmethod
    def squash(data: bytes) -> tuple[dict[str, bytes], ImageInventory]:
        """The package databases, their file lists and `os-release`, as the top layer leaves them."""
        inventory = ImageInventory()
        files = ImageLayers._squash(
            data,
            lambda path, _size: ImageLayers._wanted(path),
            MAX_WANTED_BYTES,
            inventory,
            count_layers=True,
        )
        return files, inventory

    @staticmethod
    def read_image(data: bytes) -> ImageInventory:
        """The operating-system inventory of an image tarball, and what its packages own."""
        files, inventory = ImageLayers.squash(data)
        for path in OS_RELEASE:
            if path in files:
                inventory.release = pkgdb.PackageDatabases.os_release(files[path])
                break
        owned: set[str] = set()
        if DPKG_STATUS in files:
            inventory.packages.extend(pkgdb.PackageDatabases.dpkg(files[DPKG_STATUS]))
        for path in sorted(p for p in files if p.startswith(DPKG_STATUS_D)):
            inventory.packages.extend(pkgdb.PackageDatabases.dpkg(files[path]))
        owned |= pkgdb.PackageDatabases.dpkg_owned(
            [files[p] for p in files if p.startswith(DPKG_INFO)]
        )
        if APK_INSTALLED in files:
            inventory.packages.extend(pkgdb.PackageDatabases.apk(files[APK_INSTALLED]))
            owned |= pkgdb.PackageDatabases.apk_owned(files[APK_INSTALLED])
        blobs: list[bytes] = []
        for path in RPM_SQLITE:
            if path in files:
                try:
                    blobs = pkgdb.PackageDatabases.rpm_sqlite_blobs(
                        files[path], files.get(path + "-wal")
                    )
                except Exception as exc:
                    inventory.problems.append(
                        f"the RPM database at {path} was not read ({type(exc).__name__})"
                    )
                break
        else:
            for path in RPM_LEGACY:
                if path not in files:
                    continue
                reader = (
                    pkgdb.PackageDatabases.rpm_ndb_blobs
                    if path.endswith(".db")
                    else pkgdb.PackageDatabases.rpm_bdb_blobs
                )
                try:
                    blobs = reader(files[path])
                except (ValueError, struct.error) as exc:
                    inventory.problems.append(f"the RPM database at {path} was not read ({exc})")
                break
        if blobs:
            inventory.packages.extend(pkgdb.PackageDatabases.rpm_blobs(blobs))
            owned |= pkgdb.PackageDatabases.rpm_owned(blobs)
        inventory.owned = frozenset(ImageLayers._with_merged_usr(owned))
        # distroless ships a package in both `status` and `status.d`; one entry each.
        seen: set[tuple[str, str, str]] = set()
        unique = []
        for package in inventory.packages:
            key = (package.manager, package.name, package.version)
            if key not in seen:
                seen.add(key)
                unique.append(package)
        inventory.packages = unique
        return inventory

    @staticmethod
    def _with_merged_usr(owned: set[str]) -> set[str]:
        """Both spellings of every path. With /usr merged, as on Debian 12 and RHEL 8 onward, `/lib64`
        is a link to `usr/lib64`: package file lists name one and the layer stores the other."""
        aliased = set(owned)
        for path in owned:
            if path.startswith(_MERGED):
                aliased.add("usr/" + path)
            elif path.startswith("usr/") and path[4:].startswith(_MERGED):
                aliased.add(path[4:])
        return aliased

    @staticmethod
    def skip_reason(path: str) -> str | None:
        for pattern, reason in RUNTIME_TREES:
            if pattern.search(path):
                return reason
        return None

    @staticmethod
    def added_files(
        data: bytes, inventory: ImageInventory, *, max_file_bytes: int, max_total_bytes: int
    ) -> Iterator[tuple[str, bytes]]:
        """The files the image adds beyond its distribution's packages, as the top layer leaves them.

        Language-package metadata is read from the trees that are not content-scanned, and recorded on
        the inventory rather than yielded.
        """
        skipped: dict[str, int] = {}
        metadata: dict[str, bytes] = {}

        def keep(path: str, size: int) -> bool:
            if path in inventory.owned:
                return False
            reason = ImageLayers.skip_reason(path)
            if reason is not None:
                if langpkgs.LanguagePackages.is_metadata(path) and size <= 1 << 20:
                    return True
                skipped[reason] = skipped.get(reason, 0) + 1
                return False
            if size > max_file_bytes:
                skipped[OVERSIZE] = skipped.get(OVERSIZE, 0) + 1
                return False
            return True

        files = ImageLayers._squash(data, keep, max_total_bytes, inventory, count_layers=False)
        for path in sorted(files):
            if ImageLayers.skip_reason(path) is not None:
                metadata[path] = files.pop(path)
        for path, payload in sorted(metadata.items()):
            package = langpkgs.LanguagePackages.parse(path, payload)
            if package is not None:
                inventory.language_packages.append(package)
        inventory.skipped = skipped
        inventory.added_files = len(files)
        for path in sorted(files):
            yield path, files[path]


Keep = Callable[[str, int], bool]


_MERGED: Final = ("bin/", "sbin/", "lib/", "lib32/", "lib64/", "libx32/")


__all__ = ["OVERSIZE", "ImageInventory", "ImageLayers"]
