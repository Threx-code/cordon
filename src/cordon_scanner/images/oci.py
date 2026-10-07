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
from dataclasses import dataclass, field, replace
from typing import IO, Any, ClassVar, Final

from cordon_scanner.images import langpkgs
from cordon_scanner.images import packages as pkgdb

MAX_LAYERS: Final = 256
MAX_WANTED_BYTES: Final = 256 << 20
MAX_MEMBERS_PER_LAYER: Final = 2_000_000

DPKG_STATUS: Final = "var/lib/dpkg/status"
DPKG_STATUS_D: Final = "var/lib/dpkg/status.d/"
DPKG_INFO: Final = "var/lib/dpkg/info/"
APK_INSTALLED: Final = "lib/apk/db/installed"
APK_INSTALLED_USR: Final = "usr/lib/apk/db/installed"
"""Where Wolfi and Chainguard's images (apk-tools 2.14 on a merged /usr) keep the same database."""
PACMAN_LOCAL: Final = "var/lib/pacman/local/"
"""Arch Linux: one directory per installed package, `desc` its record and `files` what it installs."""
PORTAGE_DB: Final = "var/db/pkg/"
"""Gentoo: `<category>/<name>-<version>/`, one small file per fact."""
PORTAGE_FILES: Final = frozenset({"CONTENTS", "RDEPEND", "SLOT", "repository", "PROVIDES"})
RPM_SQLITE: Final = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
RPM_LEGACY: Final = (
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/Packages",
    "var/lib/rpm/Packages.db",
    "usr/lib/sysimage/rpm/Packages.db",
)
OS_RELEASE: Final = ("etc/os-release", "usr/lib/os-release")
APT_STATES: Final = "var/lib/apt/extended_states"
APK_WORLD: Final = "etc/apk/world"

_WANTED_EXACT: Final = frozenset(
    {
        DPKG_STATUS,
        APK_INSTALLED,
        APK_INSTALLED_USR,
        *RPM_SQLITE,
        *(p + "-wal" for p in RPM_SQLITE),
        *RPM_LEGACY,
        *OS_RELEASE,
        APT_STATES,
        APK_WORLD,
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
            r"^var/(?:cache|log)/|^var/lib/(?:apt/lists|dpkg|rpm|apk|yum|dnf|zypp|alternatives|pacman)/|^etc/alternatives/|^(?:usr/)?lib/apk/db/|^usr/lib/sysimage/rpm/|^var/db/pkg/"
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
TOOLCHAIN_BINARIES: Final = re.compile(r"^usr/local/go/(?:bin|pkg/tool/[^/]+)/[^/]+$")
"""A Go toolchain's own programs: not content-scanned with the rest of its tree, but read for the
modules each was built from, as any other Go binary in the image is."""
OWNED_JAR_BYTES: Final = 64 << 20
"""A jar a distribution package installs is read for the artifacts it records, up to this size."""


@dataclass
class ImageIdentity:
    """What the image is, from its archive: the digests a registry and a runtime know it by, the
    names it was saved under, its layers, its platform, and what its labels say it was built from."""

    image_id: str | None = None
    """The SHA-256 of the image's configuration: the ID `docker images` shows."""
    manifest_digest: str | None = None
    """The digest a registry serves it under -- what `image@sha256:...` pins. An OCI layout (and
    `docker save` from Docker 25) records it; an older `docker save` does not."""
    references: tuple[str, ...] = ()
    layers: tuple[str, ...] = ()
    """Each layer's uncompressed digest (`rootfs.diff_ids`), bottom first."""
    platform: str = ""
    created: str = ""
    base_name: str | None = None
    base_digest: str | None = None
    source: str | None = None
    revision: str | None = None

    DIGEST: ClassVar[re.Pattern[str]] = re.compile(r"^sha256:[0-9a-f]{64}$")

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_id": self.image_id,
            "manifest_digest": self.manifest_digest,
            "references": list(self.references),
            "layers": list(self.layers),
            "platform": self.platform or None,
            "created": self.created or None,
            "base": {"name": self.base_name, "digest": self.base_digest}
            if self.base_name
            else None,
            "source": self.source,
            "revision": self.revision,
        }

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _digest(value: Any) -> str | None:
        return value if isinstance(value, str) and ImageIdentity.DIGEST.match(value) else None

    @staticmethod
    def read(data: bytes) -> ImageIdentity:
        import hashlib

        identity = ImageIdentity()
        references: list[str] = []
        config_bytes: bytes | None = None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            by_path = ImageLayers._members_by_path(archive)
            if "index.json" in by_path:
                index = json.loads(ImageLayers._read_member(archive, by_path["index.json"]))
                descriptor: Any = (
                    (index.get("manifests") or [{}])[0] if isinstance(index, dict) else {}
                )
                identity.manifest_digest = ImageIdentity._digest(descriptor.get("digest"))
                annotations = (
                    descriptor.get("annotations")
                    if isinstance(descriptor.get("annotations"), dict)
                    else {}
                )
                for key in ("io.containerd.image.name", "org.opencontainers.image.ref.name"):
                    value = annotations.get(key)
                    if (
                        isinstance(value, str)
                        and value
                        and value not in references
                        and (key != "org.opencontainers.image.ref.name" or not references)
                    ):
                        references.append(value)
                # An index (several platforms) leads to the manifest of the first, which names the config.
                for _ in range(4):
                    algorithm, _, hexdigest = str(descriptor.get("digest", "")).partition(":")
                    blob = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                    if blob is None:
                        break
                    document = json.loads(ImageLayers._read_member(archive, blob))
                    if isinstance(document, dict) and isinstance(document.get("config"), dict):
                        algorithm, _, hexdigest = str(
                            document["config"].get("digest", "")
                        ).partition(":")
                        config_path = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                        if config_path is not None:
                            config_bytes = ImageLayers._read_member(archive, config_path)
                        break
                    manifests = document.get("manifests") if isinstance(document, dict) else None
                    if not manifests:
                        break
                    descriptor = manifests[0]
            if "manifest.json" in by_path:
                manifest = json.loads(ImageLayers._read_member(archive, by_path["manifest.json"]))
                entry = (
                    manifest[0]
                    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict)
                    else {}
                )
                for tag in entry.get("RepoTags") or ():
                    if isinstance(tag, str) and tag not in references:
                        references.append(tag)
                config_path = by_path.get(ImageLayers._normalise(str(entry.get("Config", ""))))
                if config_bytes is None and config_path is not None:
                    config_bytes = ImageLayers._read_member(archive, config_path)
        identity.references = tuple(references)
        if config_bytes is None:
            return identity
        identity.image_id = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        config = json.loads(config_bytes)
        if not isinstance(config, dict):
            return identity
        rootfs = ImageIdentity._mapping(config.get("rootfs"))
        identity.layers = tuple(
            d for d in (rootfs.get("diff_ids") or ()) if ImageIdentity._digest(d)
        )
        identity.platform = "/".join(
            str(config[k])
            for k in ("os", "architecture", "variant")
            if isinstance(config.get(k), str) and config[k]
        )
        identity.created = str(config.get("created") or "")
        labels = ImageIdentity._mapping(ImageIdentity._mapping(config.get("config")).get("Labels"))
        text = {k: v for k, v in labels.items() if isinstance(k, str) and isinstance(v, str) and v}
        identity.base_name = text.get("org.opencontainers.image.base.name")
        identity.base_digest = ImageIdentity._digest(
            text.get("org.opencontainers.image.base.digest")
        )
        identity.source = text.get("org.opencontainers.image.source")
        identity.revision = text.get("org.opencontainers.image.revision")
        return identity


@dataclass
class ImageInventory:
    identity: ImageIdentity = field(default_factory=ImageIdentity)
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
    binaries_as_strings: int = 0
    """Files past the per-file limit content-scanned as their printable strings."""
    removed_files: int = 0
    """Added files a later layer deleted or replaced: absent from the running container, still in
    the image's layers for anyone who pulls it."""


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
        if path.startswith(PACMAN_LOCAL):
            # `<name>-<version>-<release>/desc` and `/files`: two levels down, no deeper.
            rest = path[len(PACMAN_LOCAL) :].split("/")
            return len(rest) == 2 and rest[1] in ("desc", "files")
        if path.startswith(PORTAGE_DB):
            rest = path[len(PORTAGE_DB) :].split("/")
            return len(rest) == 3 and rest[2] in PORTAGE_FILES
        return path.startswith(DPKG_INFO) and path.endswith(".list")

    LAYER_MEMBER: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}/layer\.tar|[0-9a-f]{64}\.json)$"
    )
    """An OCI layout's blob, or a classic `docker save` layer or configuration."""

    @staticmethod
    def cut_short(data: bytes) -> bool:
        """A tar that ends early, whose members so far are an image's: `docker save` writes the
        layers first and the manifest last, so a cut archive has lost the manifest that says what
        it is, and only its layer blobs say it was an image."""
        seen = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive:
                    if ImageLayers.LAYER_MEMBER.match(ImageLayers._normalise(member.name)):
                        seen += 1
                return False
        except (tarfile.TarError, OSError, ValueError, EOFError):
            return seen > 0

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
        layer: tarfile.TarFile,
        files: dict[str, bytes],
        keep: Keep,
        budget: list[int],
        removed: Removed | None = None,
        origin: dict[str, int] | None = None,
        index: int = 0,
        peek: Peek | None = None,
    ) -> None:
        """Apply one layer over `files`.

        With `removed`, a kept file this layer deletes or replaces is not forgotten: it is appended
        as `(layer that added it, path, bytes)`. Deleting a file in a later layer hides it from the
        running container and from nobody else -- `docker save` or a registry pull hands over every
        layer, and the bytes are in the one that added them.
        """

        def drop(path: str) -> None:
            payload = files.pop(path, None)
            if payload is None or removed is None:
                return
            removed.append(((origin or {}).get(path, 0), path, payload))

        for count, member in enumerate(layer):
            if count >= MAX_MEMBERS_PER_LAYER:
                raise ValueError("a layer has more members than the reader walks")
            path = ImageLayers._normalise(member.name)
            directory, base = posixpath.split(path)
            if base == ".wh..wh..opq":
                prefix = directory + "/" if directory else ""
                for known in [k for k in files if k.startswith(prefix)]:
                    drop(known)
                continue
            if base.startswith(".wh."):
                gone = posixpath.join(directory, base[len(".wh.") :])
                for known in [k for k in files if k == gone or k.startswith(gone + "/")]:
                    drop(known)
                continue
            if not member.isfile():
                drop(path)
                continue
            if not keep(path, member.size):
                drop(path)  # replaced by something not kept: the earlier copy is gone too
                if peek is not None and peek.wants(path, member.size):
                    handle = layer.extractfile(member)
                    if handle is not None:
                        if member.size <= MAX_HELD_BYTES:
                            peek.read(path, handle.read(member.size))
                        else:
                            peek.stream(path, handle, member.size)
                continue
            handle = layer.extractfile(member)
            if handle is None:
                continue
            previous = len(files.get(path, b""))
            budget[0] -= member.size - previous
            if budget[0] < 0:
                raise MemoryError("the image's files are larger than the reader keeps")
            payload = handle.read()
            if removed is not None and path in files and files[path] != payload:
                drop(path)
            files[path] = payload
            if origin is not None:
                origin[path] = index

    @staticmethod
    def _squash(
        data: bytes,
        keep: Keep,
        budget: int,
        inventory: ImageInventory,
        *,
        count_layers: bool,
        removed: Removed | None = None,
        peek: Peek | None = None,
    ) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        origin: dict[str, int] = {}
        remaining = [budget]
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            paths = ImageLayers._layer_paths(archive, inventory.problems if count_layers else [])
            if len(paths) > MAX_LAYERS:
                raise ValueError(f"the image has more than {MAX_LAYERS} layers")
            for number, name in enumerate(paths, start=1):
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
                        ImageLayers._apply_layer(
                            layer, files, keep, remaining, removed, origin, number, peek
                        )
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
        try:
            inventory.identity = ImageIdentity.read(data)
        except (KeyError, ValueError, tarfile.TarError, OSError) as exc:
            inventory.problems.append(
                f"the image's manifest and configuration were not read ({type(exc).__name__})"
            )
        return ImageLayers.databases(files, inventory)

    @staticmethod
    def databases(files: dict[str, bytes], inventory: ImageInventory) -> ImageInventory:
        """The release and the package databases among `files` (paths relative to the root, as
        `_wanted` selects them), with the files those packages own. Shared by an image, whose files
        come from its squashed layers, and a host (`images/host.py`), whose come from its disk."""
        for path in OS_RELEASE:
            if path in files:
                inventory.release = pkgdb.PackageDatabases.os_release(files[path])
                break
        owned: set[str] = set()
        if DPKG_STATUS in files:
            inventory.packages.extend(pkgdb.PackageDatabases.dpkg(files[DPKG_STATUS]))
        # distroless keeps one stanza per package in `status.d/<name>` and that package's files in
        # `status.d/<name>.md5sums`, where Debian has `info/<name>.list`. The md5sums were read
        # as if they were stanzas and never as file lists, so every file a distroless package
        # installs - the whole Python standard library in a distroless Python image - looked
        # added by the image and was content-scanned as if it were the application's own code.
        for path in sorted(p for p in files if p.startswith(DPKG_STATUS_D)):
            if path.endswith(".md5sums"):
                owned |= pkgdb.PackageDatabases.dpkg_md5sums_owned(files[path])
            else:
                inventory.packages.extend(pkgdb.PackageDatabases.dpkg(files[path]))
        owned |= pkgdb.PackageDatabases.dpkg_owned(
            [files[p] for p in files if p.startswith(DPKG_INFO)]
        )
        for path in (APK_INSTALLED, APK_INSTALLED_USR):
            if path in files:
                inventory.packages.extend(pkgdb.PackageDatabases.apk(files[path]))
                owned |= pkgdb.PackageDatabases.apk_owned(files[path])
                break
        pacman = {p: files[p] for p in files if p.startswith(PACMAN_LOCAL)}
        if pacman:
            inventory.packages.extend(pkgdb.PackageDatabases.pacman(pacman))
            owned |= pkgdb.PackageDatabases.pacman_owned(pacman)
        portage = {p: files[p] for p in files if p.startswith(PORTAGE_DB)}
        if portage:
            inventory.packages.extend(pkgdb.PackageDatabases.portage(portage))
            owned |= pkgdb.PackageDatabases.portage_owned(portage)
        # Which packages were asked for: apt marks what it pulled in automatically, apk lists what
        # was requested. Without either, the graph's roots stand for them.
        automatic = (
            pkgdb.PackageDatabases.apt_automatic(files[APT_STATES]) if APT_STATES in files else None
        )
        world = pkgdb.PackageDatabases.apk_world(files[APK_WORLD]) if APK_WORLD in files else None
        if automatic is not None or world is not None:
            inventory.packages = [
                replace(package, requested=package.name not in automatic)
                if package.manager == "dpkg" and automatic is not None
                else replace(
                    package,
                    requested=package.name in world or any(p in world for p in package.provides),
                )
                if package.manager == "apk" and world is not None
                else package
                for package in inventory.packages
            ]
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
                # The distribution's own files are not content-scanned, but a language package it
                # installed (python3-jinja2's METADATA, a jar under /usr/share/java) is still
                # installed, and still in the inventory.
                if langpkgs.LanguagePackages.is_metadata(path):
                    return size <= 1 << 20
                return path.endswith(".jar") and size <= OWNED_JAR_BYTES
            reason = ImageLayers.skip_reason(path)
            if reason is not None:
                if langpkgs.LanguagePackages.is_metadata(path) and size <= 1 << 20:
                    return True
                if TOOLCHAIN_BINARIES.match(path) and size <= MAX_HELD_BYTES:
                    return True
                if path.endswith(".jar") and size <= OWNED_JAR_BYTES:
                    # A runtime's own jars (a JDK's jce.jar, jrt-fs.jar) are not content-scanned
                    # but are inventoried, as a distribution's are.
                    return True
                skipped[reason] = skipped.get(reason, 0) + 1
                return False
            if size > max_file_bytes:
                if size > MAX_PEEK_BYTES:
                    skipped[OVERSIZE] = skipped.get(OVERSIZE, 0) + 1
                return False
            return True

        peek = Peek(max_file_bytes)
        removed: Removed = []
        files = ImageLayers._squash(
            data, keep, max_total_bytes, inventory, count_layers=False, removed=removed, peek=peek
        )
        inventory.language_packages.extend(peek.packages)
        # A program named by its version string counts only where no package database owns it.
        inventory.language_packages.extend(p for p in peek.known if p.path not in inventory.owned)
        if peek.truncated:
            skipped[OVERSIZE_STRINGS] = peek.truncated
        for path in sorted(files):
            if ImageLayers.skip_reason(path) is not None or path in inventory.owned:
                metadata[path] = files.pop(path)
        from cordon_scanner.images.binmeta import BinaryMetadata

        for path, payload in sorted(metadata.items()):
            if TOOLCHAIN_BINARIES.match(path):
                inventory.language_packages.extend(BinaryMetadata.extract(path, payload))
                continue
            if path.endswith(".jar"):
                inventory.language_packages.extend(BinaryMetadata.extract(path, payload))
                continue
            if path in inventory.owned:
                # A distribution's own Python, Ruby or npm package (python3-cryptography's
                # METADATA): already in the inventory as that OS package, and patched by the
                # distribution, so not counted again under the language's name.
                continue
            inventory.language_packages.extend(langpkgs.LanguagePackages.parse_all(path, payload))
        inventory.skipped = skipped
        inventory.added_files = len(files)
        inventory.binaries_as_strings = len(peek.strings)
        from cordon_scanner.images.binmeta import KnownBinaries

        for path in sorted(files):
            # Package metadata outside the trees that are not content-scanned (an R library under
            # /usr/local/lib/R, a vendor tree in the application) is inventoried as well as read.
            if langpkgs.LanguagePackages.is_metadata(path) and len(files[path]) <= 1 << 20:
                inventory.language_packages.extend(
                    langpkgs.LanguagePackages.parse_all(path, files[path])
                )
            inventory.language_packages.extend(KnownBinaries.identify(path, files[path]))
            # A binary small enough to scan as bytes still records what it was built from.
            if (
                path.endswith((".deps.json", ".jar", ".war", ".ear"))
                or files[path][:4] == b"\x7fELF"
            ):
                inventory.language_packages.extend(BinaryMetadata.extract(path, files[path]))
            yield path, files[path]
        yield from peek.files()
        # Deleted or replaced by a later layer, and still in the image. Named under the layer that
        # added them, so a finding says where the bytes are: `layer-3-removed/app/token.txt`.
        seen: set[tuple[int, str, int]] = set()
        for number, path, payload in removed:
            if ImageLayers.skip_reason(path) is not None:
                continue
            key = (number, path, hash(payload))
            if key in seen:
                continue
            seen.add(key)
            inventory.removed_files += 1
            yield f"{REMOVED_PREFIX.format(number)}{path}", payload
        for path, payload in ImageConfig.files(data):
            yield path, payload


Keep = Callable[[str, int], bool]
Removed = list[tuple[int, str, bytes]]

#: Past the per-file limit, a file up to `MAX_HELD_BYTES` is read whole for its build metadata and
#: strings, and one up to `MAX_PEEK_BYTES` is streamed in chunks for the same, never held.
MAX_HELD_BYTES: Final = 256 << 20
MAX_PEEK_BYTES: Final = 4 << 30
#: The strings of every large file in one image together: what the scan holds at once.
MAX_PEEK_STRINGS_BYTES: Final = 512 << 20
OVERSIZE_STRINGS: Final = "more printable text than is scanned, so its strings were cut short"
#: Where the second and later parts of a binary's strings are reported: `usr/bin/app!strings-2`.
STRINGS_PART: Final = "{}!strings-{}"


class Peek:
    """Files past the per-file content limit, read once: the packages a compiled artefact records
    (`images/binmeta.py`) and, for content rules, its printable strings in place of its bytes."""

    def __init__(
        self, max_file_bytes: int, budget: int = MAX_PEEK_STRINGS_BYTES, part: int | None = None
    ) -> None:
        from cordon_scanner.images.binmeta import MAX_STRINGS_BYTES

        self.max_file_bytes = max_file_bytes
        self.part = part or MAX_STRINGS_BYTES
        self.packages: list[langpkgs.LanguagePackage] = []
        self.known: list[langpkgs.LanguagePackage] = []
        self.strings: dict[str, list[bytes]] = {}
        self.truncated = 0
        self.budget = budget

    def wants(self, path: str, size: int) -> bool:
        return (
            self.max_file_bytes < size <= MAX_PEEK_BYTES and ImageLayers.skip_reason(path) is None
        )

    def _allowance(self, path: str) -> int:
        from cordon_scanner.images.binmeta import MAX_STRINGS_TOTAL

        held = sum(len(p) for name, parts in self.strings.items() if name != path for p in parts)
        return max(0, min(MAX_STRINGS_TOTAL, self.budget - held))

    def _keep(self, path: str, parts: list[bytes], complete: bool) -> None:
        if not complete:
            self.truncated += 1
        self.strings[path] = parts

    def read(self, path: str, data: bytes) -> None:
        from cordon_scanner.images.binmeta import BinaryMetadata, StringParts

        self.packages = [
            p for p in self.packages if p.path != path and not p.path.startswith(path + "!")
        ]
        from cordon_scanner.images.binmeta import BinaryClassifiers

        self.packages.extend(BinaryMetadata.extract(path, data))
        from cordon_scanner.images.binmeta import KnownBinaries

        self.known.extend(KnownBinaries.identify(path, data))
        strings = StringParts(self._allowance(path), self.part)
        strings.add(data)
        parts = strings.finish()
        self.packages.extend(BinaryClassifiers.from_strings(path, parts))
        self._keep(path, parts, strings.complete)

    def stream(self, path: str, handle: Any, size: int) -> None:
        from cordon_scanner.images.binmeta import BinaryClassifiers, StreamedBinary, StreamedJar

        self.packages = [p for p in self.packages if p.path != path]
        if path.lower().endswith((".jar", ".war", ".ear")):
            # An application packed as one jar past the hold limit (an uberjar of every library it
            # uses): its entries walked for the Maven artifacts they record. A jar's bytes are
            # compressed, so its strings would be noise and are not taken.
            self.packages.extend(StreamedJar.read(path, handle, size))
            return
        packages, parts, complete = StreamedBinary.read(
            path, handle, size, self._allowance(path), self.part
        )
        self.packages.extend(packages)
        self.packages.extend(BinaryClassifiers.from_strings(path, parts))
        self._keep(path, parts, complete)

    def files(self) -> Iterator[tuple[str, bytes]]:
        for path, parts in sorted(self.strings.items()):
            for number, part in enumerate(parts, start=1):
                yield (path if number == 1 else STRINGS_PART.format(path, number)), part


#: Where a file a later layer removed is reported, by the number of the layer that added it.
REMOVED_PREFIX: Final = "layer-{}-removed/"
#: Where the image's configuration is reported: what `docker inspect` shows of it.
CONFIG_PREFIX: Final = "image-config/"


class ImageConfig:
    """The image configuration: environment, entrypoint, command, labels and build history.

    None of it is a file in any layer, and all of it ships with the image: `ENV GITHUB_TOKEN=...`
    and `ARG` values a `RUN` line expanded are readable by anyone who pulls it. Rendered as two
    text files for the secret detectors. Build commands are not judged as a Dockerfile's would be:
    a history interleaves the base image's own build with the author's, with nothing marking where
    one ends, and an official image's verified download would read as the author's.
    """

    @staticmethod
    def _document(data: bytes) -> dict[str, Any] | None:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            by_path = ImageLayers._members_by_path(archive)
            name: str | None = None
            if "manifest.json" in by_path:
                manifest = json.loads(ImageLayers._read_member(archive, by_path["manifest.json"]))
                if isinstance(manifest, list) and manifest and manifest[0].get("Config"):
                    name = by_path.get(ImageLayers._normalise(str(manifest[0]["Config"])))
            elif "index.json" in by_path:
                index = json.loads(ImageLayers._read_member(archive, by_path["index.json"]))
                descriptor: Any = (index.get("manifests") or [{}])[0]
                for _ in range(4):
                    algorithm, _, hexdigest = str(descriptor.get("digest", "")).partition(":")
                    document = json.loads(
                        ImageLayers._read_member(archive, by_path[f"blobs/{algorithm}/{hexdigest}"])
                    )
                    if "config" in document:
                        algorithm, _, hexdigest = str(
                            document["config"].get("digest", "")
                        ).partition(":")
                        name = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                        break
                    manifests = document.get("manifests") or []
                    if not manifests:
                        break
                    descriptor = manifests[0]
            if name is None:
                return None
            config = json.loads(ImageLayers._read_member(archive, name))
        return config if isinstance(config, dict) else None

    @staticmethod
    def files(data: bytes) -> list[tuple[str, bytes]]:
        try:
            config = ImageConfig._document(data)
        except (KeyError, ValueError, tarfile.TarError, OSError):
            return []
        if config is None:
            return []
        raw_runtime = config.get("config")
        runtime: dict[str, Any] = raw_runtime if isinstance(raw_runtime, dict) else {}
        lines: list[str] = []
        for entry in runtime.get("Env") or ():
            if isinstance(entry, str) and "=" in entry:
                lines.append(entry)
        raw_labels = runtime.get("Labels")
        labels: dict[str, Any] = raw_labels if isinstance(raw_labels, dict) else {}
        for key, value in sorted(labels.items()):
            lines.append(f"LABEL_{key}={value}")
        environment = "\n".join(lines) + "\n" if lines else ""
        commands: list[str] = []
        for key in ("Entrypoint", "Cmd"):
            value = runtime.get(key)
            if isinstance(value, list):
                commands.append(f"{key.upper()} " + " ".join(str(v) for v in value))
        for step in config.get("history") or ():
            if isinstance(step, dict) and isinstance(step.get("created_by"), str):
                commands.append(step["created_by"])
        out: list[tuple[str, bytes]] = []
        if environment:
            out.append((f"{CONFIG_PREFIX}environment.env", environment.encode()))
        if commands:
            out.append((f"{CONFIG_PREFIX}history.txt", ("\n".join(commands) + "\n").encode()))
        return out


_MERGED: Final = ("bin/", "sbin/", "lib/", "lib32/", "lib64/", "libx32/")


__all__ = [
    "CONFIG_PREFIX",
    "OVERSIZE",
    "OVERSIZE_STRINGS",
    "REMOVED_PREFIX",
    "ImageConfig",
    "ImageIdentity",
    "ImageInventory",
    "ImageLayers",
    "Peek",
]
