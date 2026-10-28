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
from dataclasses import replace
from typing import IO, TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.images import langpkgs
from cordon_scanner.images import packages as pkgdb

if TYPE_CHECKING:
    from cordon_scanner.images.identity import ImageInventory

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
    def _real_platforms(manifests: list[Any]) -> list[tuple[int, str]]:
        """`(index, "os/arch[/variant]")` for each manifest of an image index that is an image for
        a platform. buildx adds attestation manifests under `unknown/unknown`: not platforms."""
        out: list[tuple[int, str]] = []
        for index, descriptor in enumerate(manifests):
            platform = descriptor.get("platform") if isinstance(descriptor, dict) else None
            if not isinstance(platform, dict):
                out.append((index, ""))
                continue
            label = "/".join(
                str(platform[key]) for key in ("os", "architecture", "variant") if platform.get(key)
            )
            if label and not label.startswith("unknown"):
                out.append((index, label))
        return out

    @staticmethod
    def platforms(data: bytes) -> list[tuple[int, str]]:
        """The platforms of a multi-platform image, as `(manifest index, label)`; [] for one."""
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                by_path = ImageLayers._members_by_path(archive)
                if "index.json" not in by_path:
                    return []
                document = json.loads(ImageLayers._read_member(archive, by_path["index.json"]))
                for _ in range(4):
                    manifests = document.get("manifests") or []
                    real = ImageLayers._real_platforms(manifests)
                    if len(real) > 1:
                        return real
                    if len(manifests) != 1:
                        return []
                    digest = str(manifests[0].get("digest", ""))
                    algorithm, _, hexdigest = digest.partition(":")
                    member = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                    if member is None:
                        return []
                    document = json.loads(ImageLayers._read_member(archive, member))
                    if "layers" in document:
                        return []
        except (tarfile.TarError, OSError, ValueError, KeyError):
            return []
        return []

    @staticmethod
    def _layer_paths(
        archive: tarfile.TarFile, problems: list[str], platform: int | None = None
    ) -> list[str]:
        """The image's layer members, bottom first. The first image when a tarball holds several;
        for a multi-platform image, the manifest `platform` names, else the first real platform."""
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
                real = ImageLayers._real_platforms(manifests)
                chosen = platform if platform is not None else (real[0][0] if real else 0)
                if not 0 <= chosen < len(manifests):
                    raise ValueError(f"the image index has no manifest {chosen}")
                descriptor = manifests[chosen]
                continue
            descriptor = manifests[0]
        raise ValueError("the OCI layout names no image manifest")

    #: Stream magics a layer is compressed with: gzip, zstd, bzip2, xz.
    _LAYER_MAGICS: ClassVar[tuple[bytes, ...]] = (
        b"\x1f\x8b",
        b"\x28\xb5\x2f\xfd",
        b"BZh",
        b"\xfd7zXZ\x00",
    )

    @staticmethod
    def _is_archive(raw: IO[bytes]) -> bool:
        """Whether a layer blob is a (compressed) tar at all, read from its first bytes only."""
        head = raw.read(512)
        raw.seek(0)
        if any(head.startswith(magic) for magic in ImageLayers._LAYER_MAGICS):
            return True
        # An uncompressed tar: `ustar` at offset 257, or an empty archive of zero blocks.
        return head[257:262] == b"ustar" or (len(head) == 512 and not head.strip(b"\x00"))

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
        """A zstd decompressor: the standard library's (Python 3.14+), else the core's own
        (`intel/store/zstd`), which reads the layer as a stream, as the gzip path does -- no layer
        too large to read, and no third-party decoder."""
        import importlib

        try:
            zstd = importlib.import_module("compression.zstd")
            reader: IO[bytes] = zstd.ZstdFile(raw)
            return reader
        except ImportError:
            pass
        from cordon_scanner.intel.store.zstd import Zstd

        return io.BufferedReader(Zstd.Reader(raw))

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
        platform: int | None = None,
    ) -> dict[str, bytes]:

        files: dict[str, bytes] = {}
        origin: dict[str, int] = {}
        remaining = [budget]
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            paths = ImageLayers._layer_paths(
                archive, inventory.problems if count_layers else [], platform
            )
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
                if not ImageLayers._is_archive(handle):
                    # An OCI artifact's blob -- an attestation, an SBOM, a JSON document listed
                    # as a layer -- holds no filesystem, so nothing of the OS inventory is in it.
                    # Counted as unread, it scored 233 of 650 benign images "not fully examined"
                    # for a 600-byte JSON file (review 98).
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
    def squash(data: bytes, platform: int | None = None) -> tuple[dict[str, bytes], ImageInventory]:
        """The package databases, their file lists and `os-release`, as the top layer leaves them."""
        from cordon_scanner.images.identity import ImageInventory

        inventory = ImageInventory()
        files = ImageLayers._squash(
            data,
            lambda path, _size: ImageLayers._wanted(path),
            MAX_WANTED_BYTES,
            inventory,
            count_layers=True,
            platform=platform,
        )
        return files, inventory

    @staticmethod
    def read_image(data: bytes, platform: int | None = None) -> ImageInventory:
        """The operating-system inventory of an image tarball, and what its packages own. For a
        multi-platform image, of the platform whose manifest index is given, else the first."""
        from cordon_scanner.images.identity import ImageIdentity

        files, inventory = ImageLayers.squash(data, platform)
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
        ImageLayers._mark_requested(files, inventory)
        blobs: list[bytes] = []
        for path in RPM_SQLITE:
            if path in files:
                try:
                    blobs = pkgdb.PackageDatabases.rpm_sqlite_blobs(
                        files[path], files.get(path + "-wal")
                    )
                except Exception as exc:  # noqa: BLE001
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
        ImageLayers._unique_packages(inventory)
        return inventory

    @staticmethod
    def _mark_requested(files: dict[str, bytes], inventory: ImageInventory) -> None:
        """Which packages were asked for: those apt did not pull in automatically, and those apk's world names."""

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

    @staticmethod
    def _unique_packages(inventory: ImageInventory) -> None:
        """One entry per package: distroless ships each in both status and status.d."""

        # distroless ships a package in both `status` and `status.d`; one entry each.
        seen: set[tuple[str, str, str]] = set()
        unique = []
        for package in inventory.packages:
            key = (package.manager, package.name, package.version)
            if key not in seen:
                seen.add(key)
                unique.append(package)
        inventory.packages = unique

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
        ImageLayers._record_added(inventory, peek, skipped, files, metadata)
        from cordon_scanner.images.binmeta import BinaryMetadata, KnownBinaries

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

    @staticmethod
    def _record_added(
        inventory: ImageInventory,
        peek: Peek,
        skipped: dict[str, int],
        files: dict[str, bytes],
        metadata: dict[str, bytes],
    ) -> None:
        """What the squashed files tell the inventory: the language packages found, the binaries' metadata, what was skipped and how many files the image adds."""
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
            # A distribution's own Python, Ruby or npm package (python3-cryptography's METADATA) is
            # listed under the language's name as well as the OS package's, as Syft lists it. It
            # was once skipped as already counted; measured against Syft on ten images that ship
            # them, listing them raised agreement on every one (odoo 0.85 to 1.0) and added no
            # package Syft does not list.
            inventory.language_packages.extend(langpkgs.LanguagePackages.parse_all(path, payload))
        inventory.skipped = skipped
        inventory.added_files = len(files)
        inventory.binaries_as_strings = len(peek.strings)
        inventory.as_strings = {path: peek.heads.get(path, b"") for path in peek.strings}


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


HEAD_BYTES: Final = 64
"""Enough of a file's start for every signature `detect/binary.FORMATS` reads."""


class PrefixedReader:
    """A stream whose first bytes were read off already, put back in front of it."""

    def __init__(self, head: bytes, handle: Any) -> None:
        self._head = head
        self._handle: IO[bytes] = handle

    def read(self, n: int = -1) -> bytes:
        if not self._head:
            return self._handle.read(n)
        if n < 0:
            out, self._head = self._head + self._handle.read(), b""
            return out
        out, self._head = self._head[:n], self._head[n:]
        if len(out) < n:
            out += self._handle.read(n - len(out))
        return out


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
        self.heads: dict[str, bytes] = {}

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

        self.heads[path] = data[:HEAD_BYTES]
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
        head = handle.read(HEAD_BYTES)
        self.heads[path] = head
        handle = PrefixedReader(head, handle)
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
        # What the engine needs to know what the image runs on start (`Ceilings.image_start_ceiling`).
        if isinstance(runtime.get("WorkingDir"), str) and runtime["WorkingDir"]:
            commands.append(f"WORKDIR {runtime['WorkingDir']}")
        healthcheck = runtime.get("Healthcheck")
        if isinstance(healthcheck, dict) and isinstance(healthcheck.get("Test"), list):
            commands.append("HEALTHCHECK " + " ".join(str(v) for v in healthcheck["Test"]))
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
    "ImageLayers",
    "Peek",
]
