"""Package databases and `os-release`, parsed from bytes: dpkg, apk and RPM (SQLite rpmdb).

Each package keeps what it requires and provides as its database records them -- dpkg's
`Depends` / `Pre-Depends` and `Provides`, apk's `D:` and `p:`, RPM's REQUIRENAME and PROVIDENAME
(and the files it owns, which a path requirement names) -- and whether it was asked for: apt's
`extended_states` marks what it installed automatically, apk's `world` lists what was requested.
`PackageGraph` turns that into the installed graph.
"""

from __future__ import annotations

import contextlib
import re
import sqlite3
import struct
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Final

MAX_PACKAGES: Final = 20_000
MAX_HEADER_BYTES: Final = 16 << 20

RPM_NAME, RPM_VERSION, RPM_RELEASE, RPM_EPOCH, RPM_ARCH, RPM_SOURCERPM = (
    1000,
    1001,
    1002,
    1003,
    1022,
    1044,
)
RPM_PROVIDENAME, RPM_REQUIRENAME = 1047, 1049
MAX_RELATIONS: Final = 10_000
"""Requirements or provisions read from one package: far past any real package's."""
_RPM_STRING, _RPM_INT32, _RPM_I18NSTRING = 6, 4, 9


@dataclass(frozen=True)
class OsRelease:
    id: str
    version_id: str
    version: str = ""
    pretty_name: str = ""

    @property
    def advisory_source(self) -> str | None:
        """`osv`, `alas` (Amazon's own advisories), or None when nothing publishes them."""
        if self.osv_ecosystem is not None:
            return "osv"
        if self.id == "amzn" and self.version_id in ("2", "2023"):
            return "alas"
        return None

    @property
    def osv_ecosystem(self) -> str | None:
        """OSV's name for this distribution release, or None when OSV does not cover it."""
        major = self.version_id.split(".", 1)[0]
        if self.id == "debian" and major.isdigit():
            return f"Debian:{major}"
        if self.id == "ubuntu" and self.version_id:
            return f"Ubuntu:{self.version_id}" + (":LTS" if "LTS" in self.version else "")
        if self.id == "alpine" and self.version_id.count(".") >= 1:
            return "Alpine:v" + ".".join(self.version_id.split(".")[:2])
        if self.id == "rocky" and major:
            return f"Rocky Linux:{major}"
        if self.id == "almalinux" and major:
            return f"AlmaLinux:{major}"
        if self.id == "rhel":
            return "Red Hat"
        if self.id == "opensuse-leap" and self.version_id:
            return f"openSUSE:Leap {self.version_id}"
        if self.id in ("sles", "sled") and self.version_id:
            base, _, service_pack = self.version_id.partition(".")
            product = "Server" if self.id == "sles" else "Desktop"
            suffix = f" SP{service_pack}" if service_pack and service_pack != "0" else ""
            return f"SUSE:Linux Enterprise {product} {base}{suffix}"
        if self.id == "wolfi":
            return "Wolfi"
        if self.id == "chainguard":
            return "Chainguard"
        return None


@dataclass(frozen=True)
class OsPackage:
    manager: str
    """`dpkg`, `apk`, `rpm`, `pacman` (Arch) or `portage` (Gentoo)."""
    name: str
    version: str
    arch: str = ""
    source: str = ""
    """The source package advisories name: dpkg's `Source`, apk's origin, the SRPM's name."""
    source_version: str = ""
    epoch: str = ""
    requires: tuple[str, ...] = ()
    """What it needs installed: each entry a name, or `a|b` for alternatives any one of which does."""
    provides: tuple[str, ...] = ()
    """Names and capabilities it satisfies besides its own name."""
    requested: bool | None = None
    """Asked for (True) or pulled in by another package (False); None where the image does not say."""
    triggered_by: tuple[str, ...] = ()
    """apk's `install_if`: installed because all of these are (`ssl_client` with busybox and
    libssl3). Each is a parent in the graph, as a requirer is."""

    MANAGERS: ClassVar[tuple[str, ...]] = ("dpkg", "apk", "rpm", "pacman", "portage")
    PURL_TYPE: ClassVar[dict[str, str]] = {
        "dpkg": "deb",
        "apk": "apk",
        "rpm": "rpm",
        "pacman": "alpm",
        "portage": "ebuild",
    }
    NAMESPACE: ClassVar[dict[str, str]] = {
        "dpkg": "debian",
        "apk": "alpine",
        "rpm": "redhat",
        "pacman": "arch",
        "portage": "gentoo",
    }
    DATABASE: ClassVar[dict[str, str]] = {
        "dpkg": "var/lib/dpkg/status",
        "apk": "lib/apk/db/installed",
        "rpm": "var/lib/rpm/rpmdb.sqlite",
        "pacman": "var/lib/pacman/local",
        "portage": "var/db/pkg",
    }
    """Where a finding about the package points: the database that records it."""

    @property
    def advisory_name(self) -> str:
        # Debian's and Alpine's advisories are about source packages; RPM distributions' are about
        # the binary packages a system installs.
        return (self.source or self.name) if self.manager in ("dpkg", "apk") else self.name

    @property
    def advisory_version(self) -> str:
        if self.manager == "dpkg":
            return self.source_version or self.version
        if self.manager == "rpm" and self.epoch and self.epoch != "0":
            return f"{self.epoch}:{self.version}"
        return self.version

    def purl(self, release: OsRelease | None) -> str:
        kind = self.PURL_TYPE[self.manager]
        namespace = release.id if release and release.id else self.NAMESPACE[self.manager]
        short = self.name
        if self.manager == "portage":
            # Gentoo names a package by its category, which is the purl's namespace.
            namespace, _, short = self.name.rpartition("/")
        qualifiers: dict[str, str] = {}
        if self.arch:
            qualifiers["arch"] = self.arch
        if self.manager == "rpm" and self.epoch and self.epoch != "0":
            qualifiers["epoch"] = self.epoch
        if release and release.version_id:
            qualifiers["distro"] = f"{release.id}-{release.version_id}"
        if self.source and self.source != self.name and self.manager != "rpm":
            qualifiers["upstream"] = self.source
        query = "&".join(
            f"{k}={urllib.parse.quote(v, safe='')}" for k, v in sorted(qualifiers.items())
        )
        name = urllib.parse.quote(short, safe="+")
        version = urllib.parse.quote(self.version, safe="+~:")
        return f"pkg:{kind}/{namespace}/{name}@{version}" + (f"?{query}" if query else "")


class PackageDatabases:
    """The dpkg, apk and RPM databases of an image, and the files they own."""

    @staticmethod
    def os_release(data: bytes) -> OsRelease:
        values: dict[str, str] = {}
        for line in data.decode("utf-8", "replace").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and key.isidentifier():
                values[key] = value.strip().strip("'\"")
        return OsRelease(
            id=values.get("ID", "").lower(),
            version_id=values.get("VERSION_ID", ""),
            version=values.get("VERSION", ""),
            pretty_name=values.get("PRETTY_NAME", ""),
        )

    @staticmethod
    def _stanzas(data: bytes) -> list[dict[str, str]]:
        stanzas: list[dict[str, str]] = []
        current: dict[str, str] = {}
        key = ""
        for line in data.decode("utf-8", "replace").splitlines():
            if not line.strip():
                if current:
                    stanzas.append(current)
                    current = {}
                continue
            if line[0] in " \t":
                if key:
                    current[key] += "\n" + line.strip()
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            current[key] = value.strip()
        if current:
            stanzas.append(current)
        return stanzas

    @staticmethod
    def dpkg(data: bytes) -> list[OsPackage]:
        """dpkg's `status` file, or one of distroless's `status.d` files: RFC 822 stanzas."""
        packages: list[OsPackage] = []
        for stanza in PackageDatabases._stanzas(data)[:MAX_PACKAGES]:
            status = stanza.get("Status")
            if status is not None and not status.endswith(" installed"):
                continue
            name, version = stanza.get("Package", ""), stanza.get("Version", "")
            if not name or not version:
                continue
            source, _, rest = stanza.get("Source", "").partition(" ")
            source_version = rest.strip().strip("()") if rest else ""
            requires = PackageDatabases.dpkg_relations(
                stanza.get("Pre-Depends", "")
            ) + PackageDatabases.dpkg_relations(stanza.get("Depends", ""))
            provides = tuple(
                group.split("|", 1)[0]
                for group in PackageDatabases.dpkg_relations(stanza.get("Provides", ""))
            )
            packages.append(
                OsPackage(
                    "dpkg",
                    name,
                    version,
                    stanza.get("Architecture", ""),
                    source or name,
                    source_version or version,
                    requires=requires,
                    provides=provides,
                )
            )
        return packages

    @staticmethod
    def dpkg_relations(field: str) -> tuple[str, ...]:
        """`libc6 (>= 2.34), debconf (>= 0.5) | debconf-2.0, perl:any` -> `libc6`, `debconf|debconf-2.0`,
        `perl`: names only, alternatives kept together, versions and architecture qualifiers dropped."""
        groups: list[str] = []
        for group in field.replace("\n", " ").split(",")[:MAX_RELATIONS]:
            names = []
            for alternative in group.split("|"):
                name = (
                    re.sub(r"\(.*?\)|\[.*?\]|<.*?>", "", alternative)
                    .strip()
                    .split(":", 1)[0]
                    .strip()
                )
                if name:
                    names.append(name)
            if names:
                groups.append("|".join(names))
        return tuple(groups)

    @staticmethod
    def apt_automatic(data: bytes) -> frozenset[str]:
        """apt's `extended_states`: the packages it installed automatically, to satisfy another
        one. Everything else apt installed was asked for. By name: apt files an `Architecture:
        all` package under the native architecture."""
        return frozenset(
            stanza["Package"]
            for stanza in PackageDatabases._stanzas(data)
            if stanza.get("Auto-Installed", "").strip() == "1" and stanza.get("Package")
        )

    @staticmethod
    def apk_world(data: bytes) -> frozenset[str]:
        """apk's `world`: what was asked for, one constraint per line (`curl`, `py3-pip>=24`,
        `busybox@edge`)."""
        return frozenset(
            name
            for token in data.decode("utf-8", "replace").split()
            if (name := re.split(r"[<>=~@]", token, maxsplit=1)[0]) and not name.startswith("!")
        )

    @staticmethod
    def apk(data: bytes) -> list[OsPackage]:
        """apk's `installed` database: one letter per field, a blank line between packages."""
        packages: list[OsPackage] = []
        for block in data.decode("utf-8", "replace").split("\n\n")[:MAX_PACKAGES]:
            fields: dict[str, str] = {}
            for line in block.splitlines():
                if len(line) > 2 and line[1] == ":":
                    fields.setdefault(line[0], line[2:])
            if fields.get("P") and fields.get("V"):
                packages.append(
                    OsPackage(
                        "apk",
                        fields["P"],
                        fields["V"],
                        fields.get("A", ""),
                        fields.get("o", fields["P"]),
                        # `D:so:libc.musl-x86_64.so.1 busybox>=1.36 !conflict`: what it needs; `p:`
                        # what it provides (`cmd:sh=1.36.1-r29`). A `!` is a conflict, not a need.
                        requires=tuple(
                            name
                            for token in fields.get("D", "").split()[:MAX_RELATIONS]
                            if not token.startswith("!")
                            and (name := re.split(r"[<>=~]", token, maxsplit=1)[0])
                        ),
                        provides=tuple(
                            name
                            for token in fields.get("p", "").split()[:MAX_RELATIONS]
                            if (name := re.split(r"[<>=~]", token, maxsplit=1)[0])
                        ),
                        triggered_by=tuple(
                            name
                            for token in fields.get("i", "").split()[:MAX_RELATIONS]
                            if (name := re.split(r"[<>=~]", token, maxsplit=1)[0])
                        ),
                    )
                )
        return packages

    @staticmethod
    def rpm_header(blob: bytes) -> dict[int, str]:
        """The tags needed from one RPM header blob (the rpmdb form: no lead, starts at the index)."""
        if len(blob) < 8 or len(blob) > MAX_HEADER_BYTES:
            raise ValueError("an RPM header is outside the reader's limits")
        count, size = struct.unpack_from(">II", blob, 0)
        store = 8 + 16 * count
        if count > 100_000 or store + size > len(blob):
            raise ValueError("an RPM header's index runs past its end")
        wanted = {RPM_NAME, RPM_VERSION, RPM_RELEASE, RPM_EPOCH, RPM_ARCH, RPM_SOURCERPM}
        found: dict[int, str] = {}
        for index in range(count):
            tag, kind, offset, items = struct.unpack_from(">iiii", blob, 8 + 16 * index)
            if tag not in wanted or offset < 0 or store + offset >= len(blob):
                continue
            start = store + offset
            if kind in (_RPM_STRING, _RPM_I18NSTRING):
                end = blob.find(b"\x00", start)
                found[tag] = blob[start : end if end >= 0 else len(blob)].decode("utf-8", "replace")
            elif kind == _RPM_INT32 and items >= 1 and start + 4 <= len(blob):
                found[tag] = str(struct.unpack_from(">i", blob, start)[0])
        return found

    @staticmethod
    def rpm_bdb_blobs(database: bytes) -> list[bytes]:
        """The header blobs in RPM's Berkeley DB `Packages` hash database (RHEL/CentOS 7-8, Amazon
        Linux 2). Read page by page; every chain is bounded by the page count and refuses a loop."""
        if len(database) < 512:
            raise ValueError("the Berkeley DB file is shorter than its metadata page")
        order = "<"
        magic = struct.unpack_from("<I", database, 12)[0]
        if magic != _BDB_HASH_MAGIC:
            if struct.unpack_from(">I", database, 12)[0] != _BDB_HASH_MAGIC:
                raise ValueError("not a Berkeley DB hash database")
            order = ">"
        page_size = struct.unpack_from(order + "I", database, 20)[0]
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            raise ValueError("the Berkeley DB page size is not a power of two in range")
        pages = len(database) // page_size
        last = min(struct.unpack_from(order + "I", database, 32)[0], pages - 1)

        def header(pgno: int) -> tuple[int, int, int, int]:
            base = pgno * page_size
            next_pgno, entries, hf_offset = struct.unpack_from(order + "IHH", database, base + 16)
            return next_pgno, entries, hf_offset, database[base + 25]

        blobs: list[bytes] = []
        for pgno in range(1, last + 1):
            _, entries, _, kind = header(pgno)
            if kind not in _BDB_HASH_PAGES:
                continue
            base = pgno * page_size
            for index in range(1, entries, 2):  # data items; each follows its key
                offset = struct.unpack_from(
                    order + "H", database, base + _BDB_PAGE_HEADER + 2 * index
                )[0]
                if offset >= page_size or database[base + offset] != _BDB_OFFPAGE:
                    continue
                chain, total = struct.unpack_from(order + "II", database, base + offset + 4)
                if total > MAX_HEADER_BYTES:
                    continue
                value = bytearray()
                seen: set[int] = set()
                while chain and chain < pages and chain not in seen and len(value) < total:
                    seen.add(chain)
                    next_pgno, _, used, chain_kind = header(chain)
                    if chain_kind != _BDB_OVERFLOW:
                        break
                    start = chain * page_size + _BDB_PAGE_HEADER
                    value += database[start : start + min(used, page_size - _BDB_PAGE_HEADER)]
                    chain = next_pgno
                if len(value) >= total:
                    blobs.append(bytes(value[:total]))
                if len(blobs) >= MAX_PACKAGES:
                    return blobs
        return blobs

    @staticmethod
    def rpm_ndb_blobs(database: bytes) -> list[bytes]:
        """The header blobs in RPM's NDB `Packages.db` (SUSE). A slot table of (package index, block
        offset, block count), each pointing at a `BlbS` blob in 16-byte blocks."""
        if database[:4] != _NDB_MAGIC or len(database) < 32:
            raise ValueError("not an NDB package database")
        slot_pages = struct.unpack_from("<I", database, 12)[0]
        if not 0 < slot_pages <= 4096:
            raise ValueError("the NDB slot table size is out of range")
        blobs: list[bytes] = []
        for offset in range(16, min(slot_pages * _NDB_PAGE, len(database)) - 15, 16):
            if database[offset : offset + 4] != _NDB_SLOT_MAGIC:
                continue
            index, block, count = struct.unpack_from("<III", database, offset + 4)
            if not index:
                continue
            start = block * _NDB_BLOCK
            if (
                database[start : start + 4] != _NDB_BLOB_MAGIC
                or count * _NDB_BLOCK > MAX_HEADER_BYTES
            ):
                continue
            blob_index, _checksum, length = struct.unpack_from("<III", database, start + 4)
            if blob_index != index or length > count * _NDB_BLOCK:
                continue
            blobs.append(database[start + 16 : start + 16 + length])
            if len(blobs) >= MAX_PACKAGES:
                break
        return blobs

    @staticmethod
    def rpm_blobs(blobs: list[bytes]) -> list[OsPackage]:
        packages: list[OsPackage] = []
        relations: list[tuple[list[str], list[str], list[str]]] = []
        for blob in blobs:
            with contextlib.suppress(ValueError, struct.error):
                package = PackageDatabases._rpm_package(PackageDatabases.rpm_header(blob))
                if package is not None:
                    arrays = PackageDatabases._rpm_string_arrays(
                        blob, (RPM_REQUIRENAME, RPM_PROVIDENAME)
                    )
                    indexes, basenames, dirnames = PackageDatabases._rpm_arrays(blob)
                    files = [
                        dirnames[i] + base
                        for i, base in zip(indexes, basenames, strict=False)
                        if 0 <= i < len(dirnames)
                    ]
                    packages.append(package)
                    relations.append(
                        (arrays.get(RPM_REQUIRENAME, []), arrays.get(RPM_PROVIDENAME, []), files)
                    )
        # A requirement on a path (`/bin/sh`, `/usr/bin/python3`) is met by the package owning that
        # file: each owner provides the paths some package requires.
        wanted_paths = {r for requires, _, _ in relations for r in requires if r.startswith("/")}
        out: list[OsPackage] = []
        for package, (requires, provides, files) in zip(packages, relations, strict=True):
            out.append(
                OsPackage(
                    package.manager,
                    package.name,
                    package.version,
                    package.arch,
                    package.source,
                    package.source_version,
                    package.epoch,
                    # `rpmlib(...)` is rpm's own feature list; a rich dependency (`(a or b)`) is
                    # read as its alternatives.
                    requires=tuple(
                        group
                        for r in requires[:MAX_RELATIONS]
                        if not r.startswith("rpmlib(")
                        for group in PackageDatabases.rpm_requirement(r)
                    ),
                    provides=tuple(provides[:MAX_RELATIONS])
                    + tuple(
                        f"/{f.lstrip('/')}" for f in files if f"/{f.lstrip('/')}" in wanted_paths
                    ),
                )
            )
        return out

    @staticmethod
    def rpm_requirement(requirement: str) -> tuple[str, ...]:
        """One requirement as the groups it needs met. A rich dependency: `(a or b)` is one group of
        alternatives, `(a and b)` / `(a with b)` two groups, `(a if b)` / `(a unless b)` the
        condition's subject alone. A nested rich dependency is not followed."""
        if not (requirement.startswith("(") and requirement.endswith(")")):
            return (requirement,)
        body = requirement[1:-1]
        if "(" in body:
            return ()
        body = re.split(r"\s+(?:if|unless)\s+", body, maxsplit=1)[0]
        names = [
            re.split(r"\s", part.strip(), maxsplit=1)[0]
            for part in re.split(r"\s+(?:and|with)\s+", body)
            if part.strip()
        ]
        if " or " in body:
            return (
                "|".join(
                    re.split(r"\s", part.strip(), maxsplit=1)[0]
                    for part in re.split(r"\s+or\s+", body)
                    if part.strip()
                ),
            )
        return tuple(names)

    @staticmethod
    def _rpm_string_arrays(blob: bytes, tags: tuple[int, ...]) -> dict[int, list[str]]:
        """The string-array tags asked for, from one RPM header blob."""
        count, size = struct.unpack_from(">II", blob, 0)
        store = 8 + 16 * count
        if count > 100_000 or store + size > len(blob):
            raise ValueError("an RPM header's index runs past its end")
        found: dict[int, list[str]] = {}
        for index in range(count):
            tag, kind, offset, items = struct.unpack_from(">iiii", blob, 8 + 16 * index)
            if tag not in tags or kind != _RPM_STRING_ARRAY or offset < 0 or items > MAX_RELATIONS:
                continue
            values: list[str] = []
            position = store + offset
            for _ in range(items):
                end = blob.find(b"\x00", position)
                if end < 0:
                    break
                values.append(blob[position:end].decode("utf-8", "replace"))
                position = end + 1
            found[tag] = values
        return found

    @staticmethod
    def _rpm_package(header: dict[int, str]) -> OsPackage | None:
        name, version = header.get(RPM_NAME, ""), header.get(RPM_VERSION, "")
        if not name or not version or name == "gpg-pubkey":
            return None
        release = header.get(RPM_RELEASE, "")
        source = header.get(RPM_SOURCERPM, "")
        source_name = source.rsplit("-", 2)[0] if source.count("-") >= 2 else ""
        return OsPackage(
            "rpm",
            name,
            f"{version}-{release}" if release else version,
            header.get(RPM_ARCH, ""),
            source_name,
            epoch=header.get(RPM_EPOCH, ""),
        )

    @staticmethod
    def rpm_sqlite_blobs(database: bytes, wal: bytes | None = None) -> list[bytes]:
        """The header blobs in RPM's SQLite database (RHEL 9, Fedora 33+, Rocky and Alma 9, Amazon
        Linux 2023)."""
        with tempfile.TemporaryDirectory(prefix="cordon-rpmdb-") as directory:
            path = Path(directory) / "rpmdb.sqlite"
            path.write_bytes(database)
            if wal:
                (Path(directory) / "rpmdb.sqlite-wal").write_bytes(wal)
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                rows = connection.execute(
                    "SELECT blob FROM Packages LIMIT ?", (MAX_PACKAGES,)
                ).fetchall()
            finally:
                connection.close()
        return [bytes(blob) for (blob,) in rows]

    @staticmethod
    def rpm_sqlite(database: bytes, wal: bytes | None = None) -> list[OsPackage]:
        return PackageDatabases.rpm_blobs(PackageDatabases.rpm_sqlite_blobs(database, wal))

    @staticmethod
    def _rpm_arrays(blob: bytes) -> tuple[list[int], list[str], list[str]]:
        """DIRINDEXES, BASENAMES and DIRNAMES: how RPM records the files a package owns."""
        count, size = struct.unpack_from(">II", blob, 0)
        store = 8 + 16 * count
        if count > 100_000 or store + size > len(blob):
            raise ValueError("an RPM header's index runs past its end")
        indexes: list[int] = []
        strings: dict[int, list[str]] = {}
        for index in range(count):
            tag, kind, offset, items = struct.unpack_from(">iiii", blob, 8 + 16 * index)
            if (
                tag not in (RPM_DIRINDEXES, RPM_BASENAMES, RPM_DIRNAMES)
                or offset < 0
                or items > MAX_FILES_PER_PACKAGE
            ):
                continue
            start = store + offset
            if tag == RPM_DIRINDEXES and kind == _RPM_INT32 and start + 4 * items <= len(blob):
                indexes = list(struct.unpack_from(f">{items}i", blob, start))
            elif kind == _RPM_STRING_ARRAY:
                values: list[str] = []
                position = start
                for _ in range(items):
                    end = blob.find(b"\x00", position)
                    if end < 0:
                        break
                    values.append(blob[position:end].decode("utf-8", "replace"))
                    position = end + 1
                strings[tag] = values
        return indexes, strings.get(RPM_BASENAMES, []), strings.get(RPM_DIRNAMES, [])

    @staticmethod
    def rpm_owned(blobs: list[bytes]) -> set[str]:
        """Every path the RPM database says an installed package owns, without the leading slash."""
        owned: set[str] = set()
        for blob in blobs:
            with contextlib.suppress(ValueError, struct.error):
                indexes, basenames, dirnames = PackageDatabases._rpm_arrays(blob)
                for index, base in zip(indexes, basenames, strict=False):
                    if 0 <= index < len(dirnames):
                        owned.add((dirnames[index] + base).lstrip("/"))
        return owned

    @staticmethod
    def dpkg_owned(lists: list[bytes]) -> set[str]:
        """Paths from dpkg's `info/*.list` files."""
        return {
            line.strip().lstrip("/")
            for data in lists
            for line in data.decode("utf-8", "replace").splitlines()
            if line.strip()
        }

    @staticmethod
    def dpkg_md5sums_owned(data: bytes) -> set[str]:
        """Paths from a `<package>.md5sums` file (distroless `status.d/`): `<md5>  <path>` lines."""
        owned: set[str] = set()
        for line in data.decode("utf-8", "replace").splitlines():
            _digest, _, path = line.strip().partition("  ")
            if path:
                owned.add(path.strip().lstrip("/"))
        return owned

    PACMAN_SECTION: ClassVar[re.Pattern[str]] = re.compile(r"^%([A-Z0-9]{1,32})%$")

    @staticmethod
    def _pacman_sections(data: bytes) -> dict[str, list[str]]:
        """`%NAME%` then its values, one per line, until a blank line."""
        sections: dict[str, list[str]] = {}
        current: list[str] | None = None
        for line in data.decode("utf-8", "replace").splitlines():
            heading = PackageDatabases.PACMAN_SECTION.match(line)
            if heading:
                current = sections.setdefault(heading.group(1), [])
            elif not line:
                current = None
            elif current is not None and len(current) < MAX_FILES_PER_PACKAGE:
                current.append(line)
        return sections

    @staticmethod
    def pacman(files: dict[str, bytes]) -> list[OsPackage]:
        """Arch's local database: each package's `desc`. `%REASON%` 1 is "installed as a
        dependency"; absent, it was asked for."""
        packages: list[OsPackage] = []
        for path in sorted(p for p in files if p.endswith("/desc"))[:MAX_PACKAGES]:
            fields = PackageDatabases._pacman_sections(files[path])
            name, version = (fields.get("NAME") or [""])[0], (fields.get("VERSION") or [""])[0]
            if not name or not version:
                continue
            packages.append(
                OsPackage(
                    "pacman",
                    name,
                    version,
                    (fields.get("ARCH") or [""])[0],
                    (fields.get("BASE") or [name])[0],
                    requires=tuple(
                        bare
                        for token in fields.get("DEPENDS", [])[:MAX_RELATIONS]
                        if (bare := re.split(r"[<>=]", token, maxsplit=1)[0])
                    ),
                    provides=tuple(
                        bare
                        for token in fields.get("PROVIDES", [])[:MAX_RELATIONS]
                        if (bare := re.split(r"[<>=]", token, maxsplit=1)[0])
                    ),
                    requested=(fields.get("REASON") or ["0"])[0] != "1",
                )
            )
        return packages

    @staticmethod
    def pacman_owned(files: dict[str, bytes]) -> set[str]:
        owned: set[str] = set()
        for path in (p for p in files if p.endswith("/files")):
            owned.update(
                f
                for f in PackageDatabases._pacman_sections(files[path]).get("FILES", [])
                if not f.endswith("/")
            )
        return owned

    PORTAGE_PACKAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<name>[A-Za-z0-9+_][\w+-]{0,200}?)-(?P<version>\d[\w.]{0,60}(?:_(?:alpha|beta|pre|rc|p)\d{0,12}){0,4}(?:-r\d{1,6})?)$"
    )
    PORTAGE_ATOM: ClassVar[re.Pattern[str]] = re.compile(
        r"^[<>=~!]{0,3}(?P<name>[A-Za-z0-9][\w+-]{0,100}/[A-Za-z0-9+_][\w+-]{0,200}?)(?:-\d[\w.*]{0,60}(?:_(?:alpha|beta|pre|rc|p)\d{0,12}){0,4}(?:-r\d{1,6})?)?(?::[^\s\[]{0,40})?(?:\[[^\]]{0,200}\])?$"
    )

    @staticmethod
    def portage(files: dict[str, bytes]) -> list[OsPackage]:
        """Gentoo's installed-package database: `<category>/<name>-<version>/`, the runtime
        dependencies in `RDEPEND` (atoms inside USE conditionals and `|| ( )` groups included:
        whichever was satisfied is installed, and the others match nothing)."""
        directories = sorted({p.rsplit("/", 1)[0] for p in files})
        packages: list[OsPackage] = []
        for directory in directories[:MAX_PACKAGES]:
            category, _, entry = directory.removeprefix("var/db/pkg/").partition("/")
            matched = PackageDatabases.PORTAGE_PACKAGE.match(entry)
            if not category or not matched:
                continue
            requires = tuple(
                atom.group("name")
                for token in files.get(f"{directory}/RDEPEND", b"")
                .decode("utf-8", "replace")
                .split()[:MAX_RELATIONS]
                if (atom := PackageDatabases.PORTAGE_ATOM.match(token))
            )
            packages.append(
                OsPackage(
                    "portage",
                    f"{category}/{matched.group('name')}",
                    matched.group("version"),
                    requires=requires,
                )
            )
        return packages

    @staticmethod
    def portage_owned(files: dict[str, bytes]) -> set[str]:
        """`CONTENTS`: `obj /path md5 mtime`, `sym /path -> target mtime`, `dir /path`."""
        owned: set[str] = set()
        for path in (p for p in files if p.endswith("/CONTENTS")):
            for line in files[path].decode("utf-8", "replace").splitlines()[:MAX_FILES_PER_PACKAGE]:
                kind, _, rest = line.partition(" ")
                if kind == "obj":
                    owned.add(rest.rsplit(" ", 2)[0].lstrip("/"))
                elif kind == "sym":
                    owned.add(rest.split(" -> ", 1)[0].lstrip("/"))
        return owned

    @staticmethod
    def apk_owned(data: bytes) -> set[str]:
        """Paths from apk's `installed` database: `F:` names a directory, `R:` a file in it."""
        owned: set[str] = set()
        directory = ""
        for line in data.decode("utf-8", "replace").splitlines():
            if line.startswith("F:"):
                directory = line[2:].strip("/")
            elif line.startswith("R:"):
                owned.add(f"{directory}/{line[2:]}" if directory else line[2:])
        return owned


_BDB_HASH_MAGIC: Final = 0x061561
_BDB_PAGE_HEADER: Final = 26
_BDB_HASH_PAGES: Final = (2, 13)
"""P_HASH_UNSORTED and P_HASH: the page types that hold key/data pairs."""
_BDB_OVERFLOW: Final = 7
_BDB_OFFPAGE: Final = 3
"""H_OFFPAGE: the data item lives on a chain of overflow pages, as every rpm header does."""


_NDB_MAGIC: Final = b"RpmP"
_NDB_SLOT_MAGIC: Final = b"Slot"
_NDB_BLOB_MAGIC: Final = b"BlbS"
_NDB_PAGE: Final = 4096
_NDB_BLOCK: Final = 16


RPM_DIRINDEXES, RPM_BASENAMES, RPM_DIRNAMES = 1116, 1117, 1118
_RPM_STRING_ARRAY: Final = 8
MAX_FILES_PER_PACKAGE: Final = 200_000


__all__ = ["OsPackage", "OsRelease", "PackageDatabases"]


class PackageGraph:
    """The installed packages as a graph: who requires whom, and which were asked for."""

    @staticmethod
    def edges(packages: list[OsPackage]) -> list[list[int]]:
        """For each package, the packages meeting its requirements: the first alternative installed
        satisfies a group, by name or by what a package provides."""
        by_name: dict[str, int] = {}
        for index, package in enumerate(packages):
            by_name.setdefault(package.name, index)
        for index, package in enumerate(packages):
            for provided in package.provides:
                by_name.setdefault(provided, index)
        out: list[list[int]] = []
        for index, package in enumerate(packages):
            children: list[int] = []
            for group in package.requires:
                for alternative in group.split("|"):
                    target = by_name.get(alternative)
                    if target is not None:
                        if target != index and target not in children:
                            children.append(target)
                        break
            out.append(children)
        for index, package in enumerate(packages):
            for trigger in package.triggered_by:
                parent = by_name.get(trigger)
                if parent is not None and parent != index and index not in out[parent]:
                    out[parent].append(index)
        return out

    @staticmethod
    def direct(packages: list[OsPackage], edges: list[list[int]]) -> list[bool]:
        """Asked for, where the image says (apt's states, apk's world). Where it does not, the
        packages nothing else requires -- and one of each cycle nothing outside it reaches."""
        if any(package.requested is not None for package in packages):
            return [package.requested is not False for package in packages]
        required = {child for children in edges for child in children}
        roots = [index not in required for index in range(len(packages))]
        reached: set[int] = set()
        frontier = [index for index, root in enumerate(roots) if root]
        while frontier:
            current = frontier.pop()
            if current in reached:
                continue
            reached.add(current)
            frontier.extend(edges[current])
        for index in range(len(packages)):
            if index not in reached:
                roots[index] = True
                frontier = [index]
                while frontier:
                    current = frontier.pop()
                    if current not in reached:
                        reached.add(current)
                        frontier.extend(edges[current])
        return roots
