"""What a compiled artefact says it was built from, read without running or disassembling it.

A static Go or Rust binary is the whole application in one file, often tens of megabytes -- past
the per-file content limit, so it used to be skipped and counted as "not examined". Its build
records which modules went into it, and that record is what advisory matching needs:

* Go writes `buildinfo` into every binary since 1.18: the toolchain version and each module path,
  version and checksum (`go version -m` prints it).
* Rust binaries built with `cargo auditable` carry a zlib-compressed JSON list of every crate in a
  `.dep-v0` ELF section.
* .NET applications ship `<app>.deps.json` beside the assembly, naming every NuGet package.
* A JAR keeps `META-INF/maven/<group>/<artifact>/pom.properties` for itself and, in a Spring Boot
  fat JAR, for every JAR under `BOOT-INF/lib/`.

And the printable strings of a binary (`strings`) are where an embedded credential, URL or command
lives, so a binary too large to content-scan as bytes is content-scanned as its strings instead.
"""

from __future__ import annotations

import io
import json
import posixpath
import re
import struct
import zipfile
import zlib
from dataclasses import replace
from typing import IO, Final

from cordon_scanner.images.langpkgs import LanguagePackage

GO_MAGIC: Final = b"\xff Go buildinf:"
MAX_NESTED_JARS: Final = 2000
#: One part of a binary's strings: what the scan reads as one file.
MAX_STRINGS_BYTES: Final = 48 << 20
#: All of one binary's strings, across its parts. A 200 MB Go server carries 60 to 90 MB of text.
MAX_STRINGS_TOTAL: Final = 256 << 20
_PRINTABLE: Final = re.compile(rb"[\x20-\x7e\t]{6,}")


class BinaryFacts:
    """What an executable says of itself: the machine it is built for, and whether it carries a
    signature. A signature's presence is reported, never its validity: verifying Authenticode or a
    Mach-O code signature needs the platform's trust store, which this does not have."""

    ELF_MACHINES: Final = {
        0x03: "386",
        0x08: "mips",
        0x14: "ppc",
        0x15: "ppc64",
        0x16: "s390x",
        0x28: "arm",
        0x3E: "amd64",
        0xB7: "arm64",
        0xF3: "riscv64",
        0x102: "loong64",
    }
    PE_MACHINES: Final = {
        0x14C: "386",
        0x8664: "amd64",
        0x1C0: "arm",
        0x1C4: "arm",
        0xAA64: "arm64",
    }
    MACHO_CPUS: Final = {
        7: "386",
        0x01000007: "amd64",
        12: "arm",
        0x0100000C: "arm64",
        18: "ppc",
        0x01000012: "ppc64",
    }

    @staticmethod
    def describe(data: bytes) -> tuple[str, ...]:
        if data[:4] == b"\x7fELF":
            return BinaryFacts._elf(data)
        if data[:2] == b"MZ":
            return BinaryFacts._pe(data)
        if data[:4] in (
            b"\xcf\xfa\xed\xfe",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xfe\xed\xfa\xce",
        ):
            return BinaryFacts._macho(data)
        if (
            data[:4] == b"\xca\xfe\xba\xbe"
            and len(data) >= 8
            and 0 < struct.unpack_from(">I", data, 4)[0] < 32
        ):
            # A universal binary: one slice per architecture (a Java class file shares the magic,
            # and its version number is never this small).
            count = struct.unpack_from(">I", data, 4)[0]
            cpus = [
                BinaryFacts.MACHO_CPUS.get(
                    struct.unpack_from(">i", data, 8 + 20 * i)[0] & 0xFFFFFFFF, "unknown"
                )
                for i in range(count)
                if 8 + 20 * i + 4 <= len(data)
            ]
            return (f"architecture {'+'.join(sorted(set(cpus)))} (universal)",)
        return ()

    @staticmethod
    def _elf(data: bytes) -> tuple[str, ...]:
        if len(data) < 20:
            return ()
        order = "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(order + "H", data, 18)[0]
        return (
            f"architecture {BinaryFacts.ELF_MACHINES.get(machine, f'machine {machine:#x}')}",
            "unsigned: ELF carries no signature of its own",
        )

    @staticmethod
    def _pe(data: bytes) -> tuple[str, ...]:
        if len(data) < 0x40:
            return ()
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if offset + 24 > len(data) or data[offset : offset + 4] != b"PE\0\0":
            return ()
        machine = struct.unpack_from("<H", data, offset + 4)[0]
        optional = offset + 24
        magic = struct.unpack_from("<H", data, optional)[0] if optional + 2 <= len(data) else 0
        # The certificate table is data directory 4: where Authenticode signatures live.
        directories = optional + (112 if magic == 0x20B else 96)
        certificate = directories + 8 * 4
        signed = (
            certificate + 8 <= len(data) and struct.unpack_from("<II", data, certificate)[1] > 0
        )
        architecture = BinaryFacts.PE_MACHINES.get(machine, f"machine {machine:#x}")
        return (
            f"architecture {architecture}",
            "signed (an Authenticode signature is present, not verified)" if signed else "unsigned",
        )

    @staticmethod
    def _macho(data: bytes) -> tuple[str, ...]:
        order = "<" if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
        wide = data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        if len(data) < 28:
            return ()
        cpu, _sub, _kind, commands, _size = struct.unpack_from(order + "iiiII", data, 4)
        position = 32 if wide else 28
        signed = False
        for _ in range(min(commands, 4096)):
            if position + 8 > len(data):
                break
            command, length = struct.unpack_from(order + "II", data, position)
            if command == 0x1D:  # LC_CODE_SIGNATURE
                signed = True
                break
            if length < 8:
                break
            position += length
        architecture = BinaryFacts.MACHO_CPUS.get(cpu & 0xFFFFFFFF, f"cpu {cpu:#x}")
        return (
            f"architecture {architecture}",
            "signed (a code signature is present, not verified)" if signed else "unsigned",
        )

    @staticmethod
    def jar_signature(names: list[str]) -> str:
        """A jar is signed when META-INF holds a signature file and its signature block."""
        meta = {n.upper() for n in names if n.upper().startswith("META-INF/") and n.count("/") == 1}
        stems = {n.rsplit(".", 1)[0] for n in meta if n.endswith(".SF")}
        blocks = {n.rsplit(".", 1)[0] for n in meta if n.endswith((".RSA", ".DSA", ".EC"))}
        return (
            "signed jar (a signature block is present, not verified)"
            if stems & blocks
            else "unsigned jar"
        )


class BinaryMetadata:
    """Packages a compiled artefact records about itself."""

    @staticmethod
    def extract(path: str, data: bytes) -> list[LanguagePackage]:
        name = posixpath.basename(path).lower()
        if name.endswith(".deps.json"):
            return BinaryMetadata.dotnet(path, data)
        if name.endswith((".jar", ".war", ".ear")):
            return BinaryMetadata.java(path, data)
        found: list[LanguagePackage] = []
        if GO_MAGIC in data:
            found += BinaryMetadata.go(path, data)
        if data[:4] == b"\x7fELF":
            found += BinaryMetadata.rust(path, data)
            # BusyBox copied in on its own (the busybox image has no package database): its banner
            # is the only record of the release. Matched in any ELF, not by name -- the image
            # stores the bytes under whichever applet's hard link the tar wrote first (`bin/[`).
            if len(data) <= MAX_BUSYBOX_BYTES:
                banner = BUSYBOX.search(data)
                if banner:
                    found.append(
                        LanguagePackage("runtime", "busybox", banner.group(1).decode(), path)
                    )
        facts = BinaryFacts.describe(data)
        if not found or not facts:
            return found
        # The binary's own digest beside what it says of itself: the exact artefact inventoried.
        import hashlib

        facts = (*facts, f"binary sha256:{hashlib.sha256(data).hexdigest()}")
        return [replace(package, platform=facts) for package in found]

    # -- Go ------------------------------------------------------------------------------------

    @staticmethod
    def _uvarint(data: bytes, offset: int) -> tuple[int, int]:
        value, shift = 0, 0
        while offset < len(data) and shift < 64:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, offset
            shift += 7
        raise ValueError("truncated varint")

    @staticmethod
    def go(path: str, data: bytes) -> list[LanguagePackage]:
        """Go 1.18+ inline `buildinfo`: version and module list. Older binaries store pointers into
        the data segment instead, and are left alone rather than guessed at."""
        start = data.find(GO_MAGIC)
        if start < 0 or start + 32 > len(data):
            return []
        flags = data[start + 15]
        if not flags & 0x2:
            return []
        try:
            length, offset = BinaryMetadata._uvarint(data, start + 32)
            version = data[offset : offset + length].decode("utf-8", "replace")
            offset += length
            length, offset = BinaryMetadata._uvarint(data, offset)
            modinfo = data[offset : offset + length]
        except ValueError:
            return []
        # The module text is framed by 16-byte sentinels.
        if len(modinfo) >= 33 and modinfo[-17:-16] == b"\n":
            modinfo = modinfo[16:-16]
        packages: list[LanguagePackage] = []
        if version.startswith("go"):
            packages.append(LanguagePackage("gomod", "stdlib", version[2:].split()[0], path))
        previous: LanguagePackage | None = None
        for line in modinfo.decode("utf-8", "replace").splitlines():
            fields = line.split("\t")
            if (
                fields[0] in ("dep", "mod")
                and len(fields) >= 3
                and fields[2] not in ("", "(devel)")
            ):
                previous = LanguagePackage(
                    "gomod",
                    fields[1],
                    fields[2].lstrip("v"),
                    path,
                    fields[3] if len(fields) > 3 and fields[3].startswith("h1:") else None,
                )
                # `mod` is the binary's own module: built from a tagged release (`go install
                # example.com/tool@v1.2.3`), it is a package in the image like any it depends on.
                # Built from a checkout it is `(devel)`, which names no release, and is left out.
                packages.append(previous)
            elif fields[0] == "=>" and previous is not None:
                # A replacement: the module actually built in is this one, not the one required.
                if previous in packages:
                    packages.remove(previous)
                # A local directory (`=> ./pkg/util (devel)`) is the project's own code, with no
                # release to name: nothing is listed for it.
                if len(fields) < 3 or not fields[2] or fields[2] == "(devel)":
                    continue
                packages.append(
                    LanguagePackage(
                        "gomod",
                        fields[1],
                        fields[2].lstrip("v"),
                        path,
                        fields[3] if len(fields) > 3 and fields[3].startswith("h1:") else None,
                    )
                )
        return packages

    # -- Rust ----------------------------------------------------------------------------------

    @staticmethod
    def _elf_section(data: bytes, wanted: bytes) -> bytes | None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None
        wide, little = data[4] == 2, data[5] == 1
        order = "<" if little else ">"
        try:
            if wide:
                shoff = struct.unpack_from(order + "Q", data, 0x28)[0]
                shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
            else:
                shoff = struct.unpack_from(order + "I", data, 0x20)[0]
                shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)
            if not shoff or shnum == 0 or shnum > 4096 or shstrndx >= shnum:
                return None

            def header(index: int) -> tuple[int, int, int]:
                base = shoff + index * shentsize
                if wide:
                    name, _, _, _, offset, size = struct.unpack_from(order + "IIQQQQ", data, base)
                else:
                    name, _, _, _, offset, size = struct.unpack_from(order + "IIIIII", data, base)
                return name, offset, size

            _, names_offset, names_size = header(shstrndx)
            names = data[names_offset : names_offset + names_size]
            for index in range(shnum):
                name, offset, size = header(index)
                end = names.find(b"\x00", name)
                if names[name:end] == wanted:
                    return data[offset : offset + size]
        except struct.error:
            return None
        return None

    @staticmethod
    def rust(path: str, data: bytes) -> list[LanguagePackage]:
        section = BinaryMetadata._elf_section(data, b".dep-v0")
        if not section:
            return []
        try:
            document = json.loads(zlib.decompressobj().decompress(section, 64 << 20))
        except (zlib.error, ValueError):
            return []
        return [
            LanguagePackage("cargo", str(p["name"]), str(p["version"]), path)
            for p in document.get("packages") or ()
            if isinstance(p, dict)
            and p.get("name")
            and p.get("version")
            and str(p.get("source") or "crates.io") == "crates.io"
            and p.get("kind", "runtime") == "runtime"
        ]

    # -- .NET ----------------------------------------------------------------------------------

    @staticmethod
    def dotnet(path: str, data: bytes) -> list[LanguagePackage]:
        try:
            document = json.loads(data)
        except ValueError:
            return []
        libraries = document.get("libraries") if isinstance(document, dict) else None
        if not isinstance(libraries, dict):
            return []
        out: list[LanguagePackage] = []
        for key, meta in libraries.items():
            name, _, version = str(key).partition("/")
            if isinstance(meta, dict) and meta.get("type") == "package" and name and version:
                out.append(LanguagePackage("nuget", name, version, path))
        return out

    # -- Java ----------------------------------------------------------------------------------

    @staticmethod
    def _pom_properties(text: str) -> tuple[str, str, str] | None:
        values = dict(
            line.split("=", 1)
            for line in text.splitlines()
            if "=" in line and not line.startswith("#")
        )
        group, artifact, version = (
            values.get("groupId", "").strip(),
            values.get("artifactId", "").strip(),
            values.get("version", "").strip(),
        )
        return (group, artifact, version) if group and artifact and version else None

    @staticmethod
    def _jar_by_name(path: str, archive_bytes: bytes) -> list[LanguagePackage]:
        """A jar with no `pom.properties` (Gradle's own `lib/`, the JDK's `jrt-fs.jar`): named by its
        file, versioned by its file name or its manifest. The group is unknown, so the artifact
        stands for it, as other scanners write it; the coordinate is inventory, not a Maven lookup."""
        base = posixpath.basename(path)
        matched = JAR_NAME.match(base)
        manifest: dict[str, str] = {}
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                info = archive.getinfo("META-INF/MANIFEST.MF")
                if info.file_size <= 1 << 20:
                    for line in archive.read(info).decode("utf-8", "replace").splitlines():
                        key, sep, value = line.partition(":")
                        if sep and not line.startswith(" "):
                            manifest.setdefault(key.strip(), value.strip())
        except (KeyError, zipfile.BadZipFile, OSError):
            pass
        artifact = matched.group("artifact") if matched else base.removesuffix(".jar")
        version = (
            (matched.group("version") if matched else "")
            or manifest.get("Implementation-Version", "")
            or manifest.get("Bundle-Version", "")
        )
        if not artifact or not version or not artifact[0].isalpha():
            return []
        # The group where the manifest states one (a reverse-domain name), else the artifact.
        group = next(
            (
                value.split(";", 1)[0].strip()
                for key in (
                    "Group-Id",
                    "Implementation-Vendor-Id",
                    "Bundle-SymbolicName",
                    "Automatic-Module-Name",
                )
                if "." in (value := manifest.get(key, ""))
                and JAR_GROUP.match(value.split(";", 1)[0].strip())
            ),
            artifact,
        )
        return [LanguagePackage("maven", f"{group}:{artifact}", version, path, named_by_file=True)]

    @staticmethod
    def java(path: str, data: bytes, depth: int = 0) -> list[LanguagePackage]:
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError):
            return []
        out: list[LanguagePackage] = []
        nested = 0
        with archive:
            signature = BinaryFacts.jar_signature(archive.namelist())
            for info in archive.infolist():
                name = info.filename
                if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                    if info.file_size > 1 << 20:
                        continue
                    found = BinaryMetadata._pom_properties(
                        archive.read(info).decode("utf-8", "replace")
                    )
                    if found:
                        out.append(
                            LanguagePackage(
                                "maven",
                                f"{found[0]}:{found[1]}",
                                found[2],
                                path,
                                platform=(signature,),
                            )
                        )
                elif (
                    depth == 0
                    and name.endswith(".jar")
                    and nested < MAX_NESTED_JARS
                    and info.file_size <= 64 << 20
                ):
                    nested += 1
                    out += BinaryMetadata.java(f"{path}!{name}", archive.read(info), depth + 1)
        if depth == 0 and not any(p.path == path for p in out):
            out += BinaryMetadata._jar_by_name(path, archive_bytes=data)
        own = [p for p in out if p.path == path]
        if len(own) == 1:
            # A jar naming exactly one artifact is that artifact: its SHA-1 is the checksum Maven
            # Central publishes beside every release, older ones included.
            import hashlib

            out[out.index(own[0])] = replace(
                own[0], integrity=f"sha1:{hashlib.sha1(data, usedforsecurity=False).hexdigest()}"
            )
        return out


PRINTABLE_RUN: Final = re.compile(rb"[\x20-\x7e\t]+")
JAR_GROUP: Final = re.compile(r"^[a-z][a-z0-9_-]{0,60}(?:\.[A-Za-z0-9_-]{1,60}){1,12}$")
JAR_NAME: Final = re.compile(
    r"^(?P<artifact>[A-Za-z][\w.-]{0,200}?)-(?P<version>\d[\w.+-]{0,80})\.jar$"
)
BUSYBOX: Final = re.compile(rb"BusyBox v(\d+\.\d+(?:\.\d+)?) \(")
MAX_BUSYBOX_BYTES: Final = 8 << 20
NODE_RELEASE: Final = re.compile(
    rb"/download/release/v(\d{1,4}\.\d{1,4}\.\d{1,4})/node-v\d{1,4}\.\d{1,4}\.\d{1,4}"
)


class BinaryClassifiers:
    """A runtime's version from the strings its binary carries, for a binary too large to hold:
    distroless's `nodejs/bin/node` has no headers beside it, only itself."""

    @staticmethod
    def from_strings(path: str, parts: list[bytes]) -> list[LanguagePackage]:
        if posixpath.basename(path) == "node":
            for part in parts:
                found = NODE_RELEASE.search(part)
                if found:
                    return [LanguagePackage("runtime", "node", found.group(1).decode(), path)]
        return []


class StreamedBinary:
    """A file too large to hold, read once in chunks: Go `buildinfo` and printable strings.

    `buildinfo` sits in one place and is a few kilobytes to a few hundred, so the window after its
    marker is kept; strings carry their unfinished run across each boundary. A Rust `.dep-v0`
    section is found through the ELF section table at the end of the file, which a stream does not
    reach first, so only files small enough to hold are read for it.
    """

    CHUNK: Final = 16 << 20
    WINDOW: Final = 2 << 20

    @staticmethod
    def read(
        path: str,
        handle: IO[bytes],
        size: int,
        total: int = MAX_STRINGS_TOTAL,
        part: int = MAX_STRINGS_BYTES,
    ) -> tuple[list[LanguagePackage], list[bytes], bool]:
        strings = StringParts(total, part)
        carry = b""
        tail = b""
        window: bytes | None = None
        head = b""
        import hashlib

        digest = hashlib.sha256()
        remaining = size
        while remaining > 0:
            chunk = handle.read(min(StreamedBinary.CHUNK, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            digest.update(chunk)
            if not head:
                # The headers that say the machine and hold the signature's place come first.
                head = chunk[: 1 << 16]
            if window is None:
                joined = tail + chunk
                at = joined.find(GO_MAGIC)
                if at >= 0:
                    window = joined[at:]
                tail = joined[-len(GO_MAGIC) :]
            elif len(window) < StreamedBinary.WINDOW:
                window += chunk[: StreamedBinary.WINDOW - len(window)]
            text = carry + chunk
            end = len(text)
            # The printable run the chunk ends in, carried into the next so a string split across
            # two chunks is read whole. Matched from the end of the reversed chunk: anchored only
            # at the end, the search retried from every start inside every printable run, which
            # is quadratic -- 597 of 600 seconds on one Grafana binary.
            trailing = PRINTABLE_RUN.match(text[::-1])
            if trailing and remaining > 0:
                end = len(text) - trailing.end()
                carry = text[end:][-4096:]
            else:
                carry = b""
            strings.add(text[:end])
        packages = BinaryMetadata.go(path, window) if window else []
        facts = BinaryFacts.describe(head)
        if facts and packages:
            # The digest of every byte read; a binary cut short by a read limit is not this one.
            whole = remaining == 0
            facts = (
                *facts,
                f"binary sha256:{digest.hexdigest()}"
                if whole
                else "binary digest unknown: it was not read to its end",
            )
            packages = [replace(package, platform=facts) for package in packages]
        return packages, strings.finish(), strings.complete


class StringParts:
    """A binary's printable strings, in parts no larger than one scanned file, up to a total.

    One buffer capped at a single file's size cut a large server binary's text short; parts let
    every string be read while each part stays the size the content rules are built for. A run is
    never split across two parts unless it is itself longer than a part.
    """

    def __init__(self, total: int = MAX_STRINGS_TOTAL, part: int = MAX_STRINGS_BYTES) -> None:
        self.total = total
        self.part = part
        self.parts: list[bytes] = []
        self.complete = True
        self._current = io.BytesIO()
        self._written = 0

    def add(self, data: bytes) -> None:
        if not self.complete:
            return
        for match in _PRINTABLE.finditer(data):
            run = match.group(0)
            for start in range(0, len(run), self.part - 1):
                piece = run[start : start + self.part - 1]
                if self._written + len(piece) + 1 > self.total:
                    self.complete = False
                    return
                if self._current.tell() + len(piece) + 1 > self.part:
                    self.parts.append(self._current.getvalue())
                    self._current = io.BytesIO()
                self._current.write(piece)
                self._current.write(b"\n")
                self._written += len(piece) + 1

    def finish(self) -> list[bytes]:
        if self._current.tell():
            self.parts.append(self._current.getvalue())
            self._current = io.BytesIO()
        return self.parts


class BinaryStrings:
    """The printable runs of a binary, as `strings` gives them: what text rules can read."""

    @staticmethod
    def is_binary(data: bytes) -> bool:
        return (
            data[:4] in (b"\x7fELF", b"MZ\x90\x00")
            or data[:4]
            in (
                b"\xcf\xfa\xed\xfe",
                b"\xce\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe",
            )
            or b"\x00" in data[:8192]
        )

    @staticmethod
    def extract(data: bytes, limit: int = MAX_STRINGS_BYTES) -> tuple[bytes, bool]:
        """The strings, newline-separated, and whether all of them fit under `limit`."""
        out = io.BytesIO()
        for match in _PRINTABLE.finditer(data):
            run = match.group(0)
            if out.tell() + len(run) + 1 > limit:
                return out.getvalue(), False
            out.write(run)
            out.write(b"\n")
        return out.getvalue(), True


__all__ = ["BinaryMetadata", "BinaryStrings", "StreamedBinary", "StringParts"]
