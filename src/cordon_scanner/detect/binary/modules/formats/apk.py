"""An Android package read for what the `androguard` module answers: the manifest's package, label,
components, permissions and SDK levels, the signing certificate, and the URLs the code names.

An APK is a zip. Its `AndroidManifest.xml` is binary XML (`formats.axml`); an `@string` label is read
through `resources.arsc`. A component's name is given in full: one starting with "." or holding no dot
is put after the package's name, as androguard and the platform read it. The main activity is the first
activity or alias, in manifest order and not disabled, whose intent filter has the MAIN action and the
LAUNCHER category. The certificate is the signer's: the v1 signature's PKCS#7 (the first
`META-INF/*.RSA`, `*.DSA` or `*.EC` in the archive's order, read by `modules.signature`), else the first
signer's first certificate in the APK Signing Block (v2, then v3). Its `sha1` is the hex SHA-1 of the
certificate's DER; its subject and issuer are each attribute as `label=value` in the certificate's
order with ", " between, as androguard prints one. URLs are the `http://`, `https://` and `ftp://` runs
in the string tables of `classes.dex`, `classes2.dex` and on.

Android ignores a zip entry's encryption flag and so does this reader (malware sets it to break tools).
Every member is read up to a bound, a dex string table to its declared size within the file.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.der import BadDer, Tlv
from cordon_scanner.detect.binary.modules.formats.axml import (
    BinaryXml,
    Element,
    Reference,
    ResourceTable,
)
from cordon_scanner.detect.binary.modules.formats.dex_x import DexX
from cordon_scanner.detect.binary.modules.oids import ObjectIds
from cordon_scanner.detect.binary.modules.signature import Pkcs7
from cordon_scanner.detect.binary.modules.x509 import X500, Certificate


@dataclass
class ApkFacts:
    """What the module reads, from the package itself or from a report about it."""

    package_name: bytes | None = None
    app_name: bytes | None = None
    main_activity: bytes | None = None
    activities: list[bytes] = field(default_factory=list)
    services: list[bytes] = field(default_factory=list)
    receivers: list[bytes] = field(default_factory=list)
    permissions: list[bytes] = field(default_factory=list)
    new_permissions: list[bytes] = field(default_factory=list)
    urls: list[bytes] = field(default_factory=list)
    min_sdk: int = 0
    max_sdk: int = 0
    target_sdk: int = 0
    sha1: bytes | None = None
    subject: bytes | None = None
    issuer: bytes | None = None


class Apk:
    """The reader: `facts(file)` for an APK, None for anything else."""

    NAME, LABEL, ENABLED = 0x01010003, 0x01010001, 0x0101000E
    MIN_SDK, TARGET_SDK, MAX_SDK = 0x0101020C, 0x01010270, 0x01010271
    MAX_MEMBER: ClassVar[int] = 64 << 20
    MAX_DEX: ClassVar[int] = 32
    URL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?:https?|ftp)://[^\s\"'<>\x00]+", re.IGNORECASE
    )
    SIGNERS: ClassVar[tuple[int, ...]] = (0x7109871A, 0xF05368C0)
    """The signing block's v2 and v3 scheme IDs, in the order they are looked at."""

    @staticmethod
    def facts(file: bytes) -> ApkFacts | None:
        if file[:4] != b"PK\x03\x04":
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(file)) as archive:
                infos = archive.infolist()
                for info in infos:
                    info.flag_bits &= ~0x1
                members = {i.filename: i for i in infos}
                manifest = Apk._member(archive, members.get("AndroidManifest.xml"))
                if manifest is None:
                    return None
                root = BinaryXml.root(manifest)
                if root is None or root.name != "manifest":
                    return None
                arsc = Apk._member(archive, members.get("resources.arsc"))
                out = ApkFacts()
                Apk._manifest(out, root, ResourceTable(arsc) if arsc else None)
                Apk._certificate(out, archive, infos, file)
                Apk._urls(out, archive, members)
                return out
        except (
            zipfile.BadZipFile,
            OSError,
            EOFError,
            ValueError,
            RuntimeError,
            NotImplementedError,
        ):
            return None

    @staticmethod
    def _member(archive: zipfile.ZipFile, info: zipfile.ZipInfo | None) -> bytes | None:
        if info is None:
            return None
        try:
            with archive.open(info) as handle:
                return handle.read(Apk.MAX_MEMBER)
        except (
            zipfile.BadZipFile,
            OSError,
            EOFError,
            ValueError,
            RuntimeError,
            NotImplementedError,
        ):
            return None

    @staticmethod
    def _text(value: Any, table: ResourceTable | None) -> bytes | None:
        if isinstance(value, Reference):
            value = table.string(value.id) if table is not None else None
        return value.encode("utf-8", "surrogatepass") if isinstance(value, str) else None

    @staticmethod
    def _sdk(value: Any) -> int:
        """A level as the report's reader takes it: a number, or the leading digits of a text."""
        if isinstance(value, int):
            return value if value < 1 << 31 else value - (1 << 32)
        if isinstance(value, str):
            return Apk.atoi(value.encode())
        return 0

    @staticmethod
    def atoi(text: bytes) -> int:
        """C's atoi: leading space, a sign, then digits; 0 where there are none."""
        m = re.match(rb"[ \t\n\v\f\r]*([+-]?\d+)", text)
        if m is None:
            return 0
        value = int(m.group(1))
        return (
            value if -(1 << 31) <= value < 1 << 31 else (value + (1 << 31)) % (1 << 32) - (1 << 31)
        )

    @staticmethod
    def _manifest(out: ApkFacts, root: Element, table: ResourceTable | None) -> None:
        package = root.by_name.get("package")
        out.package_name = (
            package.encode("utf-8", "surrogatepass") if isinstance(package, str) else None
        )
        prefix = package if isinstance(package, str) else ""

        def full(element: Element) -> bytes | None:
            name = element.attr(Apk.NAME, "name")
            if not isinstance(name, str) or not name:
                return None
            if name[0] == "." or "." not in name:
                name = prefix + ("" if name[0] == "." else ".") + name
            return name.encode("utf-8", "surrogatepass")

        for tag, into in (("uses-permission", out.permissions), ("uses-permission-sdk-23", out.permissions),
                          ("permission", out.new_permissions)):  # fmt: skip
            for e in root.all(tag):
                name = e.attr(Apk.NAME, "name")
                if isinstance(name, str):
                    into.append(name.encode("utf-8", "surrogatepass"))
        for sdk in root.all("uses-sdk")[:1]:
            out.min_sdk = Apk._sdk(sdk.attr(Apk.MIN_SDK, "minSdkVersion"))
            out.target_sdk = Apk._sdk(sdk.attr(Apk.TARGET_SDK, "targetSdkVersion"))
            out.max_sdk = Apk._sdk(sdk.attr(Apk.MAX_SDK, "maxSdkVersion"))
        for app in root.all("application")[:1]:
            out.app_name = Apk._text(app.attr(Apk.LABEL, "label"), table)
            for tag, into in (("activity", out.activities), ("activity-alias", out.activities),
                              ("service", out.services), ("receiver", out.receivers)):  # fmt: skip
                into.extend(n for n in map(full, app.all(tag)) if n is not None)
            for e in [c for c in app.children if c.name in ("activity", "activity-alias")]:
                if out.main_activity is None and Apk._launcher(e):
                    out.main_activity = full(e)

    @staticmethod
    def _launcher(e: Element) -> bool:
        if e.attr(Apk.ENABLED, "enabled") in (0, "false"):
            return False
        for f in e.all("intent-filter"):
            actions = {a.attr(Apk.NAME, "name") for a in f.all("action")}
            categories = {c.attr(Apk.NAME, "name") for c in f.all("category")}
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                return True
        return False

    @staticmethod
    def _certificate(
        out: ApkFacts, archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], file: bytes
    ) -> None:
        cert: Certificate | None = None
        for info in infos:
            name = info.filename.upper()
            if name.startswith("META-INF/") and name.rsplit(".", 1)[-1] in ("RSA", "DSA", "EC"):
                blob = Apk._member(archive, info)
                cert = Apk._pkcs7_signer(blob) if blob else None
                break
        if cert is None:
            der = Apk._signing_block_certificate(file)
            if der is not None:
                try:
                    cert = Certificate.parse(Apk._tlv(der))
                except (BadDer, ValueError, IndexError):
                    cert = None
        if cert is None:
            return
        out.sha1 = hashlib.sha1(cert.raw).hexdigest().encode()  # noqa: S324 - the rule surface names SHA-1
        out.subject, out.issuer = Apk.name(cert.subject), Apk.name(cert.issuer)

    @staticmethod
    def _tlv(der: bytes) -> Tlv:
        return Tlv.decode(der)

    @staticmethod
    def _pkcs7_signer(blob: bytes) -> Certificate | None:
        try:
            _, signed = Pkcs7.parse(blob)
        except (ValueError, IndexError):
            return None
        if signed is None or not signed.certs:
            return None
        located = signed.signers[0].locate(signed.certs) if signed.signers else None
        return located or signed.certs[0]

    @staticmethod
    def name(x500: X500) -> bytes:
        parts = []
        for rdn in x500.rdns:
            for oid, _tag, data in rdn:
                names = ObjectIds.NAMES.get(oid)
                label = (names[0] or names[1] or oid) if names else oid
                parts.append(f"{label}={data.decode('utf-8', 'replace')}")
        return ", ".join(parts).encode("utf-8")

    @staticmethod
    def _signing_block_certificate(file: bytes) -> bytes | None:
        """The first signer's first certificate in the APK Signing Block, v2 before v3."""
        eocd = file.rfind(b"PK\x05\x06", max(0, len(file) - 65557))
        if eocd < 0 or eocd + 20 > len(file):
            return None
        cd = int.from_bytes(file[eocd + 16 : eocd + 20], "little")
        if cd < 32 or cd > len(file) or file[cd - 16 : cd] != b"APK Sig Block 42":
            return None
        size = int.from_bytes(file[cd - 24 : cd - 16], "little")
        start = cd - size - 8
        if start < 0 or size < 24:
            return None
        pairs: dict[int, bytes] = {}
        at, end = start + 8, cd - 24
        while at + 12 <= end:
            length = int.from_bytes(file[at : at + 8], "little")
            if length < 4 or at + 8 + length > end:
                break
            pairs.setdefault(
                int.from_bytes(file[at + 8 : at + 12], "little"), file[at + 12 : at + 8 + length]
            )
            at += 8 + length
        for scheme in Apk.SIGNERS:
            value = pairs.get(scheme)
            signer = Apk._prefixed(value, 0) if value else None
            signer = (
                Apk._prefixed(signer, 0) if signer else None
            )  # the first signer of the sequence
            signed = Apk._prefixed(signer, 0) if signer else None
            if signed is None:
                continue
            digests = Apk._prefixed(signed, 0)
            certs = Apk._prefixed(signed, 4 + len(digests)) if digests is not None else None
            first = Apk._prefixed(certs, 0) if certs else None
            if first:
                return first
        return None

    @staticmethod
    def _prefixed(data: bytes | None, at: int) -> bytes | None:
        """The length-prefixed (32-bit) value at `at`, or None where it does not fit."""
        if data is None or at + 4 > len(data):
            return None
        length = int.from_bytes(data[at : at + 4], "little")
        return data[at + 4 : at + 4 + length] if at + 4 + length <= len(data) else None

    @staticmethod
    def _urls(out: ApkFacts, archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> None:
        seen: set[bytes] = set()
        names = ["classes.dex", *(f"classes{i}.dex" for i in range(2, Apk.MAX_DEX + 1))]
        for name in names:
            data = Apk._member(archive, members.get(name))
            if data is None:
                break
            for text in Apk.dex_strings(data):
                for m in Apk.URL.finditer(text):
                    if m.group(0) not in seen:
                        seen.add(m.group(0))
                        out.urls.append(m.group(0))

    @staticmethod
    def dex_strings(data: bytes) -> list[bytes]:
        """A dex file's string table, each string decoded from modified UTF-8 (one that is not left out)."""
        if data[:4] != b"dex\n" or len(data) < 0x70:
            return []
        count = int.from_bytes(data[0x38:0x3C], "little")
        table = int.from_bytes(data[0x3C:0x40], "little")
        if table + 4 * count > len(data):
            count = max(0, (len(data) - table) // 4)
        out = []
        for i in range(count):
            at = int.from_bytes(data[table + 4 * i : table + 4 * i + 4], "little")
            while at < len(data) and data[at] & 0x80:  # the length, a ULEB128 of UTF-16 units
                at += 1
            at += 1
            end = data.find(b"\x00", at)
            if at >= len(data) or end < 0:
                continue
            text = DexX.mutf8(data[at:end])
            if text is not None:
                out.append(text)
        return out


__all__ = ["Apk", "ApkFacts"]
