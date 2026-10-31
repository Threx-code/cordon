"""The Chrome extension (CRX) reader for cordon-rule: the `crx` module's values as a condition sees them.

YARA has no `crx` module; YARA-X has one, and its names are the schema here (`crx.proto` at v1.21.0). A
CRX is a zip with a signed header in front:

    CRX2: "Cr24", 2, key length, signature length, the public key, the signature, the zip
    CRX3: "Cr24", 3, header length, a CrxFileHeader protobuf, the zip

Values follow the reference's reader so a rule answers the same:

- the extension id is the first 16 bytes of the public key's SHA-256 (CRX2) or the signed header's
  crx_id (CRX3), written as 32 letters a-p;
- each signature names its key (base64) and whether it verifies: RSA PKCS #1 v1.5 (with the DigestInfo
  prefix, else without, as the reference tries both) over the zip (SHA-1, CRX2) or over
  "CRX3 SignedData\\0", the signed header's length, the signed header and the zip (SHA-256, CRX3);
  ECDSA on P-256 for CRX3's ECDSA proofs;
- manifest.json is read as the reference's typed reader reads it: a field of the wrong type, a
  duplicated field, a lone surrogate, NaN or a byte-order mark makes the whole manifest unread, and
  `permissions` must be a list of strings;
- name and description are resolved through `_locales/<default_locale or en>/messages.json` when it
  reads (`__MSG_key__`, the key matched exactly), with the unresolved text kept as raw_name and
  raw_description;
- `permhash()` is the SHA-256 of the permissions joined with nothing between them.

A header or zip that does not read gives `is_crx` false and nothing else.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.der import BadDer, Tlv
from cordon_scanner.detect.binary.modules.formats.zip import Directory, Entries, NotZip
from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig
from cordon_scanner.detect.binary.modules.x509 import PublicKey

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class NotCrx(Exception):
    """The header, its protobuf or the zip does not read."""


class Protobuf:
    """The few protobuf messages a CRX3 header holds, read by field number and wire type."""

    @staticmethod
    def fields(data: bytes) -> list[tuple[int, int, Any]]:
        """Every (field, wire type, value) in order; a truncated or impossible record raises."""
        out: list[tuple[int, int, Any]] = []
        at, n = 0, len(data)
        value: Any
        while at < n:
            key, at = Protobuf._varint(data, at)
            number, wire = key >> 3, key & 7
            if number == 0:
                raise NotCrx
            if wire == 0:
                value, at = Protobuf._varint(data, at)
            elif wire == 1:
                if at + 8 > n:
                    raise NotCrx
                value, at = data[at : at + 8], at + 8
            elif wire == 2:
                length, at = Protobuf._varint(data, at)
                if at + length > n:
                    raise NotCrx
                value, at = data[at : at + length], at + length
            elif wire == 5:
                if at + 4 > n:
                    raise NotCrx
                value, at = data[at : at + 4], at + 4
            elif wire == 3:
                at = Protobuf._skip_group(data, at, number)
                continue
            else:
                raise NotCrx
            out.append((number, wire, value))
        return out

    @staticmethod
    def _varint(data: bytes, at: int) -> tuple[int, int]:
        value = shift = 0
        for _ in range(10):
            if at >= len(data):
                raise NotCrx
            byte = data[at]
            at += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value & ((1 << 64) - 1), at
            shift += 7
        raise NotCrx

    @staticmethod
    def _skip_group(data: bytes, at: int, number: int) -> int:
        depth = 1
        while depth:
            key, at = Protobuf._varint(data, at)
            wire = key & 7
            if wire == 3:
                depth += 1
            elif wire == 4:
                depth -= 1
                if depth == 0 and key >> 3 != number:
                    raise NotCrx
            elif wire == 0:
                _, at = Protobuf._varint(data, at)
            elif wire == 1:
                at += 8
            elif wire == 2:
                length, at = Protobuf._varint(data, at)
                at += length
            elif wire == 5:
                at += 4
            else:
                raise NotCrx
            if at > len(data):
                raise NotCrx
        return at

    @staticmethod
    def bytes_field(fields: list[tuple[int, int, Any]], number: int) -> bytes | None:
        """The last value of a bytes field, as protobuf keeps it; a wrong wire type raises."""
        found = None
        for field, wire, value in fields:
            if field == number:
                if wire != 2:
                    raise NotCrx
                found = value
        return found


class StrictJson:
    """JSON read as a typed reader reads it into a struct of optional strings and string lists."""

    TEXT_FIELDS: ClassVar[tuple[str, ...]] = (
        "version", "name", "description", "minimum_chrome_version", "homepage_url", "default_locale",
    )  # fmt: skip
    LIST_FIELDS: ClassVar[tuple[str, ...]] = (
        "permissions", "host_permissions", "optional_permissions", "optional_host_permissions",
    )  # fmt: skip

    @staticmethod
    def load(raw: bytes) -> Any:
        """The document, or raise for what the reference's reader refuses: invalid UTF-8, a
        byte-order mark, NaN or Infinity, and a lone surrogate escape."""
        text = raw.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError("byte-order mark")

        def no_constant(name: str) -> Any:
            raise ValueError(name)

        doc = json.loads(text, parse_constant=no_constant, object_pairs_hook=StrictJson._pairs)
        StrictJson._no_lone_surrogates(doc)
        return doc

    @staticmethod
    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        dup: set[str] = set()
        for k, v in pairs:
            if k in out:
                dup.add(k)
            out[k] = v
        out["\0dup"] = dup  # read by manifest() for the fields a struct holds; never a JSON key
        return out

    @staticmethod
    def _no_lone_surrogates(doc: Any) -> None:
        """Raise when any key or string holds a lone surrogate: written back as JSON, it cannot be
        encoded as UTF-8 (the duplicate-name sets are written as lists, which hold only names)."""
        json.dumps(doc, ensure_ascii=False, default=sorted).encode("utf-8")

    @staticmethod
    def manifest(raw: bytes) -> dict[str, Any] | None:
        try:
            doc = StrictJson.load(raw)
        except (ValueError, UnicodeError):
            return None
        if not isinstance(doc, dict):
            return None
        if doc["\0dup"] & set(StrictJson.TEXT_FIELDS + StrictJson.LIST_FIELDS):
            return None
        out: dict[str, Any] = {}
        for name in StrictJson.TEXT_FIELDS:
            value = doc.get(name)
            if value is not None and not isinstance(value, str):
                return None
            out[name] = value
        for name in StrictJson.LIST_FIELDS:
            value = doc.get(name)
            if value is None:
                out[name] = []
                continue
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                return None
            out[name] = value
        return out

    @staticmethod
    def locale(raw: bytes) -> dict[str, str] | None:
        try:
            doc = StrictJson.load(raw)
        except (ValueError, UnicodeError):
            return None
        if not isinstance(doc, dict):
            return None
        messages: dict[str, str] = {}
        for key, entry in doc.items():
            if key == "\0dup":
                continue
            if not isinstance(entry, dict) or ("\0dup" in entry and "message" in entry["\0dup"]):
                return None
            message = entry.get("message")
            if not isinstance(message, str):
                return None
            messages[key] = message
        return messages


class Members:
    """A zip's members by exact name, the last of a repeated name winning, read stored or deflated."""

    __slots__ = ("_entries", "cur", "names")

    def __init__(self, data: bytes) -> None:
        try:
            entries = Entries(Directory(Cursor(data)))
        except NotZip as exc:
            raise NotCrx from exc
        self.cur = entries.cur
        self.names: dict[bytes, int] = {}
        for i, at in enumerate(entries.offsets):
            name_len = int(self.cur.uint(at + 28, 2, "little"))
            self.names[self.cur.data[at + 46 : at + 46 + name_len]] = i
        self._entries = entries

    def read(self, name: str) -> bytes | None:
        index = self.names.get(name.encode("utf-8"))
        if index is None:
            return None
        cur, at = self.cur, self._entries.offsets[index]
        method = cur.uint(at + 10, 2, "little")
        sizes = Entries._sizes(cur, at)
        local = cur.uint(at + 42, 4, "little")
        if sizes is None or local is ABSENT or cur.uint(local, 4, "little") != 0x04034B50:
            return None
        compressed, size = sizes
        name_len, extra_len = cur.uint(local + 26, 2, "little"), cur.uint(local + 28, 2, "little")
        if name_len is ABSENT or extra_len is ABSENT:
            return None
        start = int(local) + 30 + int(name_len) + int(extra_len)
        body = cur.data[start : start + compressed]
        if len(body) != compressed:
            return None
        if method == 0:
            return body
        if method != 8:
            return None
        try:
            inflate = zlib.decompressobj(-15)
            out = inflate.decompress(body, size + 1)
        except zlib.error:
            return None
        return out if len(out) == size else None


class Crx:
    """The `crx` module reader."""

    MAGIC: ClassVar[bytes] = b"Cr24"
    SHA1_RSA, SHA256_RSA = "sha1", "sha256"
    P256: ClassVar[str] = "1.2.840.10045.3.1.7"

    _signature = Record({"key": TEXT, "verified": BOOL})
    SCHEMA: ClassVar[Record] = Record({
        "is_crx": BOOL, "crx_version": INT, "header_size": INT,
        **dict.fromkeys(
            ("id", "version", "name", "description", "raw_name", "raw_description",
             "minimum_chrome_version", "homepage_url"), TEXT,
        ),
        **dict.fromkeys(
            ("permissions", "host_permissions", "optional_permissions", "optional_host_permissions"),
            Seq(TEXT),
        ),
        "signatures": Seq(_signature),
        "permhash": Call(Sig((), TEXT)),
    })  # fmt: skip

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {"signatures": {}}
        for name in StrictJson.LIST_FIELDS:
            out[name] = {}
        try:
            Crx._read(out, file)
        except NotCrx:
            return {"is_crx": False, "signatures": {}, **{n: {} for n in StrictJson.LIST_FIELDS}}
        return out

    @staticmethod
    def _read(out: dict[str, Any], file: bytes) -> None:
        cur = Cursor(file)
        if file[:4] != Crx.MAGIC:
            raise NotCrx
        version = cur.uint(4, 4, "little")
        if version == 2:
            zip_data, crx_id, header_size, signatures = Crx._v2(cur, file)
        elif version == 3:
            zip_data, crx_id, header_size, signatures = Crx._v3(cur, file)
        else:
            raise NotCrx
        members = Members(zip_data)
        manifest_raw = members.read("manifest.json")
        manifest = StrictJson.manifest(manifest_raw) if manifest_raw is not None else None
        lang = (manifest or {}).get("default_locale") or "en"
        locale_raw = members.read(f"_locales/{lang}/messages.json")
        locale = StrictJson.locale(locale_raw) if locale_raw is not None else None
        out.update(
            is_crx=True,
            crx_version=int(version),
            header_size=header_size,
            id=Crx.printable_id(crx_id),
            signatures=dict(enumerate(signatures)),
        )
        if manifest is not None:
            Crx._manifest(out, manifest, locale)
        permissions = [p.encode() for p in (manifest or {}).get("permissions", [])]
        out["permhash"] = (lambda: hashlib.sha256(b"".join(permissions)).hexdigest().encode(),)

    @staticmethod
    def _v2(cur: Cursor, file: bytes) -> tuple[bytes, bytes, int, list[dict[str, Any]]]:
        key_len, sig_len = cur.uint(8, 4, "little"), cur.uint(12, 4, "little")
        if key_len is ABSENT or sig_len is ABSENT or 16 + key_len + sig_len > len(file):
            raise NotCrx
        key = file[16 : 16 + key_len]
        signature = file[16 + key_len : 16 + key_len + sig_len]
        zip_data = file[16 + key_len + sig_len :]
        Members(zip_data)  # the zip must read before anything is said
        verified = Crx._rsa(key, hashlib.sha1(zip_data).digest(), Crx.SHA1_RSA, signature)  # noqa: S324 - CRX2 signs SHA-1
        signatures = [{"key": base64.b64encode(key), "verified": verified}]
        crx_id = hashlib.sha256(key).digest()[:16]
        return zip_data, crx_id, (int(key_len) + int(sig_len)) & 0xFFFFFFFF, signatures

    @staticmethod
    def _v3(cur: Cursor, file: bytes) -> tuple[bytes, bytes, int, list[dict[str, Any]]]:
        length = cur.uint(8, 4, "little")
        if length is ABSENT or 12 + length > len(file):
            raise NotCrx
        header, zip_data = file[12 : 12 + length], file[12 + length :]
        fields = Protobuf.fields(header)
        signed = Protobuf.bytes_field(fields, 10000)
        if signed is None:
            raise NotCrx
        crx_id = Protobuf.bytes_field(Protobuf.fields(signed), 1) or b""
        prefix = b"CRX3 SignedData\x00" + len(signed).to_bytes(4, "little") + signed
        digest = hashlib.sha256(prefix + zip_data).digest()
        signatures = []
        for number, kind in ((2, "rsa"), (3, "ecdsa")):
            for field, wire, value in fields:
                if field != number:
                    continue
                if wire != 2:
                    raise NotCrx
                proof = Protobuf.fields(value)
                key, signature = Protobuf.bytes_field(proof, 1), Protobuf.bytes_field(proof, 2)
                if key is None or signature is None:
                    continue
                verified = (
                    Crx._rsa(key, digest, Crx.SHA256_RSA, signature)
                    if kind == "rsa"
                    else Crx._ecdsa(key, digest, signature)
                )
                signatures.append({"key": base64.b64encode(key), "verified": verified})
        Members(zip_data)
        return zip_data, crx_id, int(length), signatures

    @staticmethod
    def _rsa(key: bytes, digest: bytes, digest_name: str, signature: bytes) -> bool:
        """PKCS #1 v1.5 with the DigestInfo prefix, else without it, as the reference tries both."""
        try:
            spki = Tlv.decode(key)
            if spki.span != key or spki.row(2)[0].row((1, 2))[0].object_id() != PublicKey.RSA:
                return False
            if PublicKey.verifies(spki, digest_name, digest, signature):
                return True
            return PublicKey.rsa_recover(spki, signature, exact=True) == digest
        except (BadDer, ValueError, IndexError, TypeError):
            return False

    @staticmethod
    def _ecdsa(key: bytes, digest: bytes, signature: bytes) -> bool:
        """ECDSA on P-256 only, the one curve the reference's CRX check takes."""
        try:
            spki = Tlv.decode(key)
            algorithm = spki.row(2)[0].row((1, 2))
            if spki.span != key or algorithm[0].object_id() != PublicKey.EC:
                return False
            if len(algorithm) < 2 or algorithm[1].object_id() != Crx.P256:
                return False
            return PublicKey.verifies(spki, "sha256", digest, signature)
        except (BadDer, ValueError, IndexError, TypeError):
            return False

    @staticmethod
    def _manifest(
        out: dict[str, Any], manifest: dict[str, Any], locale: dict[str, str] | None
    ) -> None:
        def resolved(text: str | None) -> str | None:
            if text is None or locale is None:
                return text
            if text.startswith("__MSG_") and text.endswith("__") and len(text) >= 8:
                return locale.get(text[6:-2], text)
            return text

        for name in ("name", "description"):
            value = manifest.get(name)
            shown = resolved(value) if locale is not None else value
            if shown is not None:
                out[name] = shown.encode("utf-8")
            if locale is not None and value is not None:
                out["raw_" + name] = value.encode("utf-8")
        for name in ("version", "minimum_chrome_version", "homepage_url"):
            if manifest.get(name) is not None:
                out[name] = manifest[name].encode("utf-8")
        for name in StrictJson.LIST_FIELDS:
            out[name] = {i: p.encode("utf-8") for i, p in enumerate(manifest[name])}

    @staticmethod
    def printable_id(raw: bytes) -> bytes:
        """16 bytes as 32 letters: each hex digit 0-f written a-p."""
        return bytes(ord("a") + int(c, 16) for c in raw.hex())


__all__ = ["Crx"]
