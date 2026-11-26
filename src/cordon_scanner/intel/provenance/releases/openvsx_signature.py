"""An Open VSX extension's package signature, checked against the key Open VSX signs with, pinned in this package.

Open VSX signs every extension package it hosts: next to the `.vsix` it serves a `.sigzip`, a zip of
`.signature.sig` (an Ed25519 signature over the exact bytes of the `.vsix`), `.signature.manifest` (the package's size and SHA-256,
and those of each file in it) and an empty `.signature.p7s` (the name VS Code looks for). Checked here:

1. the signature file is the one zip entry it should be, 64 bytes, and the key it was made with is one this package pins
   (`intel/data/openvsx-keys.json`; the key id comes from the registry's metadata, the key itself from the pin, never from the
   registry at scan time);
2. the signature verifies over the package that was fetched;
3. the manifest, which is not signed on its own, agrees with the package's size and hash (a consistency check, not a proof).

What this does not prove: the pinned key was read from Open VSX itself (on 2026-11-26; it is not published anywhere else that was
found), so a registry that was already hostile then would have been trusted. What it does prove is that a package now served was
signed by the key Open VSX held at that time: a later swap of a package, or of the key, is caught.

The answer is `verified`, `invalid`, `absent` (the registry publishes no signature for the release) or `unverifiable` (the
signature was made with a key not pinned, or the registry could not be asked)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import zipfile
from typing import ClassVar

from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.sigstore_bundle import Strict, TrustRoot


class OpenVsxSignature:
    SIGNATURE: ClassVar[str] = ".signature.sig"
    MANIFEST: ClassVar[str] = ".signature.manifest"
    MAX_MANIFEST: ClassVar[int] = 8 << 20
    KEY_ID: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    SPKI_PREFIX: ClassVar[bytes] = bytes.fromhex("302a300506032b6570032100")
    _keys: ClassVar[dict[str, bytes] | None] = None

    @classmethod
    def keys(cls) -> dict[str, bytes]:
        """The pinned keys by id: 32-byte Ed25519 public keys."""
        if cls._keys is None:
            document = Strict.loads(
                (TrustRoot.DATA / "openvsx-keys.json").read_text(encoding="utf-8")
            )
            found: dict[str, bytes] = {}
            for entry in document["keys"]:
                spki = base64.b64decode(entry["spki"], validate=True)
                if not spki.startswith(cls.SPKI_PREFIX) or len(spki) != len(cls.SPKI_PREFIX) + 32:
                    raise ValueError("a pinned key that is not an Ed25519 SubjectPublicKeyInfo")
                found[entry["id"]] = spki[len(cls.SPKI_PREFIX) :]
            cls._keys = found
        return cls._keys

    @classmethod
    def key_id(cls, link: object) -> str | None:
        """The key id a registry's `publicKey` link ends with, when it is one."""
        last = link.rsplit("/", 1)[-1] if isinstance(link, str) else ""
        return last if cls.KEY_ID.fullmatch(last) else None

    # -- the checks (no network) -----------------------------------------------------------------------------

    @classmethod
    def verify(cls, package: bytes, sigzip: bytes, key_id: str | None) -> ModuleCheck:
        key = cls.keys().get(key_id or "")
        if key is None:
            return ModuleCheck(
                "unverifiable",
                f"the package is signed with a key this version does not pin ({key_id or 'none named'})",
            )
        try:
            signature, manifest = cls._members(sigzip)
        except (zipfile.BadZipFile, ValueError, KeyError, OSError) as exc:
            return ModuleCheck(
                "invalid", f"the signature archive is not one this reader accepts: {exc}"
            )
        if len(signature) != 64 or not Ed25519.verify(key, package, signature):
            return ModuleCheck("invalid", "the signature does not verify over this package")
        problem = cls._manifest(manifest, package)
        if problem:
            return ModuleCheck(
                "invalid", f"the signature manifest disagrees with the package: {problem}"
            )
        return ModuleCheck("verified", "the package is as Open VSX signed it")

    @classmethod
    def _members(cls, sigzip: bytes) -> tuple[bytes, bytes]:
        with zipfile.ZipFile(io.BytesIO(sigzip)) as archive:
            names = [info.filename for info in archive.infolist()]
            if len(names) != len(set(names)) or cls.SIGNATURE not in names:
                raise ValueError("a signature archive with no signature, or with a name twice")
            sizes = {info.filename: info.file_size for info in archive.infolist()}
            if sizes[cls.SIGNATURE] != 64 or sizes.get(cls.MANIFEST, 0) > cls.MAX_MANIFEST:
                raise ValueError("a signature or manifest of a size not accepted")
            manifest = archive.read(cls.MANIFEST) if cls.MANIFEST in names else b""
            return archive.read(cls.SIGNATURE), manifest

    @staticmethod
    def _manifest(manifest: bytes, package: bytes) -> str:
        if not manifest:
            return "there is no manifest"
        try:
            stated = json.loads(manifest)["package"]
            digest = base64.b64decode(stated["digests"]["sha256"], validate=True)
            size = stated["size"]
        except (ValueError, KeyError, TypeError, binascii.Error):
            return "it does not state the package's size and hash"
        if size != len(package) or digest != hashlib.sha256(package).digest():
            return "its package hash or size is not this package's"
        return ""

    # -- the package -----------------------------------------------------------------------------------------

    @classmethod
    def check(cls, name: str, version: str, integrity: str | None) -> ModuleCheck:
        from cordon_scanner.intel.registries.openvsx import API, FILE_HOSTS, OpenVsx
        from cordon_scanner.intel.registries.registry_http import RegistryHttp
        from cordon_scanner.intel.registries.registry_request import RegistryRequest
        from cordon_scanner.intel.registry import ArchiveSources, RegistryError

        if not name or not version:
            return ModuleCheck("absent", f"{name or 'an extension'} names no release")
        try:
            namespace, extension = OpenVsx.split(name)
            archive = ArchiveSources.package_archive("vscode", name, version)
            document = OpenVsx._json(f"{API}/{namespace}/{extension}/{version}")
            files = RegistryHttp.mapping(document.get("files"))
            if not files.get("signature"):
                return ModuleCheck(
                    "absent", f"Open VSX publishes no signature for {name} {version}"
                )
            link = OpenVsx._on_file_host(files["signature"])
            sigzip = RegistryRequest.fetch_bytes(link, lambda host: host in FILE_HOSTS)
        except (RegistryError, OSError, ValueError) as exc:
            return ModuleCheck("unverifiable", f"Open VSX could not be asked: {exc}")
        return cls.verify(archive.data, sigzip, cls.key_id(files.get("publicKey")))
