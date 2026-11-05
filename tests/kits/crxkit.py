"""Chrome extensions written for the crx tests: CRX2 and CRX3 files signed for real with test keys made
here, deterministically (RSA from a seeded prime search, ECDSA P-256 with a seeded nonce), so the files
are the same bytes every run and the recorded reference output stays theirs. Test keys only."""

from __future__ import annotations

import hashlib
import io
import json
import random
import zipfile
from typing import ClassVar

from cordon_scanner.detect.binary.modules.der import Encode


class TestKeys:
    """An RSA key and a P-256 key, the same every run."""

    P: ClassVar[int] = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    A: ClassVar[int] = P - 3
    N: ClassVar[int] = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    G: ClassVar[tuple[int, int]] = (
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    )

    @staticmethod
    def prime(rng: random.Random, bits: int) -> int:
        while True:
            candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if TestKeys.probable_prime(candidate, rng):
                return candidate

    @staticmethod
    def probable_prime(n: int, rng: random.Random) -> bool:
        if n % 2 == 0:
            return n == 2
        d, r = n - 1, 0
        while d % 2 == 0:
            d, r = d // 2, r + 1
        for _ in range(24):
            x = pow(rng.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def rsa(seed: int = 7) -> tuple[int, int, int]:
        rng = random.Random(seed)  # noqa: S311 -- a test key, never a real one
        e = 65537
        while True:
            p, q = TestKeys.prime(rng, 512), TestKeys.prime(rng, 512)
            phi = (p - 1) * (q - 1)
            if p != q and phi % e:
                return p * q, e, pow(e, -1, phi)

    @staticmethod
    def rsa_spki(n: int, e: int) -> bytes:
        def integer(v: int) -> bytes:
            return Encode.wrap(2, v.to_bytes(v.bit_length() // 8 + 1, "big"))

        key = Encode.wrap(0x30, integer(n) + integer(e))
        algorithm = Encode.wrap(0x30, bytes.fromhex("06092a864886f70d0101010500"))
        return Encode.wrap(0x30, algorithm + Encode.wrap(3, b"\x00" + key))

    @staticmethod
    def rsa_sign(n: int, d: int, digest_info: bytes) -> bytes:
        width = (n.bit_length() + 7) // 8
        block = b"\x00\x01" + b"\xff" * (width - 3 - len(digest_info)) + b"\x00" + digest_info
        return pow(int.from_bytes(block, "big"), d, n).to_bytes(width, "big")

    @staticmethod
    def add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        P = TestKeys.P
        if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
            return None
        if p1 == p2:
            lam = (3 * p1[0] * p1[0] + TestKeys.A) * pow(2 * p1[1], -1, P) % P
        else:
            lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
        x = (lam * lam - p1[0] - p2[0]) % P
        return x, (lam * (p1[0] - x) - p1[1]) % P

    @staticmethod
    def mul(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
        out: tuple[int, int] | None = None
        add: tuple[int, int] | None = point
        while k:
            if k & 1:
                out = TestKeys.add(out, add)
            add = TestKeys.add(add, add)
            k >>= 1
        return out

    @staticmethod
    def ec(seed: int = 11) -> tuple[int, bytes]:
        rng = random.Random(seed)  # noqa: S311 -- a test key, never a real one
        d = rng.randrange(1, TestKeys.N)
        x, y = TestKeys.mul(d, TestKeys.G) or (0, 0)
        point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        algorithm = Encode.wrap(
            0x30, bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex("06082a8648ce3d030107")
        )
        return d, Encode.wrap(0x30, algorithm + Encode.wrap(3, b"\x00" + point))

    @staticmethod
    def ec_sign(d: int, digest: bytes, seed: int = 13) -> bytes:
        rng = random.Random(seed)  # noqa: S311 -- a test nonce, never a real one
        z = int.from_bytes(digest, "big")
        while True:
            k = rng.randrange(1, TestKeys.N)
            point = TestKeys.mul(k, TestKeys.G)
            if point is None:
                continue
            r = point[0] % TestKeys.N
            s = pow(k, -1, TestKeys.N) * (z + r * d) % TestKeys.N
            if r and s:
                break

        def integer(v: int) -> bytes:
            return Encode.wrap(2, v.to_bytes(v.bit_length() // 8 + 1, "big"))

        return Encode.wrap(0x30, integer(r) + integer(s))


class CrxKit:
    """CRX files, member by member."""

    SHA1_INFO: ClassVar[bytes] = bytes.fromhex("3021300906052b0e03021a05000414")
    SHA256_INFO: ClassVar[bytes] = bytes.fromhex("3031300d060960864801650304020105000420")

    @staticmethod
    def zip(members: dict[str, bytes]) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in members.items():
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                z.writestr(info, data)
        return out.getvalue()

    @staticmethod
    def manifest(**fields: object) -> bytes:
        base: dict[str, object] = {"name": "Ext", "version": "1.0", "manifest_version": 3}
        base.update(fields)
        return json.dumps(base).encode()

    @staticmethod
    def v2(members: dict[str, bytes], *, tamper: bool = False) -> bytes:
        n, e, d = TestKeys.rsa()
        key = TestKeys.rsa_spki(n, e)
        zip_data = CrxKit.zip(members)
        signature = TestKeys.rsa_sign(n, d, CrxKit.SHA1_INFO + hashlib.sha1(zip_data).digest())  # noqa: S324 - CRX2 signs SHA-1
        if tamper:
            zip_data = (
                zip_data[:40] + bytes([zip_data[40] ^ 1]) + zip_data[41:]
            )  # in the member's bytes
        return (
            b"Cr24" + (2).to_bytes(4, "little") + len(key).to_bytes(4, "little")
            + len(signature).to_bytes(4, "little") + key + signature + zip_data
        )  # fmt: skip

    @staticmethod
    def field(number: int, payload: bytes) -> bytes:
        def varint(v: int) -> bytes:
            out = bytearray()
            while True:
                byte = v & 0x7F
                v >>= 7
                out.append(byte | (0x80 if v else 0))
                if not v:
                    return bytes(out)

        return varint(number << 3 | 2) + varint(len(payload)) + payload

    @staticmethod
    def v3(members: dict[str, bytes], *, crx_id: bytes = b"\x01" * 16, ecdsa: bool = True,
           tamper: bool = False) -> bytes:  # fmt: skip
        zip_data = CrxKit.zip(members)
        signed = CrxKit.field(1, crx_id)
        message = b"CRX3 SignedData\x00" + len(signed).to_bytes(4, "little") + signed + zip_data
        digest = hashlib.sha256(message).digest()
        n, e, d = TestKeys.rsa()
        rsa_proof = CrxKit.field(1, TestKeys.rsa_spki(n, e)) + CrxKit.field(
            2, TestKeys.rsa_sign(n, d, CrxKit.SHA256_INFO + digest)
        )
        header = CrxKit.field(2, rsa_proof)
        if ecdsa:
            k, spki = TestKeys.ec()
            header += CrxKit.field(
                3, CrxKit.field(1, spki) + CrxKit.field(2, TestKeys.ec_sign(k, digest))
            )
        header += CrxKit.field(10000, signed)
        if tamper:
            zip_data = (
                zip_data[:40] + bytes([zip_data[40] ^ 1]) + zip_data[41:]
            )  # in the member's bytes
        return (
            b"Cr24"
            + (3).to_bytes(4, "little")
            + len(header).to_bytes(4, "little")
            + header
            + zip_data
        )

    @staticmethod
    def cases() -> dict[str, bytes]:
        locale = {"_locales/en/messages.json": b'{"appName": {"message": "Resolved Name"}}'}
        perms = CrxKit.manifest(permissions=["tabs", "storage"], host_permissions=["<all_urls>"])
        return {
            "v2": CrxKit.v2({"manifest.json": perms}),
            "v2-tampered": CrxKit.v2({"manifest.json": perms}, tamper=True),
            "v3": CrxKit.v3({"manifest.json": perms}),
            "v3-tampered": CrxKit.v3({"manifest.json": perms}, tamper=True),
            "v3-rsa-only": CrxKit.v3({"manifest.json": perms}, ecdsa=False),
            "v3-locale": CrxKit.v3({"manifest.json": CrxKit.manifest(name="__MSG_appName__"), **locale}),
            "v3-locale-missing-key": CrxKit.v3({"manifest.json": CrxKit.manifest(name="__MSG_other__"), **locale}),
            "v3-default-locale": CrxKit.v3({
                "manifest.json": CrxKit.manifest(name="__MSG_appName__", default_locale="fr"),
                "_locales/fr/messages.json": b'{"appName": {"message": "Nom"}}',
            }),
            "v3-no-manifest": CrxKit.v3({"other.txt": b"x"}),
            "v3-permission-object": CrxKit.v3({"manifest.json": CrxKit.manifest(permissions=["tabs", {"fileSystem": ["write"]}])}),
            "v3-name-wrong-type": CrxKit.v3({"manifest.json": CrxKit.manifest(name=5)}),
            "v3-duplicate-name": CrxKit.v3({"manifest.json": b'{"name": "a", "name": "b", "version": "1"}'}),
            "v3-bom": CrxKit.v3({"manifest.json": b"\xef\xbb\xbf" + perms}),
            "v3-nan": CrxKit.v3({"manifest.json": b'{"name": "a", "x": NaN}'}),
            "v3-all-fields": CrxKit.v3({"manifest.json": CrxKit.manifest(
                description="Desc", minimum_chrome_version="100", homepage_url="https://x.invalid",
                optional_permissions=["cookies"], optional_host_permissions=["https://*/*"])}),
            "v4-not-a-version": b"Cr24" + (4).to_bytes(4, "little") + b"\x00" * 32,
            "not-crx": b"PK\x03\x04 a zip, not a crx",
            "v3-truncated-header": b"Cr24" + (3).to_bytes(4, "little") + (1000).to_bytes(4, "little") + b"\x12\x05",
            "v3-no-signed-data": b"Cr24" + (3).to_bytes(4, "little") + (2).to_bytes(4, "little") + b"\x10\x01" + CrxKit.zip({"manifest.json": perms}),
            "v2-bad-zip": b"Cr24" + (2).to_bytes(4, "little") + (0).to_bytes(4, "little") + (0).to_bytes(4, "little") + b"not a zip",
        }  # fmt: skip


__all__ = ["CrxKit", "TestKeys"]
