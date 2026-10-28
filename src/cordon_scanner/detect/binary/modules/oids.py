"""OpenSSL's object identifiers as declared data: the OID registry and the digest sizes.

``NAMES`` maps an object identifier to the short and long names OpenSSL keeps for it (either may
be empty); ``DIGEST_SIZES`` maps a digest's long name to its output length in bytes. The values are
OpenSSL's own object table -- the reference a certificate's algorithm, a name's attribute type and a
timestamp's imprint are resolved against -- so they are held here verbatim as a constant table and
read by modules.signature; nothing computes them."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.detect.binary.modules.oid_iso import ISO_NAMES
from cordon_scanner.detect.binary.modules.oid_itu_t import ITU_T_NAMES
from cordon_scanner.detect.binary.modules.oid_joint import JOINT_NAMES

#: the short and long names an identifier carries, either of which OpenSSL may leave empty
OidNames = tuple[str | None, str | None]
#: a digest's output length in bytes, by its long name
DigestSizes = dict[str, int]


class ObjectIds:
    """The object-identifier registry and digest sizes, looked up by OID or digest name."""

    NAMES: ClassVar[dict[str, OidNames]] = {**ITU_T_NAMES, **ISO_NAMES, **JOINT_NAMES}

    DIGEST_SIZES: ClassVar[DigestSizes] = {
        "RSA-SHA3-224": 28,
        "RSA-SHA3-256": 32,
        "RSA-SHA3-384": 48,
        "RSA-SHA3-512": 64,
        "blake2b512": 64,
        "blake2s256": 32,
        "md4": 16,
        "md4WithRSAEncryption": 16,
        "md5": 16,
        "md5WithRSAEncryption": 16,
        "mdc2": 16,
        "mdc2WithRSA": 16,
        "ripemd160": 20,
        "ripemd160WithRSA": 20,
        "sha1": 20,
        "sha1WithRSAEncryption": 20,
        "sha224": 28,
        "sha224WithRSAEncryption": 28,
        "sha256": 32,
        "sha256WithRSAEncryption": 32,
        "sha3-224": 28,
        "sha3-256": 32,
        "sha3-384": 48,
        "sha3-512": 64,
        "sha384": 48,
        "sha384WithRSAEncryption": 48,
        "sha512": 64,
        "sha512-224": 28,
        "sha512-224WithRSAEncryption": 28,
        "sha512-256": 32,
        "sha512-256WithRSAEncryption": 32,
        "sha512WithRSAEncryption": 64,
        "shake128": 16,
        "shake256": 32,
        "sm3": 32,
        "sm3WithRSAEncryption": 32,
        "whirlpool": 64,
    }
