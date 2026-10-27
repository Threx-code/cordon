"""Digest vectors for the TLSH import hash (rule_tlsh): known results, fixed against the reference
differential, and the boundaries where the hash is empty.
"""

from __future__ import annotations

from cordon_scanner.detect.binary.rule_tlsh import Tlsh


class TestTlshDigest:
    """TLSH in the 128-bucket, one-byte-checksum configuration."""

    def test_known_digests(self) -> None:
        v1 = bytes(range(256)) * 4
        v2 = bytes((i * 37 + 11) & 0xFF for i in range(600))
        assert (
            Tlsh.digest(v1)
            == b"T16D119524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D"
        )
        assert (
            Tlsh.digest(v2)
            == b"T16CF0A25F5E2E26C4F984C7545A98C87EA008F42CA3D49C4C57770D3875E92EA57E0B2D"
        )

    def test_too_short_has_no_digest(self) -> None:
        assert Tlsh.digest(b"") == b""
        assert Tlsh.digest(b"x" * 49) == b""

    def test_too_uniform_has_no_digest(self) -> None:
        assert Tlsh.digest(bytes(2000)) == b""

    def test_digest_shape(self) -> None:
        digest = Tlsh.digest(bytes(range(256)) * 4)
        assert digest.startswith(b"T1")
        assert len(digest) == 72  # "T1" + (3 header + 32 body) bytes as upper-case hex
        assert all(c in b"0123456789ABCDEF" for c in digest[2:])
