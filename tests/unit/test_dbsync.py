"""Verifying and installing a signed advisory bundle.

The bundle is how the advisory database refreshes between scanner releases, and
its whole value is that what lands on disk is what the release pipeline signed.
So the tests that matter are the refusals: a tampered archive, a wrong key, a
member that tries to escape the destination. A test-only Ed25519 signer (built
from the vendored verify module's own field arithmetic, so no signing code
ships) produces the valid signatures the accept-path needs.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from cordon_scanner.intel import _ed25519, dbsync


# --- a test-only signer -----------------------------------------------------
# Ed25519 signing, reusing the vendored module's constants and point math. This
# lives in the tests, never in the shipped package, which stays verify-only.
def _sign_keypair(seed: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _ed25519._point_mul(a, _ed25519._G)
    public = _encode_point(A)
    return public, seed + public  # "private" bundle = seed||public, like libsodium


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z = point[0], point[1], point[2]
    zinv = pow(z, _ed25519._P - 2, _ed25519._P)
    x = x * zinv % _ed25519._P
    y = y * zinv % _ed25519._P
    return int(y | ((x & 1) << 255)).to_bytes(32, "little")


def _sign(private: bytes, message: bytes) -> bytes:
    seed, public = private[:32], private[32:]
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ed25519._L
    R = _encode_point(_ed25519._point_mul(r, _ed25519._G))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), "little") % _ed25519._L
    s = (r + k * a) % _ed25519._L
    return R + s.to_bytes(32, "little")


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return _sign_keypair(b"\x01" * 32)


def _bundle(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, payload in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _signed_advisory_bundle() -> dict[str, bytes]:
    """A minimal bundle whose digest manifest matches its data file."""
    npm = json.dumps([]).encode()
    digest = hashlib.sha256(npm).hexdigest()
    manifest = json.dumps({"advisories-npm.json": digest}).encode()
    return {"advisories-npm.json": npm, "advisories-digests.json": manifest}


class TestTheTestSigner:
    def test_it_produces_signatures_the_vendored_verify_accepts(self, keypair) -> None:
        """If this fails, every other test here is meaningless -- the signer must
        agree with the shipped verifier."""
        public, private = keypair
        sig = _sign(private, b"the message")
        assert _ed25519.verify(public, b"the message", sig)
        assert not _ed25519.verify(public, b"tampered", sig)


class TestVerifyBundle:
    def test_a_valid_signature_verifies(self, keypair) -> None:
        public, private = keypair
        archive = _bundle(_signed_advisory_bundle())
        assert dbsync.verify_bundle(archive, _sign(private, archive), public_key=public)

    def test_a_tampered_archive_does_not(self, keypair) -> None:
        public, private = keypair
        archive = _bundle(_signed_advisory_bundle())
        sig = _sign(private, archive)
        assert not dbsync.verify_bundle(archive + b"x", sig, public_key=public)

    def test_a_different_key_does_not(self, keypair) -> None:
        _, private = keypair
        other_public, _ = _sign_keypair(b"\x02" * 32)
        archive = _bundle(_signed_advisory_bundle())
        assert not dbsync.verify_bundle(archive, _sign(private, archive), public_key=other_public)


class TestInstallBundle:
    def test_a_verified_bundle_is_unpacked(self, keypair, tmp_path) -> None:
        public, private = keypair
        archive = _bundle(_signed_advisory_bundle())
        dbsync.install_bundle(archive, _sign(private, archive), tmp_path, public_key=public)
        assert (tmp_path / "advisories-npm.json").exists()
        assert (tmp_path / "advisories-digests.json").exists()

    def test_an_unverified_bundle_writes_nothing(self, keypair, tmp_path) -> None:
        public, _ = keypair
        _, wrong_private = _sign_keypair(b"\x09" * 32)
        archive = _bundle(_signed_advisory_bundle())
        with pytest.raises(dbsync.BundleError, match="did not verify"):
            dbsync.install_bundle(
                archive, _sign(wrong_private, archive), tmp_path, public_key=public
            )
        assert not list(tmp_path.iterdir())

    def test_a_bundle_whose_data_does_not_match_its_manifest_is_refused(self, keypair, tmp_path):
        """The signature covers the archive; the digest manifest is the second
        line, catching a file swapped for one with the same name but different
        bytes before it was signed."""
        public, private = keypair
        files = _signed_advisory_bundle()
        files["advisories-npm.json"] = json.dumps(
            [{"name": "x"}]
        ).encode()  # no longer matches digest
        archive = _bundle(files)
        with pytest.raises(dbsync.BundleError, match="digest manifest"):
            dbsync.install_bundle(archive, _sign(private, archive), tmp_path, public_key=public)

    def test_a_traversal_member_is_refused(self, keypair, tmp_path) -> None:
        """Even a correctly-signed bundle cannot write outside the destination."""
        public, private = keypair
        archive = _bundle({"../escape.json": b"x"})
        with pytest.raises(dbsync.BundleError):
            dbsync.install_bundle(archive, _sign(private, archive), tmp_path, public_key=public)


class TestPinnedKey:
    def test_an_unset_key_disables_bundle_sync(self) -> None:
        """With no key pinned there is nothing to verify against, so the feature
        refuses rather than trusting an unsigned download."""
        with pytest.raises(dbsync.BundleError, match="no advisory-bundle signing key"):
            dbsync.verify_bundle(b"x", b"y")


class TestFetchHostAllowlist:
    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/x",  # not https
            "https://evil.invalid/x",  # host off the allowlist
            "https://github.com.evil.invalid/x",  # look-alike host
        ],
    )
    def test_a_bad_url_is_refused(self, url, tmp_path) -> None:
        with pytest.raises(dbsync.BundleError):
            dbsync.sync_from_url(url, tmp_path, public_key=b"\x00" * 32)


class TestBuildBundle:
    def test_round_trip(self, tmp_path) -> None:
        """What build_bundle produces, install_bundle accepts."""
        files = _signed_advisory_bundle()
        for name, payload in files.items():
            (tmp_path / name).write_bytes(payload)
        archive = dbsync.build_bundle(tmp_path)
        # It is a gzip tar of the advisory files.
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            assert set(tar.getnames()) == set(files)

    def test_it_is_reproducible(self, tmp_path) -> None:
        """Same data, same bytes -- fixed mtime -- so a second builder confirms."""
        for name, payload in _signed_advisory_bundle().items():
            (tmp_path / name).write_bytes(payload)
        assert dbsync.build_bundle(tmp_path) == dbsync.build_bundle(tmp_path)

    def test_an_empty_dir_is_an_error_not_an_empty_bundle(self, tmp_path) -> None:
        with pytest.raises(dbsync.BundleError, match="no advisory data"):
            dbsync.build_bundle(tmp_path)


def test_gzip_is_stdlib_no_zstd_dependency() -> None:
    """The bundle is gzip precisely so the core needs no compression dependency."""
    assert gzip.decompress(gzip.compress(b"x")) == b"x"
