"""Install a fresh advisory database from a signed bundle.

The advisory data ships inside the wheel and can also be refreshed between
releases, so that a scanner installed six months ago can still match a
vulnerability disclosed yesterday without waiting for a new scanner release --
the model Trivy and Grype use. The refresh is a separately-versioned bundle the
operator pulls on their own schedule; nothing here runs during a scan, so the
"no network at scan time" guarantee is untouched.

What this does NOT relax is trust. The bundle is Ed25519-signed by the release
pipeline, and the signature is verified here against a key pinned in the source
before a single byte is unpacked. Verification uses the vendored, verify-only
`_ed25519` (the core takes no third-party runtime dependency). After the
signature, the per-file digest manifest already shipped in the bundle is checked
as it is for the wheel's own data, so a file altered between signing and
unpacking is still caught.

The bundle is a gzip tar -- stdlib, no compression dependency -- and is unpacked
with the `data` filter, which refuses absolute paths, traversal and symlinks, so
a hostile bundle that somehow passed the signature still cannot write outside the
destination.
"""

from __future__ import annotations

import http.client
import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cordon_scanner.intel import _ed25519

#: The release pipeline's Ed25519 public key, hex, 64 characters. Empty until a
#: maintainer pins it: bundle sync is an opt-in feature that cannot be safe
#: without a key to verify against, so an unset key disables it with a clear
#: message rather than trusting an unsigned download. The matching private key
#: lives only in the release workflow's secrets and is never in this repository.
PUBLIC_KEY_HEX = ""

PUBLIC_KEY_FILE = Path(__file__).parent / "data" / "advisory-signing-key.json"
"""Where the key ceremony's public advisory key is committed. Absent until the ceremony."""

#: Where a bundle may be fetched from. A signature makes the bytes tamper-evident
#: wherever they came from, but pinning the host as well keeps a mistyped or
#: injected URL from reaching an arbitrary server -- the same discipline
#: `osv_import` and the sandbox fetcher already apply.
ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "ghcr.io",
        "pkg-containers.githubusercontent.com",
    }
)

BUNDLE_NAME = "cordon-advisories.tar.gz"
SIGNATURE_NAME = "cordon-advisories.tar.gz.sig"

MAX_BUNDLE_BYTES = 256 << 20
TIMEOUT_SECONDS = 60.0
USER_AGENT = "cordon-scanner advisory-sync (+https://github.com/Threx-code/cordon)"


class BundleError(Exception):
    """A bundle could not be fetched, verified, or unpacked.

    Raised rather than degrading to an unverified or partial install: the whole
    point of the bundle is that what lands on disk is what was signed.
    """


class AdvisoryBundle:
    """The signed advisory bundle: building, verifying, fetching and installing it."""

    @staticmethod
    def pinned_key_hex() -> str:
        """The pinned public key: the constant if set, else the file the key ceremony writes.

        A data file rather than only a constant, so committing the ceremony's public output is the
        whole of pinning it -- no hand-copied hex for a typo to change into a different key.
        """
        if PUBLIC_KEY_HEX:
            return PUBLIC_KEY_HEX
        try:
            document = json.loads(PUBLIC_KEY_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        if not isinstance(document, dict) or document.get("keytype") != "ed25519":
            return ""
        public = document.get("public")
        return public if isinstance(public, str) else ""

    @staticmethod
    def _pinned_key() -> bytes:
        pinned = AdvisoryBundle.pinned_key_hex()
        if not pinned:
            raise BundleError(
                "no advisory-bundle signing key is configured, so a downloaded bundle "
                "cannot be verified; bundle sync is disabled. Build the database "
                "locally with `advisories sync` instead."
            )
        try:
            key = bytes.fromhex(pinned)
        except ValueError as exc:
            raise BundleError("the pinned signing key is not valid hex") from exc
        if len(key) != 32:
            raise BundleError("the pinned signing key is not a 32-byte Ed25519 key")
        return key

    @staticmethod
    def verify_bundle(archive: bytes, signature: bytes, *, public_key: bytes | None = None) -> bool:
        """Whether `signature` is a valid signature of `archive` by the pinned key.

        The signature covers the whole archive, so one check protects every file in
        it; the digest manifest inside is defence in depth for the unpack.
        """
        key = public_key if public_key is not None else AdvisoryBundle._pinned_key()
        return _ed25519.Ed25519.verify(key, archive, signature)

    @staticmethod
    def install_bundle(
        archive: bytes,
        signature: bytes,
        dest: Path,
        *,
        public_key: bytes | None = None,
    ) -> None:
        """Verify a bundle and unpack its advisory files into `dest`.

        Order matters: the signature is checked before anything is read out of the
        archive, so a hostile archive is never parsed on the strength of its own
        contents. The `data` filter then refuses any member that is absolute, escapes
        the destination, or is a link.
        """
        if not AdvisoryBundle.verify_bundle(archive, signature, public_key=public_key):
            raise BundleError("the bundle signature did not verify; nothing was installed")

        dest.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                AdvisoryBundle._safe_extract(tar, dest)
        except (tarfile.TarError, OSError) as exc:
            raise BundleError(f"the bundle could not be unpacked: {type(exc).__name__}") from exc

        from cordon_scanner.intel.advisories import AdvisoryFiles

        bad = AdvisoryFiles.verify_data_dir(dest)
        if bad:
            raise BundleError(
                f"the unpacked bundle does not match its own digest manifest: {', '.join(bad)}"
            )
        # Verified against the pinned signature and its own manifest; sealed so later scans read it.
        AdvisoryFiles.seal_manifest(dest)

    @staticmethod
    def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
        for member in tar.getmembers():
            if not (member.isreg() or member.isdir()):
                raise BundleError(f"bundle contains a non-regular member: {member.name}")
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise BundleError(f"bundle member escapes the destination: {member.name}")
        # `filter="data"` is the second, authoritative guard: it strips setuid/dev
        # nodes, rejects absolute paths and links, and re-checks traversal.
        tar.extractall(dest, filter="data")

    @staticmethod
    def build_bundle(data_dir: Path) -> bytes:
        """The gzip-tar bytes of a data directory's advisory files, for signing.

        Used by the release pipeline, not at scan time. Includes every file the
        digest manifest can name -- the per-ecosystem sets, compressed or not, the
        meta, the manifest and the exploited-vulnerability catalogue -- at a flat
        path, with a fixed mtime so the same data produces the same bytes -- a
        reproducible artefact is one a second builder can confirm. Leaving the
        compressed sets out would ship a manifest naming files the bundle lacks, and
        the installed copy would read as tampered.
        """
        patterns = (
            "advisories-*.json",
            "advisories-*.json.gz",
            "exploited.json",
            "epss.csv.gz",
            "hallucinated.json",
            "agent-actions.json",
            "vscode-extensions.json",
            "atr-rules.json.gz",
        )
        files = sorted({p for pattern in patterns for p in data_dir.glob(pattern) if p.is_file()})
        if not files:
            raise BundleError(f"no advisory data to bundle in {data_dir}")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            for path in files:
                info = tarfile.TarInfo(name=path.name)
                payload = path.read_bytes()
                info.size = len(payload)
                info.mtime = 0
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(payload))
        return buffer.getvalue()

    @staticmethod
    def _fetch(url: str) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            raise BundleError(f"refusing a non-HTTPS bundle URL: {url}")
        if parsed.hostname not in ALLOWED_HOSTS:
            raise BundleError(f"refusing a bundle host outside the allowlist: {parsed.hostname}")
        request = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
                body = response.read(MAX_BUNDLE_BYTES + 1)
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            raise BundleError(f"could not fetch {url}: {type(exc).__name__}") from exc
        if len(body) > MAX_BUNDLE_BYTES:
            raise BundleError(f"{url} exceeded {MAX_BUNDLE_BYTES} bytes and was not downloaded")
        return bytes(body)

    @staticmethod
    def sync_from_url(base_url: str, dest: Path, *, public_key: bytes | None = None) -> None:
        """Fetch the bundle and its signature from `base_url` and install them.

        `base_url` names a directory (a release's asset URL prefix). The bundle and
        its detached signature are fetched from fixed names under it, both host-pinned.
        """
        base = base_url.rstrip("/")
        archive = AdvisoryBundle._fetch(f"{base}/{BUNDLE_NAME}")
        signature = AdvisoryBundle._fetch(f"{base}/{SIGNATURE_NAME}")
        AdvisoryBundle.install_bundle(archive, signature, dest, public_key=public_key)


__all__ = ["ALLOWED_HOSTS", "BUNDLE_NAME", "SIGNATURE_NAME", "AdvisoryBundle", "BundleError"]
