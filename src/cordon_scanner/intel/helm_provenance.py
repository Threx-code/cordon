"""Helm charts' provenance files, verified as `helm verify` and `helm install --verify` do.

A chart publisher who signs (`helm package --sign`) publishes `<chart>.tgz.prov` beside the
archive: an OpenPGP cleartext signature over the chart's Chart.yaml, a `...` line, and the
archive's SHA-256 keyed by its file name (helm `pkg/provenance/sign.go`, `messageBlock`):

    name: cert-manager
    version: v1.21.2
    ...
    files:
      cert-manager-v1.21.2.tgz: sha256:73a56e17...

Over HTTPS it is fetched from the archive URL the repository's index.yaml lists, plus `.prov`; in
an OCI registry it is the manifest's layer of media type
`application/vnd.cncf.helm.chart.provenance.v1.prov` (helm `pkg/registry/constants.go`). The
check is Helm's own (`Signatory.Verify`): the signature must verify against the operator's keyring
(`intel.openpgp`), and the `files` entry for the archive's file name -- the URL's base name, or
`<name>-<version>.tgz` for OCI, as `ChartDownloader` names it -- must be the archive's SHA-256: the
one vendored in charts/ where the project pinned it, else the OCI chart layer's digest, else the
archive's own bytes, downloaded and hashed. A genuine signature over another archive does not pass.

Bounded and honest about what it cannot answer: a chart from a repository named only (`@name`) or
from the project's own tree has no repository to ask; no `.prov` means the publisher does not
sign. Network use is the scan's `--online` only, over HTTPS.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from cordon_scanner.intel import openpgp

#: helm `pkg/registry/constants.go`: ProvLayerMediaType, and ChartLayerMediaType with the
#: LegacyChartLayerMediaType older charts were pushed with.
PROVENANCE_LAYER: Final = "application/vnd.cncf.helm.chart.provenance.v1.prov"
CHART_LAYERS: Final = frozenset(
    {"application/vnd.cncf.helm.chart.content.v1.tar+gzip", "application/tar+gzip"}
)
TIMEOUT: Final = 15.0
MAX_PROV_BYTES: Final = 1 << 20
MAX_CHART_BYTES: Final = 32 << 20
"""cert-manager's chart is 150 KB."""
MAX_INDEX_BYTES: Final = 64 << 20
"""An index.yaml lists every version of every chart: Bitnami's was 27.5 MB in October 2026."""
MAX_REDIRECTS: Final = 5


class _HttpsRedirects(urllib.request.HTTPRedirectHandler):
    """A release asset redirects to storage: followed over HTTPS only, a few hops at most."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if urllib.parse.urlsplit(newurl).scheme != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class ChartCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable`, `unconfigured` (signed; no keyring) or `absent`."""
    detail: str


class HelmProvenance:
    @staticmethod
    def _get(url: str, limit: int) -> bytes | None:
        """The body, or None where the server has no such file."""
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("not https")
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - https only
        opener = urllib.request.build_opener(_HttpsRedirects)
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                body: bytes = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404, 410):
                # A bucket without public listing answers 403 for a file it does not hold
                # (charts.bitnami.com and charts.gitlab.io do, for a .prov).
                return None
            raise
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    @staticmethod
    def signed_sums(signed: bytes) -> dict[str, str] | None:
        """The `files` the signed text lists, `{file name: "sha256:<hex>"}`, read as helm's
        `ParseMessageBlock` reads it: split at every `\\n...\\n`, the second part's YAML."""
        from cordon_scanner.core.datayaml import DataYaml

        parts = signed.decode("utf-8", "replace").split("\n...\n")
        if len(parts) < 2:
            return None
        try:
            sums = DataYaml.load(parts[1], source="files")
        except ValueError:
            return None
        files = sums.get("files") if isinstance(sums, dict) else None
        if not isinstance(files, dict):
            return None
        return {str(name): str(value) for name, value in files.items()}

    @staticmethod
    def _https(
        name: str, version: str, source: str
    ) -> tuple[bytes | None, str, str | None] | ChartCheck:
        """`(provenance file, archive name, archive URL)` from an HTTPS repository: the archive is
        downloaded only once the signature has passed, and only where nothing pinned its hash."""
        from cordon_scanner.core.datayaml import DataYaml

        base = source.rstrip("/") + "/"
        index_body = HelmProvenance._get(urllib.parse.urljoin(base, "index.yaml"), MAX_INDEX_BYTES)
        if index_body is None:
            return ChartCheck("unverifiable", f"{source} serves no index.yaml")
        try:
            index = DataYaml.load(index_body.decode("utf-8", "replace"), source="index.yaml")
        except ValueError:
            return ChartCheck("unverifiable", f"{source}'s index.yaml did not parse")
        entries = (index.get("entries") or {}) if isinstance(index, dict) else {}
        listed = entries.get(name) if isinstance(entries, dict) else None
        entry = next(
            (e for e in listed or () if isinstance(e, dict) and str(e.get("version")) == version),
            None,
        )
        urls = entry.get("urls") if entry else None
        if not isinstance(urls, list) or not urls or not isinstance(urls[0], str):
            return ChartCheck("unverifiable", f"{source}'s index.yaml lists no {name} {version}")
        archive_url = urllib.parse.urljoin(base, urls[0])
        if urllib.parse.urlsplit(archive_url).scheme != "https":
            return ChartCheck(
                "unverifiable",
                f"the repository serves {name} {version} over plain HTTP ({archive_url}), which "
                "this does not fetch",
            )
        archive_name = urllib.parse.urlsplit(archive_url).path.rsplit("/", 1)[-1]
        return HelmProvenance._get(archive_url + ".prov", MAX_PROV_BYTES), archive_name, archive_url

    @staticmethod
    def _oci(
        name: str, version: str, source: str
    ) -> tuple[bytes | None, str, str | None] | ChartCheck:
        """`(provenance layer, archive name, chart layer sha256)` from an OCI registry: the layer is
        content-addressed, so its digest is the archive's SHA-256."""
        from cordon_scanner.intel.more_registries import MoreRegistries

        host, _, path = source.removeprefix("oci://").partition("/")
        if not re.fullmatch(r"[a-z0-9.\-]+(?::\d+)?", host) or ".." in path:
            return ChartCheck("unverifiable", f"{source} is not an OCI registry reference")
        repository = f"{path.strip('/')}/{name}" if path.strip("/") else name
        base_url = f"https://{host}/v2/{repository}"
        manifest = MoreRegistries._oci(
            # helm `pkg/registry/reference.go`: a `+` in a version is `_` in its OCI tag.
            f"{base_url}/manifests/{urllib.parse.quote(version.replace('+', '_'), safe='-._')}",
            "application/vnd.oci.image.manifest.v1+json",
        )
        layers = [
            layer
            for layer in (manifest.get("layers") if isinstance(manifest, dict) else None) or ()
            if isinstance(layer, dict) and isinstance(layer.get("digest"), str)
        ]
        chart = next((x["digest"] for x in layers if x.get("mediaType") in CHART_LAYERS), None)
        prov = next((x["digest"] for x in layers if x.get("mediaType") == PROVENANCE_LAYER), None)
        if not isinstance(chart, str) or not chart.startswith("sha256:"):
            return ChartCheck("unverifiable", f"{host}/{repository}:{version} has no chart layer")
        if prov is None:
            return None, f"{name}-{version}.tgz", chart.removeprefix("sha256:")
        # A blob is content-addressed: _oci_blob refuses bytes that do not hash to its digest.
        return (
            MoreRegistries._oci_blob(base_url, prov),
            f"{name}-{version}.tgz",
            chart.removeprefix("sha256:"),
        )

    @staticmethod
    def check(
        name: str,
        version: str,
        source: str | None,
        integrity: str | None,
        keyring: openpgp.Keyring,
    ) -> ChartCheck:
        """The chart's provenance file: signed by a trusted key, about this chart and archive."""
        from cordon_scanner.intel import attest
        from cordon_scanner.intel.registry_client import PackageNotFound, RegistryError

        label = f"{name} {version}"
        if not source or not source.startswith(("https://", "oci://")):
            return ChartCheck("absent", f"{label} has no repository to ask")
        pin = attest.AttestationDocuments.parse_integrity(integrity)
        pinned = pin[1] if pin and pin[0] == "sha256" else None
        try:
            found = (
                HelmProvenance._oci(name, version, source)
                if source.startswith("oci://")
                else HelmProvenance._https(name, version, source)
            )
        except PackageNotFound:
            return ChartCheck("unverifiable", f"the repository does not hold {label}")
        except (
            RegistryError,
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
            ValueError,
        ) as exc:
            return ChartCheck(
                "unverifiable", f"the chart repository could not be read ({type(exc).__name__})"
            )
        if isinstance(found, ChartCheck):
            return found
        # `located`: the chart layer's SHA-256 for an OCI chart, the archive's URL over HTTPS.
        provenance, archive_name, located = found
        if provenance is None:
            return ChartCheck("absent", f"{label} is published without a provenance file")
        if not keyring and not keyring.paths:
            return ChartCheck(
                "unconfigured",
                f"{label} is signed (a .prov file), but no keyring is configured to verify it "
                "against (--keyring)",
            )
        verified = openpgp.OpenPgp.verify(provenance, keyring)
        if verified.outcome is not openpgp.Outcome.VERIFIED:
            return ChartCheck(str(verified.outcome), f"its provenance file: {verified.detail}")
        # From here on, each failure is one `Signatory.Verify` fails on too. Helm's OpenPGP library
        # judges the signing key as it stands now (go-crypto `checkMessageSignatureDetails`,
        # `KeyExpired(..., config.Now())`), so a key expired since it signed is refused.
        if verified.expires is not None and verified.expires <= datetime.now(UTC):
            return ChartCheck(
                "invalid",
                f"its provenance file is signed by {verified.signer}, a key that expired on "
                f"{verified.expires:%Y-%m-%d}; helm refuses it (ErrKeyExpired)",
            )
        sums = HelmProvenance.signed_sums(verified.signed)
        if sums is None:
            return ChartCheck("invalid", "the signed provenance has no file checksums")
        signed_sum = sums.get(archive_name)
        if signed_sum is None:
            return ChartCheck(
                "invalid", f"the signed provenance has no SHA-256 for a file named {archive_name}"
            )
        expected = pinned or (located if source.startswith("oci://") else None)
        if expected is None and located:
            try:
                archive = HelmProvenance._get(located, MAX_CHART_BYTES)
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                return ChartCheck(
                    "unverifiable", f"{located} could not be downloaded ({type(exc).__name__})"
                )
            if archive is None:
                return ChartCheck("unverifiable", f"{located} could not be downloaded")
            expected = hashlib.sha256(archive).hexdigest()
        if expected is None:
            return ChartCheck("unverifiable", f"no SHA-256 of {archive_name} to compare")
        if signed_sum != f"sha256:{expected}":
            return ChartCheck(
                "invalid",
                f"the signed SHA-256 of {archive_name} is not the archive's "
                f"({'pinned in charts/' if pinned else 'as served'})",
            )
        return ChartCheck("verified", f"{label}: {verified.detail}, over the archive's SHA-256")


__all__ = ["ChartCheck", "HelmProvenance"]
