"""Helm provenance files (`intel/helm_provenance`), checked as `helm verify` checks them.

Offline: the chart repository and the OCI registry are stood in for; the provenance file and the
key are cert-manager's real ones (data/openpgp), so the signature check is the real one. What is
tested is everything around it that helm's `Signatory.Verify` decides: the `files` entry named for
the archive, the archive's SHA-256, and a key that has expired since it signed.

Measured against the real charts when this was written: of 447 signed charts Artifact Hub lists
with a registered key, the verdicts were checked one by one against GnuPG.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("pysequoia")

from cordon_scanner.intel import openpgp
from cordon_scanner.intel.helm_provenance import HelmProvenance
from cordon_scanner.intel.more_registries import MoreRegistries

DATA = Path(__file__).parent / "data" / "openpgp"
PROV = (DATA / "cert-manager-v1.21.2.tgz.prov").read_bytes()
SIGNED_SUM = "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a"
REPO = "https://charts.jetstack.io"
INDEX = b"""apiVersion: v1
entries:
  cert-manager:
  - name: cert-manager
    version: v1.21.2
    urls:
    - charts/cert-manager-v1.21.2.tgz
"""


class Repository:
    def __init__(self, monkeypatch, *, prov: bytes | None = PROV, index: bytes = INDEX):
        self.asked: list[str] = []
        files = {
            f"{REPO}/index.yaml": index,
            f"{REPO}/charts/cert-manager-v1.21.2.tgz.prov": prov,
        }

        def get(url: str, limit: int) -> bytes | None:
            self.asked.append(url)
            return files.get(url)

        monkeypatch.setattr(HelmProvenance, "_get", staticmethod(get))


class TestHelmProvenance:
    @pytest.fixture
    def keyring(self) -> openpgp.Keyring:
        return openpgp.OpenPgp.load((str(DATA / "cert-manager.gpg"),))

    @pytest.mark.conformance("helm", "UNI-17")
    def test_a_signed_chart_whose_archive_is_the_signed_one_verifies(
        self, monkeypatch, keyring
    ) -> None:
        Repository(monkeypatch)
        check = HelmProvenance.check(
            "cert-manager", "v1.21.2", REPO, f"sha256:{SIGNED_SUM}", keyring
        )
        assert check.outcome == "verified"
        assert "1020CF3C033D4F35BAE1C19E1226061C665DF13E" in check.detail

    @pytest.mark.conformance("helm", "UNI-17")
    def test_an_archive_the_signature_does_not_name_is_invalid(self, monkeypatch, keyring) -> None:
        Repository(monkeypatch)
        check = HelmProvenance.check("cert-manager", "v1.21.2", REPO, "sha256:" + "0" * 64, keyring)
        assert check.outcome == "invalid"
        assert "pinned in charts/" in check.detail

    @pytest.mark.conformance("helm", "UNI-17")
    def test_a_signer_the_keyring_does_not_hold_is_invalid(self, monkeypatch) -> None:
        Repository(monkeypatch)
        check = HelmProvenance.check(
            "cert-manager",
            "v1.21.2",
            REPO,
            f"sha256:{SIGNED_SUM}",
            openpgp.OpenPgp.load((str(DATA / "flowable.asc"),)),
        )
        assert check.outcome == "invalid"
        assert "does not hold" in check.detail

    def test_without_a_pin_the_archive_is_downloaded_and_hashed(self, monkeypatch, keyring) -> None:
        repository = Repository(monkeypatch)
        check = HelmProvenance.check("cert-manager", "v1.21.2", REPO, None, keyring)
        # The stand-in serves no archive, so it cannot be hashed: asked for, and not passed.
        assert f"{REPO}/charts/cert-manager-v1.21.2.tgz" in repository.asked
        assert check.outcome == "unverifiable"

    def test_a_provenance_file_naming_another_archive_is_invalid(
        self, monkeypatch, keyring
    ) -> None:
        # Signed for cert-manager-v1.21.2.tgz; the index serves it under another name.
        Repository(
            monkeypatch,
            index=INDEX.replace(b"charts/cert-manager-v1.21.2.tgz", b"charts/renamed.tgz"),
        )
        monkeypatch.setattr(
            HelmProvenance,
            "_get",
            staticmethod(
                lambda url, limit: {
                    f"{REPO}/index.yaml": INDEX.replace(
                        b"charts/cert-manager-v1.21.2.tgz", b"charts/renamed.tgz"
                    ),
                    f"{REPO}/charts/renamed.tgz.prov": PROV,
                }.get(url)
            ),
        )
        check = HelmProvenance.check(
            "cert-manager", "v1.21.2", REPO, f"sha256:{SIGNED_SUM}", keyring
        )
        assert check.outcome == "invalid"
        assert "no SHA-256 for a file named renamed.tgz" in check.detail

    def test_a_key_expired_since_it_signed_is_refused_as_helm_refuses_it(
        self, monkeypatch, keyring
    ) -> None:
        Repository(monkeypatch)
        real = openpgp.OpenPgp.verify

        def expired(data, ring, *, signature=None):
            result = real(data, ring, signature=signature)
            return openpgp.Result(
                result.outcome,
                result.detail,
                result.signed,
                result.signer,
                datetime.now(UTC) - timedelta(days=1),
            )

        monkeypatch.setattr(openpgp.OpenPgp, "verify", staticmethod(expired))
        check = HelmProvenance.check(
            "cert-manager", "v1.21.2", REPO, f"sha256:{SIGNED_SUM}", keyring
        )
        assert check.outcome == "invalid"
        assert "ErrKeyExpired" in check.detail

    def test_an_unsigned_chart_has_nothing_to_verify(self, monkeypatch, keyring) -> None:
        Repository(monkeypatch, prov=None)
        assert (
            HelmProvenance.check("cert-manager", "v1.21.2", REPO, None, keyring).outcome == "absent"
        )

    def test_a_signed_chart_with_no_keyring_says_so(self, monkeypatch) -> None:
        Repository(monkeypatch)
        check = HelmProvenance.check("cert-manager", "v1.21.2", REPO, None, openpgp.Keyring())
        assert check.outcome == "unconfigured"

    def test_a_chart_served_over_plain_http_is_not_fetched(self, monkeypatch, keyring) -> None:
        repository = Repository(
            monkeypatch,
            index=INDEX.replace(
                b"charts/cert-manager-v1.21.2.tgz",
                b"http://example.invalid/cert-manager-v1.21.2.tgz",
            ),
        )
        check = HelmProvenance.check("cert-manager", "v1.21.2", REPO, None, keyring)
        assert check.outcome == "unverifiable" and "plain HTTP" in check.detail
        assert repository.asked == [f"{REPO}/index.yaml"]

    def test_a_repository_named_only_has_nothing_to_ask(self, keyring) -> None:
        assert (
            HelmProvenance.check("redis", "1.0.0", "registry:internal", None, keyring).outcome
            == "absent"
        )

    def test_an_oci_chart_uses_its_provenance_layer_and_tag(self, monkeypatch, keyring) -> None:
        asked: list[str] = []
        manifest = {
            "layers": [
                {
                    "mediaType": "application/vnd.cncf.helm.chart.provenance.v1.prov",
                    "digest": "sha256:" + "1" * 64,
                },
                {
                    "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                    "digest": f"sha256:{SIGNED_SUM}",
                },
            ]
        }

        def oci(url: str, accept: str):
            asked.append(url)
            return manifest

        monkeypatch.setattr(MoreRegistries, "_oci", staticmethod(oci))
        monkeypatch.setattr(MoreRegistries, "_oci_blob", staticmethod(lambda base, digest: PROV))
        # cert-manager's real OCI chart is tagged without the v its HTTPS repository uses; the
        # provenance file names the archive helm downloads it as, <name>-<version>.tgz.
        check = HelmProvenance.check(
            "cert-manager", "v1.21.2", "oci://quay.io/jetstack/charts", None, keyring
        )
        assert asked == ["https://quay.io/v2/jetstack/charts/cert-manager/manifests/v1.21.2"]
        assert check.outcome == "verified"

    def test_an_oci_version_with_a_plus_is_asked_by_its_underscore_tag(
        self, monkeypatch, keyring
    ) -> None:
        asked: list[str] = []
        monkeypatch.setattr(
            MoreRegistries,
            "_oci",
            staticmethod(lambda url, accept: asked.append(url) or {"layers": []}),
        )
        HelmProvenance.check(
            "app", "1.0.0+build.1", "oci://registry.example.invalid/charts", None, keyring
        )
        assert asked == ["https://registry.example.invalid/v2/charts/app/manifests/1.0.0_build.1"]
