"""Terraform providers' signed checksums (`intel/terraform_provenance`), checked as `terraform init` checks them.

Offline: the registry is stood in for; the registry's download answer, the `SHA256SUMS` file, its detached signature and the
signing key are the real ones for hashicorp/random 3.6.3 (`terraform/`, fetched from registry.terraform.io and
releases.hashicorp.com on 2026-11-25), so the signature check is the real one. What is tested is everything around it: which
key vouches, the locked zip hash against the signed lines, and what each failure is called."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.intel.provenance import openpgp
from cordon_scanner.intel.provenance.terraform_provenance import TerraformProvenance
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "terraform"
ANSWER: dict[str, Any] = json.loads((DATA / "download.json").read_text(encoding="utf-8"))
SUMS = (DATA / "SHA256SUMS").read_bytes()
SIGNATURE = (DATA / "SHA256SUMS.sig").read_bytes()
LOCKED = "zh:" + SUMS.decode().splitlines()[0].split()[0]
NAME, VERSION = "hashicorp/random", "3.6.3"


class Registry:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        answer: dict[str, Any] | None = None,
        sums: bytes | None = SUMS,
        signature: bytes | None = SIGNATURE,
        down: bool = False,
    ) -> None:
        self.answer = answer if answer is not None else ANSWER
        self.asked: list[str] = []

        def get(url: str, limit: int) -> bytes | None:
            self.asked.append(url)
            if down:
                raise OSError("unreachable")
            if url.startswith("https://registry.terraform.io/"):
                return json.dumps(self.answer).encode()
            if url == self.answer.get("shasums_url"):
                return sums
            if url == self.answer.get("shasums_signature_url"):
                return signature
            return None

        monkeypatch.setattr(TerraformProvenance, "_get", staticmethod(get))


class Keyrings:
    @staticmethod
    def of_registry_key(tmp_path: Path) -> openpgp.Keyring:
        """The operator trusts the key HashiCorp registered: the one the registry serves."""
        armor = ANSWER["signing_keys"]["gpg_public_keys"][0]["ascii_armor"]
        path = tmp_path / "hashicorp.asc"
        path.write_text(armor, encoding="utf-8")
        return openpgp.OpenPgp.load((str(path),))


class TestASignedReleaseTheOperatorTrusts:
    def test_it_is_verified_and_says_what_it_covers(self, monkeypatch, tmp_path) -> None:
        Registry(monkeypatch)
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, Keyrings.of_registry_key(tmp_path))
        assert check.outcome == "verified" and "lists the locked zip" in check.detail

    def test_the_registry_is_asked_for_the_release_and_nothing_else_of_it(
        self, monkeypatch, tmp_path
    ) -> None:
        registry = Registry(monkeypatch)
        TerraformProvenance.check(NAME, VERSION, LOCKED, Keyrings.of_registry_key(tmp_path))
        assert registry.asked[0].endswith("/hashicorp/random/3.6.3/download/linux/amd64")
        assert len(registry.asked) == 3 and all(
            url.startswith("https://") for url in registry.asked
        )


class TestASignatureOnlyTheRegistryVouchesFor:
    def test_it_is_not_called_verified(self, monkeypatch) -> None:
        Registry(monkeypatch)
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring())
        assert check.outcome == "unconfigured"
        assert "which the registry serves" in check.detail and "--keyring" in check.detail


class TestWhatIsRefused:
    def test_checksums_edited_after_signing(self, monkeypatch, tmp_path) -> None:
        Registry(monkeypatch, sums=SUMS.replace(b"a", b"b", 1))
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, Keyrings.of_registry_key(tmp_path))
        assert check.outcome == "invalid" and "does not verify" in check.detail

    def test_a_locked_zip_the_signed_list_does_not_hold(self, monkeypatch, tmp_path) -> None:
        Registry(monkeypatch)
        other = "zh:" + "0" * 64
        check = TerraformProvenance.check(NAME, VERSION, other, Keyrings.of_registry_key(tmp_path))
        assert check.outcome == "invalid" and "no line of the signed checksums" in check.detail

    def test_a_signature_by_a_key_the_operator_does_not_hold_and_the_registry_does_not_serve(
        self, monkeypatch, tmp_path
    ) -> None:
        stripped = {**ANSWER, "signing_keys": {"gpg_public_keys": []}}
        Registry(monkeypatch, answer=stripped)
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, Keyrings.of_registry_key(tmp_path))
        assert check.outcome == "verified"  # the operator's own keyring holds the signer
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring())
        assert check.outcome == "invalid"

    def test_a_registry_checksum_that_the_signed_list_does_not_hold(
        self, monkeypatch, tmp_path
    ) -> None:
        Registry(monkeypatch, answer={**ANSWER, "shasum": "f" * 64})
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, Keyrings.of_registry_key(tmp_path))
        assert check.outcome == "invalid" and "registry's own checksum" in check.detail


class TestWhatCannotBeAnswered:
    def test_a_lock_that_pins_only_the_package_hash(self, monkeypatch, tmp_path) -> None:
        Registry(monkeypatch)
        check = TerraformProvenance.check(
            NAME, VERSION, "h1:abc=", Keyrings.of_registry_key(tmp_path)
        )
        assert check.outcome == "unverifiable" and "no zip hash" in check.detail

    def test_a_release_with_no_signature_file(self, monkeypatch) -> None:
        stripped = {k: v for k, v in ANSWER.items() if k != "shasums_signature_url"}
        Registry(monkeypatch, answer=stripped)
        assert (
            TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring()).outcome == "absent"
        )

    def test_a_signature_file_the_host_does_not_hold(self, monkeypatch) -> None:
        Registry(monkeypatch, signature=None)
        assert (
            TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring()).outcome == "absent"
        )

    def test_a_release_the_registry_does_not_hold(self, monkeypatch) -> None:
        monkeypatch.setattr(TerraformProvenance, "_get", staticmethod(lambda url, limit: None))
        check = TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring())
        assert check.outcome == "unverifiable" and "does not hold" in check.detail

    def test_a_registry_that_cannot_be_reached(self, monkeypatch) -> None:
        Registry(monkeypatch, down=True)
        assert (
            TerraformProvenance.check(NAME, VERSION, LOCKED, openpgp.Keyring()).outcome
            == "unverifiable"
        )

    @pytest.mark.parametrize("name", ["random", "a/b/c", "Hashi Corp/random", "../x/y", ""])
    def test_an_address_that_is_not_a_provider_is_not_asked(self, monkeypatch, name: str) -> None:
        registry = Registry(monkeypatch)
        assert (
            TerraformProvenance.check(name, VERSION, LOCKED, openpgp.Keyring()).outcome
            == "unverifiable"
        )
        assert registry.asked == []

    @pytest.mark.parametrize("version", ["", "../1", "1 2", "1/2"])
    def test_a_version_the_registry_cannot_serve_is_not_asked(
        self, monkeypatch, version: str
    ) -> None:
        registry = Registry(monkeypatch)
        assert (
            TerraformProvenance.check(NAME, version, LOCKED, openpgp.Keyring()).outcome
            == "unverifiable"
        )
        assert registry.asked == []


class TestTheSignedSums:
    def test_a_line_that_is_not_a_sum_refuses_the_file(self) -> None:
        assert TerraformProvenance.signed_sums(b"not a sum line\n") is None

    def test_the_real_file_lists_each_platform(self) -> None:
        sums = TerraformProvenance.signed_sums(SUMS)
        assert sums is not None and len(sums) >= 10
