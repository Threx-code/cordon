"""Ansible collections' signatures (`intel/ansible_signatures`), checked as `ansible-galaxy` checks
them.

The data (data/ansible_signatures) is a collection built by `ansible-galaxy collection build`, its
MANIFEST.json signed with throwaway keys by GnuPG: one the keyring holds, one it does not, and one
that expired three seconds after it signed. Run through `ansible-galaxy collection verify
--offline --keyring` when this was written, the four verdicts below (verified; tampered, stranger
and expired failing) were the ones ansible-core 2.19 gave.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.error
from pathlib import Path

import pytest

pytest.importorskip("pysequoia")

from cordon_scanner.core.content import FileContent
from cordon_scanner.ecosystems.ansible import AnsibleGalaxyEcosystem
from cordon_scanner.intel import openpgp
from cordon_scanner.intel.ansible_signatures import VERSION, AnsibleSignatures

DATA = Path(__file__).parent / "data" / "ansible_signatures"
MANIFEST = (DATA / "MANIFEST.json").read_bytes()
TRUSTED = (DATA / "trusted.asc").read_text(encoding="utf-8")
STRANGER = (DATA / "stranger.asc").read_text(encoding="utf-8")
EXPIRED = (DATA / "expired.asc").read_text(encoding="utf-8")
RECORD_URL = VERSION.format(ns="demo", name="signed", v="1.0.0")
ARTIFACT_URL = "https://galaxy.ansible.com/api/v3/artifacts/demo-signed-1.0.0.tar.gz"


class Galaxy:
    """galaxy.ansible.com and the signature URLs, stood in: what each URL serves."""

    @staticmethod
    def artifact(manifest: bytes = MANIFEST) -> bytes:
        """A collection artifact holding only this MANIFEST.json."""
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            member = tarfile.TarInfo("MANIFEST.json")
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
        return out.getvalue()

    def __init__(self, monkeypatch, *, signatures: list[str], body: bytes | None = None) -> None:
        body = Galaxy.artifact() if body is None else body
        self.asked: list[str] = []
        self.files: dict[str, bytes] = {
            RECORD_URL: json.dumps(
                {
                    "signatures": [{"signature": s} for s in signatures],
                    "download_url": ARTIFACT_URL,
                    "artifact": {"sha256": hashlib.sha256(Galaxy.artifact()).hexdigest()},
                }
            ).encode(),
            ARTIFACT_URL: body,
        }

        def get(url: str, limit: int) -> bytes:
            self.asked.append(url)
            if url not in self.files:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
            return self.files[url]

        monkeypatch.setattr(AnsibleSignatures, "_get", staticmethod(get))


class TestInstalled:
    @pytest.fixture
    def keyring(self) -> openpgp.Keyring:
        return openpgp.OpenPgp.load((str(DATA / "keyring.asc"),))

    @pytest.mark.conformance("ansible", "UNI-17")
    def test_a_signature_by_a_key_the_keyring_holds_verifies(self, keyring) -> None:
        check = AnsibleSignatures.installed("demo.signed", "1.0.0", MANIFEST, (TRUSTED,), keyring)
        assert check.outcome == "verified"

    def test_a_manifest_changed_after_it_was_signed_is_invalid(self, keyring) -> None:
        changed = MANIFEST.replace(b'"README.md"', b'"README.txt"')
        assert changed != MANIFEST
        check = AnsibleSignatures.installed("demo.signed", "1.0.0", changed, (TRUSTED,), keyring)
        assert check.outcome == "invalid"

    def test_a_signer_the_keyring_does_not_hold_fails_as_no_pubkey_does(self, keyring) -> None:
        check = AnsibleSignatures.installed("demo.signed", "1.0.0", MANIFEST, (STRANGER,), keyring)
        assert check.outcome != "verified"
        assert "does not hold" in check.detail

    def test_a_key_that_has_expired_fails_as_expkeysig_does(self, keyring) -> None:
        check = AnsibleSignatures.installed("demo.signed", "1.0.0", MANIFEST, (EXPIRED,), keyring)
        assert check.outcome == "invalid"
        assert "EXPKEYSIG" in check.detail

    def test_one_good_signature_among_failing_ones_is_enough(self, keyring) -> None:
        # GALAXY_REQUIRED_VALID_SIGNATURE_COUNT defaults to 1.
        check = AnsibleSignatures.installed(
            "demo.signed", "1.0.0", MANIFEST, (STRANGER, EXPIRED, TRUSTED), keyring
        )
        assert check.outcome == "verified"

    def test_a_signed_collection_with_no_keyring_says_so(self) -> None:
        check = AnsibleSignatures.installed(
            "demo.signed", "1.0.0", MANIFEST, (TRUSTED,), openpgp.Keyring()
        )
        assert check.outcome == "unconfigured"


class TestRemote:
    @pytest.fixture
    def keyring(self) -> openpgp.Keyring:
        return openpgp.OpenPgp.load((str(DATA / "keyring.asc"),))

    def test_galaxys_signature_is_checked_over_the_artifacts_manifest(
        self, monkeypatch, keyring
    ) -> None:
        galaxy = Galaxy(monkeypatch, signatures=[TRUSTED])
        assert AnsibleSignatures.remote("demo.signed", "1.0.0", (), keyring).outcome == "verified"
        assert galaxy.asked == [RECORD_URL, ARTIFACT_URL]

    def test_a_requirements_signature_url_is_fetched_and_counted(
        self, monkeypatch, keyring
    ) -> None:
        galaxy = Galaxy(monkeypatch, signatures=[])
        galaxy.files["https://signatures.example.invalid/demo.asc"] = TRUSTED.encode()
        check = AnsibleSignatures.remote(
            "demo.signed", "1.0.0", ("https://signatures.example.invalid/demo.asc",), keyring
        )
        assert check.outcome == "verified"

    def test_an_artifact_that_is_not_the_one_galaxy_hashed_is_invalid(
        self, monkeypatch, keyring
    ) -> None:
        Galaxy(monkeypatch, signatures=[TRUSTED], body=Galaxy.artifact(MANIFEST + b"\n"))
        check = AnsibleSignatures.remote("demo.signed", "1.0.0", (), keyring)
        assert check.outcome == "invalid"
        assert "SHA-256" in check.detail

    def test_an_unsigned_collection_downloads_nothing(self, monkeypatch, keyring) -> None:
        galaxy = Galaxy(monkeypatch, signatures=[])
        assert AnsibleSignatures.remote("demo.signed", "1.0.0", (), keyring).outcome == "absent"
        assert galaxy.asked == [RECORD_URL]

    def test_a_name_galaxy_does_not_hold_is_absent(self, monkeypatch, keyring) -> None:
        # A role is named `namespace.name` too; the collection index answers 404 for it.
        Galaxy(monkeypatch, signatures=[])
        assert (
            AnsibleSignatures.remote("geerlingguy.java", "2.0.0", (), keyring).outcome == "absent"
        )

    def test_a_signature_on_the_installing_machine_cannot_be_read(
        self, monkeypatch, keyring
    ) -> None:
        Galaxy(monkeypatch, signatures=[])
        check = AnsibleSignatures.remote("demo.signed", "1.0.0", ("/etc/sigs/demo.asc",), keyring)
        assert check.outcome == "unverifiable"

    def test_a_signature_url_over_plain_http_is_not_fetched(self, monkeypatch, keyring) -> None:
        galaxy = Galaxy(monkeypatch, signatures=[])
        check = AnsibleSignatures.remote(
            "demo.signed", "1.0.0", ("http://signatures.example.invalid/demo.asc",), keyring
        )
        assert check.outcome == "unverifiable"
        assert galaxy.asked == [RECORD_URL]


class TestTheInstalledRecord:
    """The reader pairs an installed collection's MANIFEST.json with what its install recorded in
    `ansible_collections/<ns>.<name>-<version>.info/GALAXY.yml`."""

    @staticmethod
    def files(galaxy_yml: str | None) -> dict[str, FileContent]:
        out = {
            "collections/ansible_collections/demo/signed/MANIFEST.json": FileContent.from_bytes(
                "collections/ansible_collections/demo/signed/MANIFEST.json", MANIFEST
            )
        }
        if galaxy_yml is not None:
            path = "collections/ansible_collections/demo.signed-1.0.0.info/GALAXY.yml"
            out[path] = FileContent.from_bytes(path, galaxy_yml.encode())
        return out

    def entry(self, galaxy_yml: str | None):
        files = self.files(galaxy_yml)
        manifest = files["collections/ansible_collections/demo/signed/MANIFEST.json"]
        graph = AnsibleGalaxyEcosystem().parse_lockfile_in_tree(manifest, files)
        assert graph.parse_error is None
        return graph.entries[0]

    def test_recorded_signatures_are_carried_with_the_bytes_they_cover(self) -> None:
        indented = "\n".join("      " + line for line in TRUSTED.splitlines())
        entry = self.entry(
            "format_version: 1.0.0\nsignatures:\n  - pubkey_fingerprint: ''\n"
            f"    signature: |\n{indented}\nversion: 1.0.0\n"
        )
        assert entry.signatures == (TRUSTED.rstrip("\n") + "\n",)
        assert entry.signed == MANIFEST

    def test_without_a_record_or_with_no_signatures_nothing_is_carried(self) -> None:
        assert self.entry(None).signatures == ()
        assert self.entry("format_version: 1.0.0\nsignatures: []\n").signatures == ()
        assert self.entry("signatures: [\n").signatures == ()

    def test_a_requirements_collections_signature_urls_are_its_sources(self) -> None:
        text = (
            "collections:\n  - name: demo.signed\n    version: 1.0.0\n    signatures:\n"
            "      - https://signatures.example.invalid/demo.asc\n"
            "  - name: demo.single\n    signatures: https://signatures.example.invalid/one.asc\n"
            "roles:\n  - name: geerlingguy.java\n    signatures: [https://x.example.invalid/r]\n"
        )
        manifest = AnsibleGalaxyEcosystem().parse_manifest(
            FileContent.from_bytes("requirements.yml", text.encode())
        )
        assert {d.name: d.signature_sources for d in manifest.dependencies} == {
            "demo.signed": ("https://signatures.example.invalid/demo.asc",),
            "demo.single": ("https://signatures.example.invalid/one.asc",),
            "geerlingguy.java": (),
        }
