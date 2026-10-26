"""OpenPGP verification (`intel/openpgp`, over `intel/pgp`), on real publishers' signatures and keys.

The files in data/openpgp are public: chart provenance files and their publishers' signing keys,
exactly as served in October 2026. Each was checked with GnuPG when it was added, and each is here
for what it showed:

    cert-manager    an RSA signature value of 4094 bits declared as 4096
    cisco-nso       a DSA `s` of 252 bits declared as 256
    flowable        both of the key's user ID certifications 4095 bits declared as 4096
    openfga         a key that expired in 2025, signing in 2026 (GnuPG: EXPKEYSIG)
    hivemq          a key whose only self-signature (2026) is later than the chart's signature
                    (2025)

GnuPG and Helm verify the first three and the last; Sequoia, which this replaced, refused all
four. data/ansible_signatures holds detached signatures GnuPG made over a collection manifest.
"""

from __future__ import annotations

import contextlib
import random
from pathlib import Path

import pytest

from cordon_scanner.intel.provenance.openpgp import Canonical, Keybox, OpenPgp, Outcome
from cordon_scanner.intel.provenance.pgp import Certs, Packets, PgpError, Signature
from support import ROOT as REPO

DATA = REPO / "tests" / "unit" / "data" / "openpgp"
ANSIBLE = REPO / "tests" / "unit" / "data" / "ansible_signatures"


class Files:
    @staticmethod
    def read(name: str) -> bytes:
        return (DATA / name).read_bytes()

    @staticmethod
    def packets(name: str) -> bytes:
        blocks = Canonical.blocks(Files.read(name), b"PUBLIC KEY BLOCK")
        return blocks[0] if blocks else Files.read(name)


class TestArmor:
    def test_crc24_of_nothing_is_its_initial_value(self) -> None:
        assert Canonical.crc24(b"") == 0xB704CE

    def test_armor_and_dearmor_are_inverse(self) -> None:
        data = bytes(range(256)) * 3
        assert Canonical.dearmor(Canonical.armor(data)) == data

    def test_a_block_with_a_wrong_checksum_is_not_read(self) -> None:
        raw = Files.read("cert-manager-v1.21.2.tgz.prov")
        block = raw[raw.index(b"-----BEGIN PGP SIGNATURE-----") :]
        assert Canonical.dearmor(block) is not None
        assert Canonical.dearmor(block.replace(b"=/4RL", b"=AAAA")) is None


class TestReadAsGnuPGReadsIt:
    @pytest.mark.parametrize("prov", ["cert-manager-v1.21.2.tgz.prov", "cisco-nso-7.6.1.tgz.prov"])
    def test_an_overstated_signature_value_is_the_value_it_is(self, prov: str) -> None:
        """The bit count is not hashed: a value with leading zero bits is the same value."""
        raw = Files.read(prov)
        block = Canonical.dearmor(raw[raw.index(b"-----BEGIN PGP SIGNATURE-----") :].strip())
        assert block is not None
        (tag, body), *_ = Packets.read(block)
        signature = Signature.parse(body)
        assert tag == 2 and signature.issuer_ids

    def test_a_key_whose_self_signatures_are_overstated_is_usable(self) -> None:
        keyring = OpenPgp.load((str(DATA / "flowable.asc"),))
        assert [k.fingerprint for k in keyring.keys] == ["B3B09108406A7DFE92757807A79624786AE252EB"]
        assert keyring.keys[0].cert.expiration() is not None


class TestKeyring:
    def test_concatenated_armored_exports_are_one_keyring(self, tmp_path: Path) -> None:
        both = tmp_path / "ring.asc"
        both.write_bytes(Files.read("flowable.asc") + Files.read("leocolomb.asc"))
        assert len(OpenPgp.load((str(both),)).keys) == 2

    def test_a_gnupg_keybox_is_read_as_helm_reads_it(self, tmp_path: Path) -> None:
        keyblock = Certs.split(Files.packets("cert-manager.gpg"))[0].packets

        def blob(kind: int, body: bytes, flags: int = 0) -> bytes:
            # u32 length, u8 type, u8 version, u16 flags, u32 offset, u32 length, then the keyblock.
            header = 16
            return (
                (header + len(body)).to_bytes(4, "big")
                + bytes([kind, 1])
                + flags.to_bytes(2, "big")
                + header.to_bytes(4, "big")
                + len(body).to_bytes(4, "big")
                + body
            )

        first = (32).to_bytes(4, "big") + bytes([1, 1, 0, 0]) + b"KBXf" + bytes(20)
        kbx = tmp_path / "pubring.kbx"
        # The OpenPGP blob, then an ephemeral one GnuPG and Helm skip.
        kbx.write_bytes(first + blob(2, keyblock) + blob(2, b"x", 0x0002))
        assert Keybox.detect(kbx.read_bytes())
        keyring = OpenPgp.load((str(kbx),))
        assert [k.fingerprint for k in keyring.keys] == ["1020CF3C033D4F35BAE1C19E1226061C665DF13E"]

    def test_a_malformed_keybox_is_a_problem_not_a_crash(self, tmp_path: Path) -> None:
        kbx = tmp_path / "pubring.kbx"
        kbx.write_bytes(
            (32).to_bytes(4, "big")
            + bytes([1, 1, 0, 0])
            + b"KBXf"
            + bytes(20)
            + b"\x00\x00\x00\xff\x02"
        )
        keyring = OpenPgp.load((str(kbx),))
        assert not keyring and keyring.problems

    def test_a_key_with_no_user_id_is_left_out_as_helm_leaves_it_out(self, tmp_path: Path) -> None:
        packets = Packets.read(Files.packets("leocolomb.asc"))
        bare = b"".join(
            bytes([0xC0 | tag, 0xFF]) + len(body).to_bytes(4, "big") + body
            for tag, body in packets
            if tag not in (2, 13)
        )
        path = tmp_path / "bare.gpg"
        path.write_bytes(bare)
        keyring = OpenPgp.load((str(path),))
        assert not keyring.keys
        assert "no user ID" in keyring.problems[0]
        result = OpenPgp.verify(Files.read("cisco-nso-7.6.1.tgz.prov"), keyring)
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "holds no usable key" in result.detail

    def test_hostile_bytes_are_refused_never_crash(self) -> None:
        rng = random.Random(4880)  # noqa: S311 -- a reproducible fuzz input, not a secret
        seed = Files.packets("cert-manager.gpg")
        for _ in range(300):
            data = bytearray(seed)
            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            with contextlib.suppress(PgpError):  # refused is the answer; anything else escapes
                Certs.split(bytes(data))


class TestVerify:
    @pytest.mark.parametrize(
        ("prov", "key", "fingerprint"),
        [
            (
                "cert-manager-v1.21.2.tgz.prov",
                "cert-manager.gpg",
                "1020CF3C033D4F35BAE1C19E1226061C665DF13E",
            ),
            (
                "cisco-nso-7.6.1.tgz.prov",
                "leocolomb.asc",
                "7D422B98DC0F24610C5807CBB9FDEEE84C92D2AA",
            ),
            ("flowable-7.1.0.tgz.prov", "flowable.asc", "B3B09108406A7DFE92757807A79624786AE252EB"),
        ],
    )
    def test_real_signatures_gnupg_accepts_verify(
        self, prov: str, key: str, fingerprint: str
    ) -> None:
        result = OpenPgp.verify(Files.read(prov), OpenPgp.load((str(DATA / key),)))
        assert result.outcome is Outcome.VERIFIED
        assert result.signer == fingerprint
        assert b"\n...\nfiles:\n" in result.signed

    def test_a_key_certified_after_it_signed_verifies_as_gnupg_and_helm_judge_it(self) -> None:
        """Judged as the key stands now, as Helm judges it: its current self-signature binds it."""
        result = OpenPgp.verify(
            Files.read("hivemq-operator-0.11.62.tgz.prov"),
            OpenPgp.load((str(DATA / "hivemq.asc"),)),
        )
        assert result.outcome is Outcome.VERIFIED

    def test_altered_content_under_a_trusted_key_is_invalid(self) -> None:
        tampered = Files.read("cert-manager-v1.21.2.tgz.prov").replace(
            b"sha256:73a5", b"sha256:73a6"
        )
        result = OpenPgp.verify(tampered, OpenPgp.load((str(DATA / "cert-manager.gpg"),)))
        assert result.outcome is Outcome.INVALID
        assert "altered" in result.detail

    def test_every_altered_line_of_a_signed_provenance_is_invalid(self) -> None:
        raw = Files.read("cisco-nso-7.6.1.tgz.prov")
        keyring = OpenPgp.load((str(DATA / "leocolomb.asc"),))
        text_end = raw.index(b"-----BEGIN PGP SIGNATURE-----")
        lines = raw[:text_end].split(b"\n")
        for i, line in enumerate(lines[3:-2], start=3):
            if not line.strip():
                continue
            changed = b"\n".join([*lines[:i], line + b"x", *lines[i + 1 :]]) + raw[text_end:]
            assert OpenPgp.verify(changed, keyring).outcome is Outcome.INVALID, i

    def test_a_signer_the_keyring_does_not_hold_is_invalid_and_named(self) -> None:
        result = OpenPgp.verify(
            Files.read("cert-manager-v1.21.2.tgz.prov"), OpenPgp.load((str(DATA / "flowable.asc"),))
        )
        assert result.outcome is Outcome.INVALID
        assert "1226061C665DF13E" in result.detail and "does not hold" in result.detail

    def test_a_key_expired_before_it_signed_is_invalid(self) -> None:
        result = OpenPgp.verify(
            Files.read("openfga-0.3.16.tgz.prov"), OpenPgp.load((str(DATA / "openfga.asc"),))
        )
        assert result.outcome is Outcome.INVALID
        assert "expired on 2025-03-13, before it made this signature on 2026-10-06" in result.detail

    def test_no_keyring_is_unverifiable(self) -> None:
        result = OpenPgp.verify(Files.read("cert-manager-v1.21.2.tgz.prov"), OpenPgp.load(()))
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "--keyring" in result.detail

    def test_a_detached_signature_verifies_and_is_bound_to_its_data(self) -> None:
        keyring = OpenPgp.load((str(ANSIBLE / "keyring.asc"),))
        manifest = (ANSIBLE / "MANIFEST.json").read_bytes()
        signature = (ANSIBLE / "trusted.asc").read_bytes()
        assert OpenPgp.verify(manifest, keyring, signature=signature).outcome is Outcome.VERIFIED
        assert (
            OpenPgp.verify(manifest + b" ", keyring, signature=signature).outcome is Outcome.INVALID
        )
