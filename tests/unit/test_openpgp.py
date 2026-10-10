"""OpenPGP verification (`intel/openpgp`), on real publishers' signatures and keys.

The files in data/openpgp are public: chart provenance files and their publishers' signing keys,
exactly as served in October 2026. Each was checked with GnuPG when it was added, and each is here
for what it showed:

    cert-manager    an RSA signature value of 4094 bits declared as 4096: Sequoia refused it
    cisco-nso       a DSA `s` of 252 bits declared as 256: the same, for DSA
    flowable        both of the key's user ID certifications 4095 bits declared as 4096: Sequoia
                    found no binding, so the key was unusable
    openfga         a key that expired in 2025, signing in 2026 (GnuPG: EXPKEYSIG)
    hivemq          a key whose only self-signature (2026) is later than the chart's signature
                    (2025): GnuPG and Helm accept it, Sequoia cannot judge it
"""

from __future__ import annotations

from pathlib import Path

import pytest

pysequoia = pytest.importorskip("pysequoia")

from cordon_scanner.intel.openpgp import Canonical, Keybox, OpenPgp, Outcome  # noqa: E402

DATA = Path(__file__).parent / "data" / "openpgp"


def read(name: str) -> bytes:
    return (DATA / name).read_bytes()


def signature_block(text: bytes) -> bytes:
    return text[text.index(b"-----BEGIN PGP SIGNATURE-----") :]


class TestCanonical:
    def test_crc24_of_nothing_is_its_initial_value(self) -> None:
        assert Canonical.crc24(b"") == 0xB704CE

    @pytest.mark.parametrize("prov", ["cert-manager-v1.21.2.tgz.prov", "cisco-nso-7.6.1.tgz.prov"])
    def test_an_overstated_value_is_what_sequoia_refuses_and_canonical_makes_readable(
        self, prov: str
    ) -> None:
        raw = read(prov)
        with pytest.raises(RuntimeError, match="Not a signature"):
            pysequoia.Sig.from_bytes(signature_block(raw))
        fixed = Canonical.signed(raw)
        assert pysequoia.Sig.from_bytes(signature_block(fixed)).issuer_key_id
        # The signed text is not touched, only the signature block.
        assert (
            fixed[: fixed.index(b"-----BEGIN PGP SIGNATURE-----")]
            == raw[: raw.index(b"-----BEGIN PGP SIGNATURE-----")]
        )

    def test_the_value_itself_is_kept(self) -> None:
        raw = Canonical.dearmor(signature_block(read("cert-manager-v1.21.2.tgz.prov")))
        assert raw is not None
        fixed = Canonical.packets(raw)
        value = lambda packets: int.from_bytes(packets[-512:], "big")  # noqa: E731
        assert fixed != raw and value(fixed) == value(raw)
        # Declared 4096, actual 4094: the header now says 4094.
        assert int.from_bytes(fixed[-514:-512], "big") == 4094

    def test_a_canonical_signature_is_returned_byte_for_byte(self) -> None:
        key = pysequoia.Tsk.generate("Test <test@example.invalid>")
        signed = pysequoia.sign(
            key.signer(), b"files:\n  a.tgz: sha256:00\n", mode=pysequoia.SignatureMode.CLEAR
        )
        assert Canonical.signed(signed) == signed

    def test_a_block_with_a_wrong_checksum_is_left_alone(self) -> None:
        raw = read("cert-manager-v1.21.2.tgz.prov")
        broken = raw.replace(b"=/4RL", b"=AAAA")
        assert Canonical.signed(broken) == broken

    def test_not_openpgp_at_all_is_returned_unchanged(self) -> None:
        assert Canonical.packets(b"\x00not packets") == b"\x00not packets"
        assert Canonical.signed(b"plain text") == b"plain text"


class TestKeyring:
    def test_a_key_whose_self_signatures_are_overstated_is_made_usable(self) -> None:
        raw = read("flowable.asc")
        with pytest.raises(RuntimeError, match="No binding signature"):
            _ = pysequoia.Cert.split_bytes(raw)[0].expiration
        keyring = OpenPgp.load((str(DATA / "flowable.asc"),))
        assert [k.fingerprint for k in keyring.keys] == ["B3B09108406A7DFE92757807A79624786AE252EB"]
        assert keyring.keys[0].cert.expiration is not None

    def test_concatenated_armored_exports_are_one_keyring(self, tmp_path: Path) -> None:
        both = tmp_path / "ring.asc"
        both.write_bytes(read("flowable.asc") + read("leocolomb.asc"))
        assert len(OpenPgp.load((str(both),)).keys) == 2

    def test_a_gnupg_keybox_is_read_as_helm_reads_it(self, tmp_path: Path) -> None:
        keyblock = bytes(pysequoia.Cert.split_bytes(read("cert-manager.gpg"))[0])

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
        raw = Canonical.dearmor(read("leocolomb.asc").replace(b"PUBLIC KEY BLOCK", b"SIGNATURE"))
        assert raw is not None
        packets = Canonical._packets(raw)
        assert packets is not None
        bare = b"".join(
            bytes([0xC0 | tag]) + Canonical._length(len(body)) + body
            for tag, body in packets
            if tag not in (2, 13)
        )
        path = tmp_path / "bare.gpg"
        path.write_bytes(bare)
        keyring = OpenPgp.load((str(path),))
        assert not keyring.keys
        assert "no user ID" in keyring.problems[0]
        result = OpenPgp.verify(read("cisco-nso-7.6.1.tgz.prov"), keyring)
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "holds no usable key" in result.detail


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
        result = OpenPgp.verify(read(prov), OpenPgp.load((str(DATA / key),)))
        assert result.outcome is Outcome.VERIFIED
        assert result.signer == fingerprint
        assert b"\n...\nfiles:\n" in result.signed

    def test_altered_content_under_a_trusted_key_is_invalid(self) -> None:
        tampered = read("cert-manager-v1.21.2.tgz.prov").replace(b"sha256:73a5", b"sha256:73a6")
        result = OpenPgp.verify(tampered, OpenPgp.load((str(DATA / "cert-manager.gpg"),)))
        assert result.outcome is Outcome.INVALID
        assert "altered" in result.detail

    def test_a_signer_the_keyring_does_not_hold_is_invalid_and_named(self) -> None:
        result = OpenPgp.verify(
            read("cert-manager-v1.21.2.tgz.prov"), OpenPgp.load((str(DATA / "flowable.asc"),))
        )
        assert result.outcome is Outcome.INVALID
        assert "1226061C665DF13E" in result.detail and "does not hold" in result.detail

    def test_a_key_expired_before_it_signed_is_invalid(self) -> None:
        result = OpenPgp.verify(
            read("openfga-0.3.16.tgz.prov"), OpenPgp.load((str(DATA / "openfga.asc"),))
        )
        assert result.outcome is Outcome.INVALID
        assert "expired on 2025-03-13, before it made this signature on 2026-10-06" in result.detail

    def test_a_key_certified_after_it_signed_is_unverifiable_not_a_forgery(self) -> None:
        result = OpenPgp.verify(
            read("hivemq-operator-0.11.62.tgz.prov"), OpenPgp.load((str(DATA / "hivemq.asc"),))
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert (
            "certified on 2026-05-15, after this signature was made on 2025-12-09" in result.detail
        )

    def test_no_keyring_is_unverifiable(self) -> None:
        result = OpenPgp.verify(read("cert-manager-v1.21.2.tgz.prov"), OpenPgp.load(()))
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "--keyring" in result.detail

    def test_a_detached_signature_verifies_and_is_bound_to_its_data(self, tmp_path: Path) -> None:
        key = pysequoia.Tsk.generate("Test <test@example.invalid>")
        ring = tmp_path / "ring.asc"
        cert = pysequoia.Cert.split_bytes(bytes(key.extract_certificate()))[0]
        ring.write_bytes(bytes(cert))
        keyring = OpenPgp.load((str(ring),))
        manifest = b'{"collection_info": {"name": "x"}}'
        signature = pysequoia.sign(key.signer(), manifest, mode=pysequoia.SignatureMode.DETACHED)
        assert OpenPgp.verify(manifest, keyring, signature=signature).outcome is Outcome.VERIFIED
        assert (
            OpenPgp.verify(manifest + b" ", keyring, signature=signature).outcome is Outcome.INVALID
        )
