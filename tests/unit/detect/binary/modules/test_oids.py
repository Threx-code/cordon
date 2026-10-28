"""The object-identifier registry (modules.oids) is OpenSSL's object table held as declared data. These pin a
sample of the resolutions modules.signature depends on -- a certificate's key and signature algorithms, a
digest, a name attribute type -- and the table's size, so an edit that drops or changes an entry is caught.
"""

from __future__ import annotations

from cordon_scanner.detect.binary.modules.oids import ObjectIds


class TestObjectIds:
    def test_the_table_is_populated(self) -> None:
        assert len(ObjectIds.NAMES) == 1064
        assert len(ObjectIds.DIGEST_SIZES) == 37

    def test_known_identifiers_resolve_to_their_names(self) -> None:
        assert ObjectIds.NAMES["1.2.840.113549.1.1.1"] == ("rsaEncryption", "rsaEncryption")
        assert ObjectIds.NAMES["1.2.840.10045.2.1"] == ("id-ecPublicKey", "id-ecPublicKey")
        assert ObjectIds.NAMES["2.16.840.1.101.3.4.2.1"] == ("SHA256", "sha256")
        assert ObjectIds.NAMES["2.5.4.3"] == ("CN", "commonName")

    def test_an_unknown_identifier_is_absent(self) -> None:
        assert "1.2.3.4.5.6.7.8.9" not in ObjectIds.NAMES

    def test_digest_sizes(self) -> None:
        assert ObjectIds.DIGEST_SIZES["sha256"] == 32
        assert ObjectIds.DIGEST_SIZES["sha1"] == 20
