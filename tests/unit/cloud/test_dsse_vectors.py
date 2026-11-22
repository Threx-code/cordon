"""The DSSE envelope the scanner reads natively, on the specification's test vectors and under a changed byte.

The pre-authentication encoding is `DSSEv1 <len(type)> <type> <len(payload)> <payload>` with the lengths in decimal, counted in bytes. The
first vector is the one the DSSE protocol document gives. An envelope the platform signed verifies here (all thirteen platform cases,
`test_bundle_chain.py`); here every changed byte of one of them is refused.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, BundleRefused, Dsse
from support import ROOT as REPO

FIXTURES = json.loads(
    (REPO / "tests" / "unit" / "cloud" / "bundle_chain_fixtures.json").read_text(encoding="utf-8")
)


class TestThePreAuthenticationEncoding:
    def test_the_vector_in_the_specification(self) -> None:
        assert (
            Dsse.pae("http://example.com/HelloWorld", b"hello world")
            == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        )

    def test_an_empty_payload_keeps_the_separator(self) -> None:
        assert Dsse.pae("t", b"") == b"DSSEv1 1 t 0 "

    def test_lengths_count_bytes_not_characters(self) -> None:
        assert Dsse.pae("é", "é".encode()) == b"DSSEv1 2 \xc3\xa9 2 \xc3\xa9"

    @pytest.mark.parametrize("size", [9, 10, 99, 100, 1000, 65_536])
    def test_the_length_is_decimal_without_padding(self, size: int) -> None:
        assert Dsse.pae("t", b"x" * size).startswith(f"DSSEv1 1 t {size} ".encode())

    def test_spaces_newlines_and_nul_in_the_payload_are_kept_as_they_are(self) -> None:
        payload = b"a b\nc\x00d"
        assert Dsse.pae("t", payload) == b"DSSEv1 1 t 7 " + payload

    def test_a_type_and_a_payload_that_swap_do_not_encode_the_same(self) -> None:
        assert Dsse.pae("ab", b"c") != Dsse.pae("a", b"bc")


class TestAChangedByte:
    """One platform-signed envelope, with the clock inside its window; each change must be refused."""

    CASE = FIXTURES["cases"][0]
    ROOT_KEY = bytes.fromhex(FIXTURES["root_public"])

    def accept(self, envelope: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        return BundleChain.accept_bundle(
            root_public=self.ROOT_KEY,
            delegation=FIXTURES["delegation"],
            envelope=envelope,
            tenant=FIXTURES["tenant"],
            now=datetime.fromisoformat(self.CASE["now"]),
            held=None,
        )

    def test_the_unchanged_envelope_is_taken(self) -> None:
        assert self.accept(self.CASE["offered"][0])[0] == "new"

    def test_every_sampled_payload_byte_changed_is_refused_and_never_as_a_chain_break(self) -> None:
        envelope = self.CASE["offered"][0]
        body = bytearray(base64.b64decode(envelope["payload"]))
        positions = sorted(
            {*range(0, len(body), max(1, len(body) // 24)), len(body) // 2, len(body) - 1}
        )
        for position in positions:
            changed = copy.deepcopy(envelope)
            flipped = bytearray(body)
            flipped[position] ^= 0x01
            changed["payload"] = base64.b64encode(bytes(flipped)).decode("ascii")
            with pytest.raises(BundleError) as caught:
                self.accept(changed)
            assert not isinstance(caught.value, BundleRefused), position

    def test_a_changed_signature_byte_is_refused(self) -> None:
        envelope = copy.deepcopy(self.CASE["offered"][0])
        raw = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
        raw[len(raw) // 2] ^= 0x01
        envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(BundleError):
            self.accept(envelope)

    def test_a_changed_payload_type_is_refused(self) -> None:
        envelope = copy.deepcopy(self.CASE["offered"][0])
        envelope["payloadType"] = envelope["payloadType"] + "x"
        with pytest.raises(BundleError):
            self.accept(envelope)
