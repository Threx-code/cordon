"""The right-to-left share of a file (`ObfuscationText._is_rtl_resource`), counted in C.

The count once visited every character in Python. It now counts ASCII letters on the bytes and
looks only at the characters above ASCII; these tests hold it to the original definition on
inputs chosen to break the shortcut: invalid UTF-8 beside ASCII letters, letters that are also
numbers, combining marks, the share's threshold and the minimum letter count. Every character
above ASCII is written as an escape, so none is in the file itself.
"""

from __future__ import annotations

import random

from cordon_scanner.detect.code.obfuscation import (
    RTL_RANGES,
    RTL_RESOURCE_MIN_LETTERS,
    RTL_RESOURCE_SHARE,
    ObfuscationText,
)

ALEF = "\N{ARABIC LETTER ALEF}"


class TestRightToLeftShare:
    #: Characters around every edge of the shortcut: ASCII letters and non-letters, Latin-1
    #: letters, digits that are not decimal (superscripts), letters that are numbers (Roman
    #: numerals, CJK), combining marks, and Hebrew, Arabic and Arabic presentation forms at the
    #: ends of the right-to-left ranges, with the bidi controls themselves.
    ALPHABET = "aZ09_ \n.{}" + "".join(
        map(
            chr,
            (
                0x00E9,
                0x00AA,
                0x00B2,
                0x00BD,
                0x2160,
                0x4E00,
                0x0301,
                0x05D0,
                0x0590,
                0x08FF,
                0xFB1D,
                0xFDFF,
                0xFE70,
                0xFEFF,
                0x0627,
                0x06F1,
                0x202E,
                0x202B,
                0x200F,
                0x1E800,
                0x1EFFF,
                0x1F600,
            ),
        )
    )
    RIGHT_TO_LEFT = "".join(map(chr, (0x05D0, 0x0627, 0x06F1, 0xFB1D, 0x1E800)))
    #: Bytes that are not UTF-8 on their own: a lone continuation, a truncated lead, an
    #: overlong form and a surrogate's encoding.
    BROKEN = (b"\x80", b"\xc3", b"\xe2\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xff")

    @staticmethod
    def reference(raw: bytes) -> bool:
        """The definition, character by character, as the detector first wrote it."""
        text = raw.decode("utf-8", "replace")
        letters = [character for character in text if character.isalpha()]
        if len(letters) < RTL_RESOURCE_MIN_LETTERS:
            return False
        right_to_left = sum(
            1 for c in letters if any(low <= ord(c) <= high for low, high in RTL_RANGES)
        )
        return right_to_left / len(letters) >= RTL_RESOURCE_SHARE

    def sample(self, rng: random.Random) -> bytes:
        size = rng.choice((0, 50, 199, 200, 201, 260, 1000, 3000))
        rtl_weight = rng.choice((0.0, 0.05, 0.09, 0.1, 0.11, 0.3, 0.9))
        parts: list[bytes] = []
        for _ in range(size):
            roll = rng.random()
            if roll < 0.03:
                parts.append(rng.choice(self.BROKEN))
            elif roll < 0.03 + rtl_weight:
                parts.append(rng.choice(self.RIGHT_TO_LEFT).encode())
            else:
                parts.append(rng.choice(self.ALPHABET).encode())
        return b"".join(parts)

    def test_it_agrees_with_the_definition_on_twenty_thousand_inputs(self) -> None:
        rng = random.Random(20261027)  # noqa: S311 -- a fixture, not key material
        verdicts = {True: 0, False: 0}
        for _ in range(20_000):
            raw = self.sample(rng)
            expected = self.reference(raw)
            assert ObfuscationText._is_rtl_resource(raw) is expected, raw[:80]
            verdicts[expected] += 1
        assert min(verdicts.values()) > 1_000  # both answers exercised, not one

    def test_the_minimum_letter_count_is_exact(self) -> None:
        arabic = ALEF * (RTL_RESOURCE_MIN_LETTERS - 1)
        assert not ObfuscationText._is_rtl_resource(arabic.encode())
        assert ObfuscationText._is_rtl_resource((arabic + ALEF).encode())

    def test_ascii_bytes_after_a_broken_sequence_still_count(self) -> None:
        """The decoder replaces `\\xc3` alone and keeps the letter after it, so the byte count
        of ASCII letters is the decoded count."""
        raw = (b"\xc3a" * 150) + (ALEF * 60).encode()
        assert ObfuscationText._is_rtl_resource(raw) is self.reference(raw)
