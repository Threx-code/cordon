"""Trend Micro's TLSH locality-sensitive hash, in the configuration the ELF import digest ("telfhash")
reports: 128 buckets, a one-byte checksum, and a five-byte window advanced one byte at a time.

The algorithm follows the published TLSH specification. A window of five consecutive bytes is reduced to
six bucket votes through a fixed Pearson permutation; the vote counts are summarised against their own
quartiles into a 32-byte body; a header carries a running checksum, a length code and the two quartile
ratios. The textual form is "T1" followed by the header and the reversed body in upper-case hex, every
header byte having its two nibbles exchanged.

The Pearson permutation and the length-code bounds are fixed tables defined by the algorithm itself and are
carried here as data (they cannot be regenerated from a formula). Quartile ratios are produced in IEEE-754
single precision, as the specification requires: each operand and the quotient are rounded to the nearest
single, ties to even, then the quotient is truncated toward zero. Input under 50 bytes, or data that fills
too few buckets, has no hash and yields the empty string.
"""

from __future__ import annotations

import bisect
from fractions import Fraction
from typing import ClassVar


class Tlsh:
    """TLSH digest in the 128-bucket / one-byte-checksum configuration."""

    BUCKET_COUNT: ClassVar[int] = 128
    BODY_LEN: ClassVar[int] = 32
    MIN_LEN: ClassVar[int] = 50

    #: Pearson permutation of 0..255 (the algorithm's fixed substitution table).
    PEARSON: ClassVar[bytes] = bytes((
        1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213, 181, 161, 85, 218, 80,
        64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
        25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235, 97, 234, 57, 22, 60, 250, 82, 175,
        208, 5, 127, 199, 111, 62, 135, 248, 174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
        132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219, 119, 68, 223, 78, 83, 88, 201, 99,
        122, 11, 92, 32, 136, 114, 52, 10, 138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
        170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131, 125, 173, 15, 238, 79, 95, 89, 16,
        105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
        27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203, 233, 40, 186, 147, 198, 192, 155, 33,
        164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
        51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
    ))  # fmt: skip

    #: Upper bound of each length code: the smallest index whose bound is >= the data length.
    LENGTH_BOUNDS: ClassVar[tuple[int, ...]] = (
        1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876, 2439, 3171, 3475,
        3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970, 17567,
        19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564, 50121, 55133, 60646, 66711, 73382,
        80721, 88793, 97672, 107439, 118183, 130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337,
        278670, 306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800, 795081, 874589,
        962048, 1058252, 1164078, 1280486, 1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836,
        3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467,
        9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870, 20312458, 22343706,
        24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573, 47895730, 52685306, 57953837,
        63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659, 124229227, 136652151, 150317384,
        165349128, 181884040, 200072456, 220079703, 242087671, 266296456, 292926096, 322218735, 354440623,
        389884688, 428873168, 471760495, 518936559, 570830240, 627913311, 690704607, 759775136, 835752671,
        919327967, 1011260767, 1112386880, 1223623232, 1345985727, 1480584256, 1628642751, 1791507135,
        1970657856, 2167723648, 2384496256, 2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
    )  # fmt: skip

    #: Per bucket vote: (salt byte, two window offsets back from the newest byte).
    WINDOW_TRIPLETS: ClassVar[tuple[tuple[int, int, int], ...]] = (
        (49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4),
    )  # fmt: skip

    #: Per-salt 256-byte substitution tables (``x -> PEARSON[salt ^ x]``), built once on first use.
    _salt_cache: ClassVar[dict[int, bytes] | None] = None
    #: Deletion sets for the histogram's value splits, cached by range across calls.
    _delete_cache: ClassVar[dict[tuple[int, int], bytes]] = {}
    #: Bucket values TLSH discards (>= 128), deleted in one pass before the histogram.
    _HIGH: ClassVar[bytes] = bytes(range(128, 256))

    @classmethod
    def digest(cls, data: bytes) -> bytes:
        """The "T1..." digest of `data`, or b"" when the data is too short or too uniform to hash."""
        if len(data) < cls.MIN_LEN:
            return b""
        active, checksum = cls._tally(data)
        ranked = sorted(active)
        q1 = ranked[cls.BUCKET_COUNT // 4 - 1]
        q2 = ranked[cls.BUCKET_COUNT // 2 - 1]
        q3 = ranked[cls.BUCKET_COUNT - cls.BUCKET_COUNT // 4 - 1]
        if q3 == 0:
            return b""
        if sum(1 for c in active if c > 0) <= 2 * cls.BODY_LEN:
            return b""

        body = bytearray(cls.BODY_LEN)
        for i in range(cls.BODY_LEN):
            packed = 0
            for j in range(4):
                c = active[4 * i + j]
                if c > q3:
                    packed += 3 << (2 * j)
                elif c > q2:
                    packed += 2 << (2 * j)
                elif c > q1:
                    packed += 1 << (2 * j)
            body[i] = packed

        length_code = cls._length_code(len(data))
        low = cls._ratio(q1, q3) % 16
        high = cls._ratio(q2, q3) % 16
        ratio_byte = (low | (high << 4)) & 0xFF
        header = bytes(
            (
                cls._swap_nibbles(checksum),
                cls._swap_nibbles(length_code),
                cls._swap_nibbles(ratio_byte),
            )
        )
        return b"T1" + (header + bytes(reversed(body))).hex().upper().encode()

    @classmethod
    def _tally(cls, data: bytes) -> tuple[list[int], int]:
        """The kept bucket counts and the one-byte checksum, over the whole input. Each triplet's bucket at
        every window position is three Pearson substitutions of XORed byte slices, applied to the entire
        slice at once with ``bytes.translate`` and big-integer XOR (C speed); only the checksum, a running
        one-byte fold, is sequential, and its per-position prefix is still formed by the vectorised step."""
        table = cls.PEARSON
        length = len(data)
        newest = data[4:length]  # the window's newest byte at every position
        back = {offset: data[4 - offset : length - offset] for offset in (1, 2, 3, 4)}
        salted = cls._salt_tables()
        buckets = []
        for salt, j, k in cls.WINDOW_TRIPLETS:
            votes = newest.translate(salted[salt])
            votes = cls._xor(votes, back[j]).translate(table)
            votes = cls._xor(votes, back[k]).translate(table)
            buckets.append(votes)
        active = [0] * cls.BUCKET_COUNT
        kept = b"".join(buckets).translate(None, cls._HIGH)  # TLSH keeps only buckets 0..127
        cls._partition(kept, 0, cls.BUCKET_COUNT, active)
        prefix = cls._xor(newest.translate(salted[1]), back[1]).translate(table)
        checksum = 0
        for byte in prefix:
            checksum = table[byte ^ checksum]
        return active, checksum

    @classmethod
    def _partition(cls, data: bytes, lo: int, hi: int, active: list[int]) -> None:
        """Tally the bucket values in ``[lo, hi)`` occurring in ``data`` into ``active`` by recursive halving:
        ``bytes.translate`` (a C pass) keeps only the bytes in each half, so a leaf's count is just the length
        of the bytes that reached it. Each tree level touches the whole input once, ~7 levels for 128 values."""
        if not data:
            return
        if hi - lo == 1:
            active[lo] = len(data)
            return
        mid = (lo + hi) // 2
        cls._partition(data.translate(None, cls._delete_for(lo, mid)), lo, mid, active)
        cls._partition(data.translate(None, cls._delete_for(mid, hi)), mid, hi, active)

    @classmethod
    def _delete_for(cls, lo: int, hi: int) -> bytes:
        """The ``translate`` deletion set that keeps only byte values in ``[lo, hi)`` -- cached, as it depends
        only on the split, not the data."""
        table = cls._delete_cache.get((lo, hi))
        if table is None:
            table = bytes(v for v in range(256) if not lo <= v < hi)
            cls._delete_cache[(lo, hi)] = table
        return table

    @staticmethod
    def _xor(left: bytes, right: bytes) -> bytes:
        """The byte-wise XOR of two equal-length byte strings as a single big-integer operation."""
        value = int.from_bytes(left, "little") ^ int.from_bytes(right, "little")
        return value.to_bytes(len(left), "little")

    @classmethod
    def _salt_tables(cls) -> dict[int, bytes]:
        """A 256-byte table per salt in use (the checksum's 1 and the six triplets'), mapping ``x`` to
        ``PEARSON[salt ^ x]`` so the first Pearson step applies to a whole slice in one ``translate``."""
        if cls._salt_cache is None:
            table = cls.PEARSON
            salts = {1, *(salt for salt, _, _ in cls.WINDOW_TRIPLETS)}
            cls._salt_cache = {salt: bytes(table[salt ^ x] for x in range(256)) for salt in salts}
        return cls._salt_cache

    @staticmethod
    def _swap_nibbles(byte: int) -> int:
        return ((byte >> 4) | (byte << 4)) & 0xFF

    @classmethod
    def _length_code(cls, length: int) -> int:
        idx = bisect.bisect_left(cls.LENGTH_BOUNDS, length)
        return min(idx, len(cls.LENGTH_BOUNDS) - 1)

    @classmethod
    def _ratio(cls, q: int, q3: int) -> int:
        """The percentage q/q3 in IEEE-754 single precision throughout, truncated toward zero: the
        value the hash records before its modulo. Each operand and the quotient round to the nearest
        single, ties to even."""
        # The count is a 32-bit unsigned quantity; the mask keeps that wrap explicit. It only bites
        # for very large (multi-megabyte) inputs, where q * 100 passes 2**32, and is deliberate.
        numerator = cls._to_single((q * 100) & 0xFFFFFFFF)
        denominator = cls._to_single(q3)
        return int(cls._to_single(numerator / denominator))

    @staticmethod
    def _to_single(value: Fraction | int) -> Fraction:
        """`value` (>= 0) as the nearest IEEE-754 single, ties to even, returned exactly as a Fraction."""
        x = Fraction(value)
        if x == 0:
            return x
        exponent = x.numerator.bit_length() - x.denominator.bit_length()
        if Fraction(2) ** exponent > x:
            exponent -= 1
        unit = Fraction(2) ** (exponent - 23)
        scaled = x / unit
        whole = scaled.numerator // scaled.denominator
        remainder = scaled - whole
        if remainder > Fraction(1, 2) or (remainder == Fraction(1, 2) and whole % 2):
            whole += 1
        return whole * unit


__all__ = ["Tlsh"]
