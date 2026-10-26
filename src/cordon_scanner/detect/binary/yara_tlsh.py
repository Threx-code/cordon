"""TLSH, the locality-sensitive hash behind YARA's `elf.telfhash()`, as YARA 4.5.1 builds it.

YARA compiles Trend Micro's TLSH (libyara/tlshc, Apache License 2.0) with 128 buckets, a one-byte
checksum and a five-byte window (`-DBUCKETS_128 -DCHECKSUM_1B`). This is that configuration,
byte for byte: the same Pearson table, the same six bucket triplets per window, quartiles, the
length code, the quartile ratios computed in single precision as the C does, and the hex form
with its nibble swaps and reversed body, "T1"-prefixed. Input shorter than 50 bytes, or with too
few buckets filled, has no hash, and YARA then reports the empty string.
"""

from __future__ import annotations

import bisect
from fractions import Fraction
from typing import ClassVar


class Tlsh:
    V_TABLE: ClassVar[bytes] = bytes([
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
    ])  # fmt: skip
    #: the upper bound of each length code (`topval`, tlsh_util.c)
    TOPVAL: ClassVar[tuple[int, ...]] = (
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
    BUCKETS: ClassVar[int] = 128
    CODE_SIZE: ClassVar[int] = 32
    MIN_DATA_LENGTH: ClassVar[int] = 50
    #: (salt, the three window positions back from the newest byte) per bucket count
    TRIPLETS: ClassVar[tuple[tuple[int, int, int], ...]] = (
        (49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4),
    )  # fmt: skip

    @staticmethod
    def digest(data: bytes) -> bytes:
        """The "T1..." hash of `data`, or b"" where TLSH gives none."""
        if len(data) < Tlsh.MIN_DATA_LENGTH:
            return b""
        v = Tlsh.V_TABLE
        buckets = [0] * 256
        checksum = 0
        for i in range(4, len(data)):
            a = data[i]
            back = (a, data[i - 1], data[i - 2], data[i - 3], data[i - 4])
            checksum = v[v[v[1 ^ a] ^ back[1]] ^ checksum]
            for salt, j, k in Tlsh.TRIPLETS:
                buckets[v[v[v[salt ^ a] ^ back[j]] ^ back[k]]] += 1
        ordered = sorted(buckets[: Tlsh.BUCKETS])
        q1, q2, q3 = (
            ordered[Tlsh.BUCKETS // 4 - 1],
            ordered[Tlsh.BUCKETS // 2 - 1],
            ordered[Tlsh.BUCKETS - Tlsh.BUCKETS // 4 - 1],
        )
        if q3 == 0:
            return b""
        if sum(1 for b in buckets[: Tlsh.BUCKETS] if b > 0) <= 4 * Tlsh.CODE_SIZE // 2:
            return b""
        code = bytearray(Tlsh.CODE_SIZE)
        for i in range(Tlsh.CODE_SIZE):
            h = 0
            for j in range(4):
                k = buckets[4 * i + j]
                if q3 < k:
                    h += 3 << (j * 2)
                elif q2 < k:
                    h += 2 << (j * 2)
                elif q1 < k:
                    h += 1 << (j * 2)
            code[i] = h
        lvalue = Tlsh.length_code(len(data))
        q1ratio = Tlsh.ratio(q1, q3) % 16
        q2ratio = Tlsh.ratio(q2, q3) % 16
        qb = (q1ratio | (q2ratio << 4)) & 0xFF
        out = bytes([Tlsh.swap(checksum), Tlsh.swap(lvalue), Tlsh.swap(qb)]) + bytes(reversed(code))
        return b"T1" + out.hex().upper().encode()

    @staticmethod
    def swap(byte: int) -> int:
        return ((byte >> 4) | (byte << 4)) & 0xFF

    @staticmethod
    def length_code(length: int) -> int:
        """`l_capturing`: the first code whose upper bound holds the length."""
        idx = bisect.bisect_left(Tlsh.TOPVAL, length)
        return min(idx, len(Tlsh.TOPVAL) - 1)

    @staticmethod
    def ratio(q: int, q3: int) -> int:
        """`(unsigned int)((float)(q * 100) / (float)q3)`: single-precision, rounded to nearest
        even at each step, then truncated."""
        a = Tlsh.f32((q * 100) & 0xFFFFFFFF)
        b = Tlsh.f32(q3)
        return int(Tlsh.f32(a / b))

    @staticmethod
    def f32(value: Fraction | int) -> Fraction:
        """`value` rounded to the nearest IEEE single (ties to even); non-negative input."""
        x = Fraction(value)
        if x == 0:
            return x
        e = x.numerator.bit_length() - x.denominator.bit_length()
        if Fraction(2) ** e > x:
            e -= 1
        scale = Fraction(2) ** (e - 23)
        m = x / scale
        whole = m.numerator // m.denominator
        rest = m - whole
        if rest > Fraction(1, 2) or (rest == Fraction(1, 2) and whole % 2):
            whole += 1
        return whole * scale


__all__ = ["Tlsh"]
