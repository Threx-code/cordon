"""A fixed body of invented text that a delivered rule pack is timed on.

The corpus is made here from a seed: syllables joined into made-up words, laid out as lines of words, brackets, signs and numbers. It is invented text only and is derived from no corpus and no
package. Every call makes the same bytes, so a time measured on it means the same thing on every machine and in the backend gate that calls the same function.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar, Final

MASK: Final = (1 << 64) - 1


class CalibrationCorpus:
    SEED: ClassVar[int] = 7131
    FILES: ClassVar[int] = 40
    BYTES_PER_FILE: ClassVar[int] = 24_000
    SYLLABLES: ClassVar[tuple[str, ...]] = (
        "al", "bo", "cri", "dun", "el", "fa", "gor", "hi", "ju", "ka", "lem", "mo", "ni", "or", "pu", "qua", "ras", "ti", "ul", "ve", "wo", "xi", "yan", "zu",
    )  # fmt: skip
    JOINERS: ClassVar[tuple[str, ...]] = (
        " ",
        " ",
        " ",
        " ",
        "(",
        ")",
        " = ",
        ", ",
        ".",
        "_",
        ";\n",
        "\n",
        " 17 ",
        " 3.5 ",
        ': "',
        '" ',
        "/",
        "-",
    )

    @staticmethod
    def _step(state: int) -> int:
        """A 64-bit linear congruential step: plain integer arithmetic, the same on every Python."""
        return (state * 6364136223846793005 + 1442695040888963407) & MASK

    @classmethod
    def files(cls) -> tuple[bytes, ...]:
        state, out = cls.SEED, []
        for _ in range(cls.FILES):
            parts: list[str] = []
            size = 0
            while size < cls.BYTES_PER_FILE:
                state = cls._step(state)
                word = "".join(
                    cls.SYLLABLES[(state >> (8 * k + 16)) % len(cls.SYLLABLES)]
                    for k in range(1 + (state >> 60) % 3)
                )
                state = cls._step(state)
                joiner = cls.JOINERS[(state >> 33) % len(cls.JOINERS)]
                parts.append(word + joiner)
                size += len(word) + len(joiner)
            out.append("".join(parts).encode("ascii"))
        return tuple(out)

    @classmethod
    def digest(cls) -> str:
        """The sha256 of the corpus, so a change to what it is shows."""
        body = hashlib.sha256()
        for data in cls.files():
            body.update(hashlib.sha256(data).digest())
        return body.hexdigest()


__all__ = ["CalibrationCorpus"]
