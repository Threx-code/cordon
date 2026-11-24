"""What a scan counts about each file it reads, without keeping any of its text: how big it is and how many encoded literals it holds, of what kind.

The counts feed the facts record. A size class is one word from a closed list. An encoded literal is a long unbroken run that is data and not prose: base64 text, hexadecimal digits, a run of `\\x` escapes
or a run of unicode escapes; each is counted under its kind and nothing of it is kept. Only the first `WINDOW` bytes of a text file are read for them, so the cost of a scan stays flat for a very large file.
"""

from __future__ import annotations

import re
from typing import ClassVar

from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.files.instruction_paths import INSTRUCTION_PATHS


class FileFacts:
    #: The upper bound (exclusive, in bytes) of each size class; a file at or past the last is `huge`.
    SIZE_CLASSES: ClassVar[tuple[tuple[str, int], ...]] = (
        ("empty", 1),
        ("tiny", 1024),
        ("small", 16 * 1024),
        ("medium", 256 * 1024),
        ("large", 4 * 1024 * 1024),
    )
    HUGE: ClassVar[str] = "huge"
    #: How much of a file is read for encoded literals.
    WINDOW: ClassVar[int] = 1024 * 1024
    #: The kinds of encoded literal, in the order they are reported.
    ENCODINGS: ClassVar[tuple[str, ...]] = ("base64", "hex", "hex_escape", "unicode_escape")
    #: How long a run must be to count: characters of base64 or hex, escapes of either kind.
    LONG_RUN: ClassVar[int] = 64
    LONG_ESCAPES: ClassVar[dict[str, int]] = {"hex_escape": 16, "unicode_escape": 8}
    #: Every byte that is not one base64 is written in is turned into a space, so the runs of the others are the words left: split in one pass, never a pattern that could start again inside a run.
    BASE64_ONLY: ClassVar[bytes] = bytes.maketrans(
        bytes(
            b
            for b in range(256)
            if b not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        ),
        b" " * (256 - 65),
    )
    #: Every unbroken run of each kind of escape; each run is judged by its length afterwards.
    HEX: ClassVar[re.Pattern[bytes]] = re.compile(rb"[0-9a-fA-F]+")
    ESCAPES: ClassVar[dict[str, re.Pattern[bytes]]] = {
        "hex_escape": re.compile(rb"(?:[\\]x[0-9a-fA-F]{2})+"),
        "unicode_escape": re.compile(rb"(?:[\\]u[0-9a-fA-F]{4})+"),
    }
    ESCAPE_BYTES: ClassVar[dict[str, int]] = {"hex_escape": 4, "unicode_escape": 6}

    @classmethod
    def size_class(cls, size: int) -> str:
        """The class of a file of `size` bytes."""
        for name, bound in cls.SIZE_CLASSES:
            if size < bound:
                return name
        return cls.HUGE

    @classmethod
    def encoded_literals(cls, raw: bytes) -> dict[str, int]:
        """How many encoded literals of each kind the first `WINDOW` bytes hold; only the kinds present are in the answer."""
        head = raw[: cls.WINDOW]
        found = dict.fromkeys(cls.ENCODINGS, 0)
        for word in head.translate(cls.BASE64_ONLY).split():
            digits = word.rstrip(b"=")
            if len(digits) >= cls.LONG_RUN:
                kind = "hex" if len(digits) % 2 == 0 and cls.HEX.fullmatch(digits) else "base64"
                found[kind] += 1
        for kind, pattern in cls.ESCAPES.items():
            minimum = cls.LONG_ESCAPES[kind] * cls.ESCAPE_BYTES[kind]
            found[kind] = sum(
                1 for match in pattern.finditer(head) if match.end() - match.start() >= minimum
            )
        return {kind: count for kind, count in found.items() if count}

    @staticmethod
    def is_instruction(path: str) -> bool:
        """Whether `path` is a file an agent reads its instructions from (a CLAUDE.md, an AGENTS.md, a rules folder, a skill's SKILL.md ...)."""
        return any(PathGlob.matches(path, pattern) for pattern in INSTRUCTION_PATHS)


__all__ = ["FileFacts"]
