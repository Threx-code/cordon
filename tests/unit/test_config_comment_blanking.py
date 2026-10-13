"""`ConfigDetector._without_comments` jumps between the bytes that change its state instead of
visiting every byte. It must blank exactly what the byte-by-byte reading blanked: the reference
below is that reading, kept verbatim, and the two are compared on every shape that matters and on
random strings over the bytes the state machine acts on."""

from __future__ import annotations

import random

from cordon_scanner.detect.config_files import ConfigDetector


class ByteByByte:
    """The reading `_without_comments` replaced, unchanged."""

    @staticmethod
    def without_comments(raw: bytes) -> bytes:
        if b"#" not in raw:
            return raw
        out = bytearray(raw)
        quote: int | None = None
        index = 0
        length = len(out)
        while index < length:
            character = out[index]
            if character == 0x0A:
                quote = None
                index += 1
                continue
            if character == 0x5C:
                index += 2
                continue
            if quote is None and character in (0x22, 0x27):
                quote = character
            elif character == quote:
                quote = None
            elif quote is None and character == 0x23:
                while index < length and out[index] != 0x0A:
                    out[index] = 0x20
                    index += 1
                continue
            index += 1
        return bytes(out)


class TestCommentBlankingMatchesTheByteReading:
    CASES = (
        b"",
        b"no comment here",
        b"# whole line\nkey: value\n",
        b"key: value  # trailing\n",
        b'password: "a#b"\n',
        b"password: 'a#b' # real comment\n",
        b'say: "unterminated # still quoted\nnext: 1 # comment\n',
        b"escaped: \\# not a comment\n",
        b'quote: "a\\"#b" # comment\n',
        b"backslash at end \\",
        b'continued: "a \\\n # still in the quote"\n',
        b"#",
        b"#\n#\n",
        b'mixed: "it\'s" # done\n',
    )

    def test_known_shapes(self) -> None:
        for raw in self.CASES:
            assert ConfigDetector._without_comments(raw) == ByteByByte.without_comments(raw), raw

    def test_random_strings_over_the_state_bytes(self) -> None:
        pieces = (b"a", b" ", b'"', b"'", b"#", b"\\", b"\n", b"x#y", b"\\\n", b'"#"')
        generator = random.Random(7)  # noqa: S311 -- a fixture, not key material
        for _ in range(20000):
            raw = b"".join(generator.choice(pieces) for _ in range(generator.randint(0, 40)))
            assert ConfigDetector._without_comments(raw) == ByteByByte.without_comments(raw), raw

    def test_offsets_are_preserved(self) -> None:
        raw = b"a: 1 # x\nb: 2\n"
        assert len(ConfigDetector._without_comments(raw)) == len(raw)
