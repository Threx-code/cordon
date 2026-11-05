"""A strict DER reader: the encoding every certificate, key and signature here arrives in.

Strict, because a lenient reader is how verifiers get fooled. Two readers that disagree on what
bytes mean -- one accepting a long-form length where a short one fits, a leading zero on an
integer, trailing bytes after a value -- let one party sign one thing and another verify a
different one. So this reader accepts exactly the distinguished encoding (X.690 section 10) and
refuses everything else with `DerError`:

- definite lengths only, in their shortest form;
- an INTEGER in its fewest bytes, and never negative where a size or a key part is read;
- no bytes left over after a value its caller reads whole;
- bounded nesting, so no input recurses without limit.

Verify-only code reads with it; nothing here encodes.
"""

from __future__ import annotations

from typing import ClassVar


class DerError(ValueError):
    """The bytes are not the distinguished encoding of what was asked for."""


class Der:
    """One TLV: `tag` (the identifier octet), `body` (its contents), `raw` (the whole encoding)."""

    __slots__ = ("body", "raw", "tag")

    SEQUENCE: ClassVar[int] = 0x30
    SET: ClassVar[int] = 0x31
    INTEGER: ClassVar[int] = 0x02
    BIT_STRING: ClassVar[int] = 0x03
    OCTET_STRING: ClassVar[int] = 0x04
    NULL: ClassVar[int] = 0x05
    OID: ClassVar[int] = 0x06
    UTF8_STRING: ClassVar[int] = 0x0C
    PRINTABLE_STRING: ClassVar[int] = 0x13
    IA5_STRING: ClassVar[int] = 0x16
    UTC_TIME: ClassVar[int] = 0x17
    GENERALIZED_TIME: ClassVar[int] = 0x18
    BOOLEAN: ClassVar[int] = 0x01
    MAX_DEPTH: ClassVar[int] = 32

    def __init__(self, tag: int, body: bytes, raw: bytes) -> None:
        self.tag, self.body, self.raw = tag, body, raw

    # -- reading ------------------------------------------------------------

    @staticmethod
    def read(data: bytes, offset: int = 0) -> tuple[Der, int]:
        """The TLV at `offset`, and the offset just past it."""
        n = len(data)
        if offset + 2 > n:
            raise DerError("truncated")
        tag = data[offset]
        if tag & 0x1F == 0x1F:
            raise DerError("a high tag number")  # none of the structures read here use one
        first = data[offset + 1]
        at = offset + 2
        if first < 0x80:
            length = first
        elif first == 0x80:
            raise DerError("an indefinite length")
        else:
            count = first & 0x7F
            if count > 4 or at + count > n:
                raise DerError("a length out of range")
            length = int.from_bytes(data[at : at + count], "big")
            if data[at] == 0 or length < 0x80:
                raise DerError("a length not in its shortest form")
            at += count
        end = at + length
        if end > n:
            raise DerError("a value past the end")
        return Der(tag, bytes(data[at:end]), bytes(data[offset:end])), end

    @staticmethod
    def parse(data: bytes, tag: int | None = None) -> Der:
        """`data` as exactly one TLV, with nothing after it."""
        value, end = Der.read(data)
        if end != len(data):
            raise DerError("bytes after the value")
        if tag is not None and value.tag != tag:
            raise DerError(f"expected tag {tag:#x}, found {value.tag:#x}")
        return value

    def children(self) -> list[Der]:
        """The TLVs a constructed value holds, in order."""
        if not self.tag & 0x20:
            raise DerError("not a constructed value")
        out, at = [], 0
        while at < len(self.body):
            child, at = Der.read(self.body, at)
            out.append(child)
        return out

    def expect(self, tag: int) -> Der:
        if self.tag != tag:
            raise DerError(f"expected tag {tag:#x}, found {self.tag:#x}")
        return self

    # -- values -------------------------------------------------------------

    def integer(self, *, unsigned: bool = True) -> int:
        self.expect(Der.INTEGER)
        b = self.body
        if not b:
            raise DerError("an empty integer")
        if len(b) > 1 and ((b[0] == 0 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80)):
            raise DerError("an integer not in its fewest bytes")
        value = int.from_bytes(b, "big", signed=True)
        if unsigned and value < 0:
            raise DerError("a negative integer")
        return value

    def bit_string(self) -> bytes:
        """A BIT STRING's bytes; only whole bytes are read here (no unused bits)."""
        self.expect(Der.BIT_STRING)
        if not self.body or self.body[0] != 0:
            raise DerError("a bit string with unused bits")
        return self.body[1:]

    def oid(self) -> str:
        self.expect(Der.OID)
        b = self.body
        if not b or b[-1] & 0x80:
            raise DerError("a malformed object identifier")
        parts: list[int] = []
        value = 0
        for i, byte in enumerate(b):
            if value == 0 and byte == 0x80 and (i == 0 or not b[i - 1] & 0x80):
                raise DerError("an object identifier arc with a leading zero")
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(value)
                value = 0
        first = parts[0]
        head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
        return ".".join(map(str, head + parts[1:]))

    def boolean(self) -> bool:
        self.expect(Der.BOOLEAN)
        if self.body not in (b"\x00", b"\xff"):
            raise DerError("a boolean not 00 or FF")
        return self.body == b"\xff"

    def text(self) -> str:
        if self.tag not in (Der.UTF8_STRING, Der.PRINTABLE_STRING, Der.IA5_STRING):
            raise DerError(f"not a string: tag {self.tag:#x}")
        try:
            return self.body.decode("utf-8" if self.tag == Der.UTF8_STRING else "ascii")
        except UnicodeDecodeError as exc:
            raise DerError("a string not in its encoding") from exc


__all__ = ["Der", "DerError"]
