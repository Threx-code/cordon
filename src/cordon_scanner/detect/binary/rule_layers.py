"""The decoded layers of a file, for the rules that ask to read them (`layers = "decoded"`).

A rule written for a payload misses the same payload wrapped once: `atob("...")`, a
`Buffer.from(..., "base64")`, Python's `base64.b64decode(b"...")` or `zlib.decompress(...)` over a
literal. The scanner already takes these apart for its own detectors (`analysis/shared/deobfuscation`),
but as text, for reading code. A rule matches bytes, and the payload under a wrapper is as often a
binary (an executable, an archive) as a script, so this decodes the same idioms to bytes, nothing
filtered for readability, and hands each layer to the rules with how it was reached.

Raw bytes stay the default view. Only a rule whose meta says `layers = "decoded"` reads the layers,
so every other rule, and every result proven against YARA and YARA-X, is the file's bytes alone.

Static and bounded throughout: nothing is run; a literal is decoded only when it is written out
whole in the file; at most `MAX_DEPTH` layers deep, `MAX_LAYERS` layers a file and `MAX_BYTES` a
layer, and a compressed literal is inflated only up to `MAX_BYTES`, so a decompression bomb costs
what a megabyte costs.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass
from typing import ClassVar

#: The meta value a rule sets to read decoded layers as well as the raw bytes.
LAYERS_META = "layers"
LAYERS_DECODED = "decoded"


@dataclass(frozen=True)
class Layer:
    """One decoded layer: its bytes, how it was reached, and how deep it sits (the file is 1)."""

    data: bytes
    how: str
    depth: int


class RuleLayers:
    """The decoded layers under a file's bytes, outermost first."""

    MAX_DEPTH: ClassVar[int] = 4
    MAX_LAYERS: ClassVar[int] = 64
    MAX_BYTES: ClassVar[int] = 1 << 20
    #: Shorter literals carry no payload worth a rule's time, and are most often ids and hashes.
    MIN_LITERAL: ClassVar[int] = 16

    _B64: ClassVar[str] = r"[A-Za-z0-9+/=_\-\s]{16,2000000}"
    _HEX: ClassVar[str] = r"[0-9a-fA-F\s]{16,2000000}"
    _QUOTE: ClassVar[str] = r"""[bB]?(?P<q>['"`])"""
    #: (how, pattern, decoder) over the text of the layer above. Each pattern names its literal `b`.
    _FORMS: ClassVar[tuple[tuple[str, re.Pattern[bytes], str], ...]] = tuple(
        (how, re.compile(pattern.encode()), decoder)
        for how, pattern, decoder in (
            ("atob", r"\batob\s{0,4}\(\s{0,4}" + _QUOTE + "(?P<b>" + _B64 + r")(?P=q)", "base64"),
            (
                "Buffer.from base64",
                r"\bBuffer\s{0,4}\.\s{0,4}from\s{0,4}\(\s{0,4}"
                + _QUOTE
                + "(?P<b>"
                + _B64
                + r")(?P=q)"
                r"\s{0,4},\s{0,4}['\"]base64(?:url)?['\"]",
                "base64",
            ),
            (
                "Buffer.from hex",
                r"\bBuffer\s{0,4}\.\s{0,4}from\s{0,4}\(\s{0,4}"
                + _QUOTE
                + "(?P<b>"
                + _HEX
                + r")(?P=q)"
                r"\s{0,4},\s{0,4}['\"]hex['\"]",
                "base16",
            ),
            (
                "b64decode",
                r"\b(?:b64decode|urlsafe_b64decode|decodebytes|standard_b64decode)\s{0,4}\(\s{0,4}"
                + _QUOTE
                + "(?P<b>"
                + _B64
                + r")(?P=q)",
                "base64",
            ),
            (
                "bytes.fromhex",
                r"\b(?:bytes|bytearray)\s{0,4}\.\s{0,4}fromhex\s{0,4}\(\s{0,4}"
                + _QUOTE
                + "(?P<b>"
                + _HEX
                + r")(?P=q)",
                "base16",
            ),
            (
                "unhexlify",
                r"\b(?:unhexlify|a2b_hex)\s{0,4}\(\s{0,4}" + _QUOTE + "(?P<b>" + _HEX + r")(?P=q)",
                "base16",
            ),
        )
    )
    #: A decoded layer that is itself zlib, gzip or raw-deflate data is inflated as a further layer.
    _COMPRESSED: ClassVar[tuple[tuple[str, bytes, int], ...]] = (
        ("gzip", b"\x1f\x8b", 16 + zlib.MAX_WBITS),
        ("zlib", b"\x78", zlib.MAX_WBITS),
    )

    @classmethod
    def of(cls, data: bytes) -> list[Layer]:
        """Every layer under `data`, to `MAX_DEPTH` deep: each distinct, none the file itself."""
        out: list[Layer] = []
        seen = {data}
        frontier = [data]
        for depth in range(2, cls.MAX_DEPTH + 2):
            following: list[bytes] = []
            for body in frontier:
                for how, layer in cls._decoded(body):
                    if layer in seen or len(out) >= cls.MAX_LAYERS:
                        continue
                    seen.add(layer)
                    out.append(Layer(layer, how, depth))
                    following.append(layer)
            if not following:
                break
            frontier = following
        return out

    @classmethod
    def _decoded(cls, body: bytes) -> list[tuple[str, bytes]]:
        found: list[tuple[str, bytes]] = []
        inflated = cls._inflated(body)
        if inflated is not None:
            found.append(inflated)
        for how, pattern, decoder in cls._FORMS:
            for match in pattern.finditer(body):
                layer = cls._decode(re.sub(rb"\s", b"", match.group("b")), decoder)
                if layer is not None and len(layer) >= cls.MIN_LITERAL // 2:
                    found.append((how, layer[: cls.MAX_BYTES]))
        return found

    @staticmethod
    def _decode(literal: bytes, decoder: str) -> bytes | None:
        try:
            if decoder == "base16":
                return binascii.unhexlify(literal) if len(literal) % 2 == 0 else None
            standard = literal.replace(b"-", b"+").replace(b"_", b"/")
            return base64.b64decode(standard + b"=" * (-len(standard) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None

    @classmethod
    def _inflated(cls, body: bytes) -> tuple[str, bytes] | None:
        """`body` inflated, when it is compressed data: at most `MAX_BYTES` out, whatever it claims."""
        for how, magic, wbits in cls._COMPRESSED:
            if not body.startswith(magic):
                continue
            try:
                plain = zlib.decompressobj(wbits).decompress(body, cls.MAX_BYTES)
            except zlib.error:
                continue
            if plain:
                return f"{how} inflate", plain
        return None

    @staticmethod
    def wanted(meta: object) -> bool:
        """Whether a rule's meta asks for the decoded layers."""
        return isinstance(meta, dict) and str(meta.get(LAYERS_META, "")).lower() == LAYERS_DECODED


__all__ = ["LAYERS_DECODED", "LAYERS_META", "Layer", "RuleLayers"]
