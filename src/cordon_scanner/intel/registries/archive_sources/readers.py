"""The small readings the archive sources share: a digest in the forms registries write it, and the lines of a file kept with a
registry's index. Plain string work, one pass, no pattern over a document."""

from __future__ import annotations

import base64
import binascii

HEX = frozenset("0123456789abcdef")
WIDTH = {"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}


class Digest:
    @staticmethod
    def hex(algorithm: str, value: str) -> tuple[str, str] | None:
        """`(algorithm, lower-case hex)` when `value` is a hex digest of that algorithm's width, else None."""
        text = value.strip().lower()
        if WIDTH.get(algorithm) == len(text) and set(text) <= HEX:
            return algorithm, text
        return None

    @classmethod
    def sri(cls, value: str) -> tuple[str, str] | None:
        """`sha256-<base64>` (Subresource Integrity, as Bazel writes it) as a hex digest."""
        algorithm, _, encoded = value.strip().partition("-")
        if algorithm not in ("sha256", "sha384", "sha512"):
            return None
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return None
        return cls.hex(algorithm, raw.hex())

    @classmethod
    def labelled(cls, value: str) -> tuple[str, str] | None:
        """`sha256=<hex>` (as opam writes it)."""
        algorithm, _, digest = value.strip().partition("=")
        return cls.hex(algorithm, digest)


class Lines:
    """An indented file (the small YAML of an index, an opam file) read as its lines."""

    @staticmethod
    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    @classmethod
    def under(cls, text: str, header: str, *, at: int = 0) -> list[str]:
        """The lines that belong to the first line `header` (at indent `at`): each deeper than it, up to the next line that is not."""
        lines = text.splitlines()
        for start, line in enumerate(lines):
            if (
                cls.indent(line) == at
                and line.strip().rstrip(":").strip("\"'") == header.rstrip(":")
                and line.rstrip().endswith(":")
            ):
                body: list[str] = []
                for follower in lines[start + 1 :]:
                    if follower.strip() and cls.indent(follower) <= at:
                        break
                    if follower.strip():
                        body.append(follower)
                return body
        return []

    @classmethod
    def scalar(cls, lines: list[str], key: str) -> str:
        """The value of `key: value` among `lines` (quotes removed), "" when there is none or it has nested lines."""
        for line in lines:
            label, colon, value = line.strip().partition(":")
            if colon and label.strip("\"'") == key:
                return value.strip().strip("\"'")
        return ""

    @classmethod
    def items(cls, lines: list[str], key: str) -> list[str]:
        """The `- value` lines that follow `key:` (quotes removed)."""
        out: list[str] = []
        collecting = False
        base = -1
        for line in lines:
            stripped = line.strip()
            if not collecting:
                label, colon, value = stripped.partition(":")
                if colon and label.strip("\"'") == key:
                    if value.strip():
                        return [value.strip().strip("\"'")]
                    collecting, base = True, cls.indent(line)
                continue
            if stripped.startswith("- ") and cls.indent(line) >= base:
                out.append(stripped[2:].strip().strip("\"'"))
            elif cls.indent(line) <= base:
                break
        return out
