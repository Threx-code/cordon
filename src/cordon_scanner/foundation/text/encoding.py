"""How a file's bytes become text: the UTF-8 re-encoding every detector's bytes go through, and the
decoding `FileContent.text` and `text_head` share (moved from `foundation/content.py` when it reached
its length limit with note 80's bounded decode)."""

from __future__ import annotations


class TextEncoding:
    """Text re-encoded as UTF-8 for reading."""

    @staticmethod
    def as_utf8(raw: bytes) -> bytes:
        """UTF-16 text, re-encoded as UTF-8; anything else unchanged.

        Every detector matches bytes, and a UTF-16 file interleaves each ASCII character with a NUL:
        `curl ... | sh` written to a PowerShell script saved as UTF-16 -- Windows PowerShell 5's
        default -- matched no pattern and was then filed as binary for its NULs, so it was never
        read at all. Transcoded once here, it is read like any other script. Only with a byte-order
        mark, NULs where UTF-16 over a mostly-ASCII alphabet puts them, and a clean decode: a binary
        that happens to start `FF FE` stays as it is.
        """
        if not raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" not in raw[2:66]:
            return raw
        try:
            return raw.decode("utf-16").encode("utf-8")
        except UnicodeDecodeError:
            return raw

    @staticmethod
    def decoded(raw: bytes, data: bytes) -> str:
        """`data` (a prefix of `raw`, or all of it) decoded as the whole file is: UTF-8, past a UTF-8
        mark, or UTF-16 where its mark is borne out (`looks_utf16`); permissively, with
        ``errors="replace"``."""
        encoding = "utf-8"
        if raw.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
        elif raw.startswith((b"\xff\xfe", b"\xfe\xff")) and TextEncoding.looks_utf16(raw):
            encoding = "utf-16"
        try:
            return data.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            return data.decode("latin-1", errors="replace")

    @staticmethod
    def looks_utf16(raw: bytes) -> bool:
        """Corroborate a UTF-16 byte-order mark before trusting it.

        Those two bytes are not rare, and any file whose content happens to
        begin with them was previously decoded as UTF-16 and turned into noise.
        Real UTF-16 text over a mostly-ASCII alphabet is half NUL bytes, so
        their absence is decisive.
        """
        return b"\x00" in raw[2:66]


__all__ = ["TextEncoding"]
