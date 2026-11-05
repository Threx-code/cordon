"""Readers for file formats that arrive through the supply chain: models, documents, media.

Every reader here parses bytes it was given and never executes, loads or renders them. Each one is
bounded (size, depth, object count) and raises `FormatError` rather than guessing when input is
malformed or a limit is hit, so a caller can report "not examined" instead of "clean".
"""

from __future__ import annotations

import struct
import zipfile
import zlib
from functools import wraps
from typing import TYPE_CHECKING, ParamSpec, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

P = ParamSpec("P")
R = TypeVar("R")


class FormatError(Exception):
    """The input could not be read within the reader's limits. Safe to show."""


MALFORMED = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
    struct.error,
    NotImplementedError,
    RuntimeError,
    EOFError,
    IndexError,
    KeyError,
    ValueError,
    OverflowError,
    UnicodeError,
    OSError,
)
"""What the standard library raises on a crafted file: an unsupported zip method, an encrypted
member, a short read, a bad length. All mean the same thing to a caller: not readable."""


class FormatBounds:
    """Readers that may raise only FormatError, whatever the input does."""

    @staticmethod
    def bounded(reader: Callable[P, R]) -> Callable[P, R]:
        """Let a reader raise only `FormatError`, whatever the input made the standard library do."""

        @wraps(reader)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return reader(*args, **kwargs)
            except FormatError:
                raise
            except MALFORMED as exc:
                raise FormatError(f"malformed input ({type(exc).__name__})") from exc
            except RecursionError as exc:
                raise FormatError("the input nests deeper than the reader follows") from exc

        return wrapper


__all__ = ["MALFORMED", "FormatBounds", "FormatError"]
