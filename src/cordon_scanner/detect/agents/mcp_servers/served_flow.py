"""What an MCP server's handlers hand the agent to read, followed through the code.

A tool's result, a resource's content and a prompt's messages are all text the agent reads as its own
context. `McpServerSource._tool_returns` reads the literals a `return` names; an attacker who keeps the
order in a module constant, a list joined at run time, a template, a `result += NOTE` or a base64 string
the handler decodes is not read by it. This follows the text to where it is written:

```
  handler           @mcp.tool() @mcp.prompt() @mcp.resource(uri) @server.call_tool() @server.get_prompt()
                    @server.read_resource() · server.tool(...) .prompt(...) .resource(...) .registerPrompt(...)
                    setRequestHandler(CallTool | GetPrompt | ReadResource ...)
        │
        └── what it returns ──► a literal · a constant · an f-string or template · a joined list ·
                                a name it appended to (`result += NOTE`) · a decoded literal (base64, hex,
                                `atob`, `Buffer.from`, `chr` lists) · a helper's own return
```

The text is folded, never run: a closed table of string operations is evaluated on constants (nothing is
imported, called or executed), within fixed bounds. This module holds what the Python and JavaScript
readers share (`served_python.py`, `served_js.py`); `served_text.py` gives each served text once and
reads it.
"""

from __future__ import annotations

import binascii
import codecs
import zlib
from dataclasses import dataclass
from typing import ClassVar, Final

#: Files a JavaScript or TypeScript server's handlers live in.
JS_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx")
#: The most text one served value is read to, and the most served values one file gives.
MAX_TEXT: Final = 60_000
MAX_SERVED: Final = 200
#: What the table of string operations may spend on one handler.
FOLD_BUDGET: Final = 4_000
#: How deep a value is folded (a name's definition, a helper's return, a nested call).
FOLD_DEPTH: Final = 24
#: How many helper functions a served value may pass through.
HELPER_DEPTH: Final = 2
#: The largest decoded value a decoder is asked for (a decompression bomb stops here).
DECODE_LIMIT: Final = 1_000_000


@dataclass(frozen=True, slots=True)
class Served:
    """One text a handler hands the agent: `kind` is `result`, `resource`, `prompt`, `error` (the
    message of an exception the handler raises, or of a result marked as an error) or `notification`
    (a log or progress message sent to the client); `start` and `end` are character offsets of the
    value in the file; `via` says how the text was reached (`literal`, `constant`, `joined`,
    `appended`, `decoded`, `helper`)."""

    kind: str
    text: str
    start: int
    end: int
    via: tuple[str, ...]


class Decode:
    """The decoders a handler may wrap a literal in; each returns None for what does not decode.
    Pure string operations: bounded, never run code."""

    @staticmethod
    def base64(value: str | bytes, *, urlsafe: bool = False) -> bytes | None:
        raw = value.encode("utf-8", "replace") if isinstance(value, str) else value
        compact = b"".join(raw.split())
        if not compact or len(compact) > 2 * DECODE_LIMIT:
            return None
        if urlsafe:
            compact = compact.replace(b"-", b"+").replace(b"_", b"/")
        compact = compact.rstrip(b"=")
        try:
            return binascii.a2b_base64(compact + b"=" * (-len(compact) % 4))
        except binascii.Error:
            return None

    @staticmethod
    def hexadecimal(value: str | bytes) -> bytes | None:
        raw = value.encode("utf-8", "replace") if isinstance(value, str) else value
        compact = b"".join(raw.split())
        if not compact or len(compact) > 2 * DECODE_LIMIT:
            return None
        try:
            return binascii.unhexlify(compact)
        except (binascii.Error, ValueError):
            return None

    @staticmethod
    def inflate(raw: bytes) -> bytes | None:
        """A zlib, gzip or raw deflate stream, at most `DECODE_LIMIT` bytes of it."""
        for bits in (zlib.MAX_WBITS, 16 + zlib.MAX_WBITS, -zlib.MAX_WBITS):
            expander = zlib.decompressobj(bits)
            try:
                out = expander.decompress(raw, DECODE_LIMIT)
            except zlib.error:
                continue
            if out:
                return out
        return None

    @staticmethod
    def text(raw: bytes | None) -> str:
        return "" if raw is None else raw.decode("utf-8", "replace")[:MAX_TEXT]

    @staticmethod
    def rot13(value: str) -> str:
        return codecs.encode(value, "rot13")

    @classmethod
    def base64_text(cls, content: str) -> str:
        return cls.text(cls.base64(content))

    @classmethod
    def base64url_text(cls, content: str) -> str:
        return cls.text(cls.base64(content, urlsafe=True))

    @classmethod
    def hex_text(cls, content: str) -> str:
        return cls.text(cls.hexadecimal(content))

    #: The names `Buffer.from(text, name)` and `codecs.decode(text, name)` give an encoding, and the
    #: method here that reads each.
    NAMES: ClassVar[dict[str, str]] = {
        "base64": "base64_text",
        "base64_codec": "base64_text",
        "base64url": "base64url_text",
        "hex": "hex_text",
        "hex_codec": "hex_text",
        "rot13": "rot13",
        "rot_13": "rot13",
    }

    @classmethod
    def named(cls, encoding: str, content: str) -> str | None:
        """`content` decoded as the encoding of that name, or None for a name not in the table."""
        method = cls.NAMES.get(encoding.strip().lower().replace("-", "_"))
        return None if method is None else str(getattr(cls, method)(content))


__all__ = [
    "DECODE_LIMIT",
    "FOLD_BUDGET",
    "FOLD_DEPTH",
    "HELPER_DEPTH",
    "JS_SUFFIXES",
    "MAX_SERVED",
    "MAX_TEXT",
    "Decode",
    "Served",
]
