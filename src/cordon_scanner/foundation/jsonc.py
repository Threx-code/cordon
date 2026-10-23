"""Parse JSON that carries `//` and `/* */` comments and trailing commas -- the form developer
tools accept and write (VS Code `settings.json` and tasks, `tsconfig.json`, dev-container configs).

`Jsonc.loads` returns the parsed value, or `None` when the text cannot be recovered as JSON. A caller
that scans a config file treats `None` as "parse this as text instead", never as "nothing here" -- a
comment or a trailing comma must not make a file go unscanned.

The comment stripper is string-aware: it never removes a `//` or `/*` that sits inside a JSON string
(a URL like `"https://example"` keeps its slashes), and it only drops a trailing comma that is
outside a string.
"""

from __future__ import annotations

import json
from typing import Any


class Jsonc:
    """JSON-with-comments parsing. Stateless; call the static methods."""

    @staticmethod
    def _strip(text: str) -> str:
        out: list[str] = []
        i, n = 0, len(text)
        in_str = esc = False
        while i < n:
            c = text[i]
            if in_str:
                out.append(c)
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                i += 1
                continue
            if c == '"':
                in_str = True
                out.append(c)
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
            elif c == ",":
                # Drop a trailing comma: the next non-space character closes an object or array.
                j = i + 1
                while j < n and text[j] in " \t\r\n":
                    j += 1
                if j < n and text[j] in "}]":
                    i += 1
                    continue
                out.append(c)
            else:
                out.append(c)
            i += 1
        return "".join(out)

    @staticmethod
    def loads(text: Any) -> Any | None:
        """Parse `text` as JSON, tolerating comments and trailing commas; `None` if unrecoverable.

        `text` is typed loosely so a caller can hand it a value that may not be a string."""
        if not isinstance(text, str):
            return None
        try:
            return json.loads(text)
        except ValueError:
            pass
        try:
            return json.loads(Jsonc._strip(text))
        except ValueError:
            return None
