"""Cordon's mark, as the MCP server shows it to clients that display server icons.

The geometry of `docs/assets/logo-mark.svg`, inlined as a data URI: nothing is fetched to show it,
so a client rendering it makes no request and leaks nothing about where it runs.
"""

from __future__ import annotations

import base64
from typing import Final

MARK_SVG: Final = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
    '<path d="M 43.47 15.62 A 20 20 0 1 0 43.47 48.38" fill="none" stroke="#1f7a6f" '
    'stroke-width="8" stroke-linecap="round"/>'
    '<rect x="43.5" y="26.5" width="11" height="11" rx="2.5" fill="#d9822b"/></svg>'
)

#: The `icons` entry of the server's Implementation (protocol 2025-11-25 and later).
ICONS: Final = [
    {
        "src": "data:image/svg+xml;base64," + base64.b64encode(MARK_SVG.encode()).decode(),
        "mimeType": "image/svg+xml",
        "sizes": ["any"],
    }
]
