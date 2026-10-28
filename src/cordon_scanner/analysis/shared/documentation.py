"""The parts of a file that document code rather than being it: Python docstrings, and a JSON
manifest's project metadata.

`SourceComments` (`foundation/text/comments.py`) finds comments with a line scan; these need more:
a docstring is told from an ordinary string by where it sits in the parse, and a manifest's metadata
by its key at the top of the object. A host a docstring describes, or the repository URL a
`package.json` names, is not one the code contacts.
"""

from __future__ import annotations

import functools
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class DocumentationSpans:
    """Byte ranges of a file that are documentation, not code."""

    #: A manifest's fields about the project, which no install fetches: where its source, home
    #: page and issue tracker are, who wrote it, how to fund it.
    METADATA_KEYS: ClassVar[frozenset[bytes]] = frozenset(
        {
            b"repository",
            b"homepage",
            b"bugs",
            b"author",
            b"contributors",
            b"maintainers",
            b"funding",
        }
    )

    @staticmethod
    def manifest_metadata(raw: bytes) -> tuple[tuple[int, int], ...]:
        """Byte ranges of a JSON manifest's project metadata (`METADATA_KEYS`, top level only):
        `iflow-open-engine`'s `"repository": {"url": "http://<ip>:13000/..."}` names where the
        source is kept, and npm contacts none of it at install (review 98 G6). Only for an object
        with a top-level `name`; what a script or a config value holds is not in these."""
        spans: list[tuple[int, int]] = []
        depth, i, n = 0, 0, len(raw)
        key: bytes | None = None
        named = False
        while i < n:
            c = raw[i : i + 1]
            if c == b'"':
                end = DocumentationSpans._json_string_end(raw, i)
                if depth == 1 and key is None and raw[end : end + 64].lstrip().startswith(b":"):
                    key = raw[i + 1 : end - 1]
                    named = named or key == b"name"
                elif depth == 1:
                    if key in DocumentationSpans.METADATA_KEYS:
                        spans.append((i, end))
                    key = None
                i = end
                continue
            if c in (b"{", b"["):
                if depth == 1 and key in DocumentationSpans.METADATA_KEYS:
                    end = DocumentationSpans._json_value_end(raw, i)
                    spans.append((i, end))
                    key, i = None, end
                    continue
                depth += 1
            elif c in (b"}", b"]"):
                depth -= 1
                key = None if depth == 1 else key
            elif c == b"," and depth == 1:
                key = None
            i += 1
        return tuple(spans) if named else ()

    @staticmethod
    def _json_string_end(raw: bytes, start: int) -> int:
        """The offset just past the JSON string that opens at `start`."""
        i = start + 1
        while i < len(raw):
            if raw[i : i + 1] == b"\\":
                i += 2
                continue
            if raw[i : i + 1] == b'"':
                return i + 1
            i += 1
        return len(raw)

    @staticmethod
    def _json_value_end(raw: bytes, start: int) -> int:
        """The offset just past the JSON object or array that opens at `start`."""
        depth, i = 0, start
        while i < len(raw):
            c = raw[i : i + 1]
            if c == b'"':
                i = DocumentationSpans._json_string_end(raw, i)
                continue
            if c in (b"{", b"["):
                depth += 1
            elif c in (b"}", b"]"):
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return len(raw)

    @staticmethod
    @functools.lru_cache(maxsize=8)
    def of(raw: bytes, language: str | None) -> tuple[tuple[int, int], ...]:
        """Byte ranges of Python docstrings, and of a JSON manifest's project metadata
        (`manifest_metadata`).

        `block_comment_spans` covers `/* */` and `comment_column` covers `#`, and
        neither sees a triple-quoted string used as documentation -- which in Python
        is where a module explains itself.

        It matters because a string is also how a real request is written, so
        "inside a string" cannot separate the two. "Inside a docstring" can: a
        docstring is a bare string EXPRESSION, never an argument to a call. A module
        that writes `urlopen("https://x.example")` is contacting that host and one
        whose opening paragraph mentions it is not.

        `unslothai/unsloth` is the case. `studio/backend/cloudflare_tunnel.py`
        opens by explaining that "cloudflared quick tunnel gives a free
        https://*.trycloudflare.com URL that works anywhere, with no account" --
        an accurate description of the tool it drives, and `trycloudflare.com` is on
        the drop-point host list precisely because that property makes it a good
        exfiltration endpoint. Paired with a `platform.machine()` call a hundred
        lines below, the sentence was a `high` finding.

        Offsets are bytes, matching `ast`'s own `col_offset`, so they line up with
        the rest of the detector without a decode.
        """
        if language == "json":
            return DocumentationSpans.manifest_metadata(raw)
        if language != "python":
            return ()
        import ast

        try:
            tree = PythonSyntax.shared(raw)
        except (SyntaxError, ValueError, RecursionError):
            return ()

        # Line starts found with `bytes.find`, not a Python loop over every byte of the file: the
        # same offsets, without a million interpreter steps for a one-megabyte module. Three
        # detectors ask about the same file, so the answer is also kept per (bytes, language).
        starts = [0]
        newline = raw.find(b"\n")
        while newline != -1:
            starts.append(newline + 1)
            newline = raw.find(b"\n", newline + 1)

        def offset(line: int, column: int) -> int:
            if line < 1 or line > len(starts):
                return -1
            return starts[line - 1] + column

        spans: list[tuple[int, int]] = []
        for node in PythonSyntax.of(
            tree, ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef
        ):
            first = node.body[0] if node.body else None
            if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Constant):
                continue
            if not isinstance(first.value.value, str):
                continue
            start = offset(first.lineno, first.col_offset)
            end = offset(first.end_lineno or first.lineno, first.end_col_offset or 0)
            if 0 <= start < end:
                spans.append((start, end))
        return tuple(spans)


__all__ = ["DocumentationSpans"]
