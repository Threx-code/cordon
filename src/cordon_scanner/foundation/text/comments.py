"""Whether a position in a line is code or a remark about code.

A capability named in a comment is not a capability, and a credential-shaped
phrase in a sentence is not a credential. Both showed up in the measurement
corpus on files nobody would call suspicious:

    # systemd-detect-virt reports lxc inside containers

is a line of `misc/error_handler.func` in `community-scripts/ProxmoxVE`, and it
was reported as `SUSPECT.ANTI_ANALYSIS.001` -- a rule about code checking whether
it is being observed, matched against a sentence explaining that it does not.

Two TensorFlow headers were reported as assigning credentials on the strength of
comment prose. One documents an environment variable whose name ends in `_FILTER`
by showing it set to a quoted list of compiler pass names. The other explains what
a compiler pass renames instructions to, in a sentence of the form "after this
pass" followed by a colon and an example name -- a credential word, a separator
and a high-entropy-looking value, in an English sentence.

They are written out here as descriptions rather than as the lines themselves,
because this project scans its own source and a faithful copy would be a true
positive.

## What this does and does not claim

Line comments only, plus the continuation lines of a C-style block, recognised by
language. Quote state is tracked, so the `#` in `curl "http://x/#frag"` is not a
comment and the fragment after it is not commented out.

A full parse is not attempted and is not needed. The question is whether the
bytes at one offset will be executed, the syntaxes that answer it are short, and
being wrong in the direction of "this is code" costs nothing: an unknown language
has no openers and nothing is suppressed.

## Where it is applied, and where it deliberately is not

Capability matching, where being in a comment settles the matter: a comment does
not run. And the generic credential-assignment rule, whose evidence is a name and
an entropy measure -- weak enough that prose mentioning a password defeats it.

NOT the provider patterns. `ghp_` followed by thirty-six characters is a GitHub
token wherever it sits, and a credential somebody commented out rather than
rotated has leaked exactly as far as one on a live line. Suppressing those would
trade a small amount of noise for the loudest kind of miss.
"""

from __future__ import annotations

import functools
import re
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

HASH = ("#",)
SLASHES = ("//",)
DASHES = ("--",)
ANGLE = ("<!--",)

#: A URL scheme ending exactly where a `//` starts: `https:`, `file:`, `ws:`. Searched only in the few
#: characters before the `//`, so a megabyte line of links stays linear.
URL_SCHEME_BEFORE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,31}:$")

LINE_COMMENT_OPENERS: dict[str, tuple[str, ...]] = {
    "cmake": HASH,
    "dockerfile": HASH,
    "elixir": HASH,
    "makefile": HASH,
    "perl": HASH,
    "powershell": HASH,
    "r": HASH,
    "python": HASH,
    "ruby": HASH,
    "shell": HASH,
    "toml": HASH,
    "yaml": HASH,
    "c": SLASHES,
    "cpp": SLASHES,
    "csharp": SLASHES,
    "dart": SLASHES,
    "go": SLASHES,
    "groovy": SLASHES,
    "java": SLASHES,
    "javascript": SLASHES,
    "json": SLASHES,
    "kotlin": SLASHES,
    "rust": SLASHES,
    "scala": SLASHES,
    "swift": SLASHES,
    "typescript": SLASHES,
    # Two syntaxes, and both are used in the wild.
    "php": HASH + SLASHES,
    "haskell": DASHES,
    "lua": DASHES,
    "sql": DASHES,
    "markdown": ANGLE,
    "xml": ANGLE,
}
"""Line-comment openers, by language name as `LanguageRegistry` reports it.

`json` is here because comment-bearing JSON is ordinary in practice: every
`tsconfig.json`, `devcontainer.json` and VS Code settings file has `//` lines in
it, and a parser that rejects them is not the parser those files are read by.
"""

BLOCK_COMMENT_LANGUAGES = frozenset(
    {
        "c",
        "cpp",
        "csharp",
        "dart",
        "go",
        "groovy",
        "java",
        "javascript",
        "json",
        "kotlin",
        "php",
        "rust",
        "scala",
        "swift",
        "typescript",
    }
)
"""Languages with `/* ... */`, whose continuation lines start with `*`."""

QUOTES = ("'", '"', "`")

BLOCK_OPEN = "/*"
BLOCK_CLOSE = "*/"

BLOCK_DELIMITERS: dict[str, tuple[str, str]] = {
    **dict.fromkeys(BLOCK_COMMENT_LANGUAGES, (BLOCK_OPEN, BLOCK_CLOSE)),
    # PowerShell's block comment, where a script's help and usage live: `irm <url> | iex` written
    # there as the instructions for running it is prose, not code.
    "powershell": ("<#", "#>"),
}
"""Each language's block comment, opener and closer."""

LANGUAGE_QUOTES: dict[str, tuple[str, ...]] = {
    # A backtick is PowerShell's escape character, not a quote.
    "powershell": ("'", '"'),
}


class SourceComments:
    """Where comments and docstrings are in source text."""

    @staticmethod
    @functools.lru_cache(maxsize=4)
    def _scanner(language: str) -> re.Pattern[str]:
        """One pattern matching every position the scan has to stop at.

        The scan jumps rather than steps. Everything between two interesting
        positions -- a quote, a block opener, a line opener -- is by definition
        ordinary code that the loop would do nothing with, so `re.search` skips it
        in C instead of a Python iteration and a `startswith` per character.
        """
        openers = [re.escape(opener) for opener in LINE_COMMENT_OPENERS.get(language, ())]
        # Longest first, so `//` is not matched as a prefix of a longer opener by an
        # alternation that happens to list the shorter one earlier.
        openers.sort(key=len, reverse=True)
        opener, _ = BLOCK_DELIMITERS.get(language, (BLOCK_OPEN, BLOCK_CLOSE))
        quotes = LANGUAGE_QUOTES.get(language, QUOTES)
        alternatives = [re.escape(opener), *openers, "[" + re.escape("".join(quotes)) + "]"]
        return re.compile("|".join(alternatives))

    @staticmethod
    @functools.lru_cache(maxsize=4)
    def block_comment_spans(text: str, language: str | None) -> tuple[tuple[int, int], ...]:
        """Where the `/* ... */` blocks are, as half-open offset ranges.

        The per-line heuristic in `is_commented` asks whether a continuation line begins
        with `*`, which is what a documentation comment looks like in every C-family
        codebase -- and is not what a paragraph of prose looks like. Praxis's
        `AuthForcePasswordReset.tsx` explains why the form carries `method="post"` by
        quoting the URL that leaked when hydration failed on a dev build:

            /sign-in?email=...&password=...

        Indented prose inside a block, on a line that starts with a slash. Reported as a
        credential assignment at HIGH, three times across three auth templates, in the
        comment that exists to explain why the leak was fixed.

        A pass over the file, cached here as well as by the caller: the capability,
        secret and obfuscation detectors each ask for the same file's spans, and the
        answer depends only on the arguments. The cache is small on purpose -- it
        serves the detectors looking at the file currently being scanned, not a
        repository's worth of them.

        String literals are tracked so that `"/*"` inside one does not open a block,
        and a `//` line comment is skipped so that `// /*` does not either. An
        unterminated block runs to the end of the file, which is what a compiler
        would do with it.
        """
        delimiters = BLOCK_DELIMITERS.get(language or "")
        if delimiters is None:
            return ()
        opener, closer = delimiters
        quotes = LANGUAGE_QUOTES.get(language or "", QUOTES)

        spans: list[tuple[int, int]] = []
        length = len(text)
        scanner = SourceComments._scanner(language or "")
        index = 0
        while index < length:
            match = scanner.search(text, index)
            if match is None:
                break
            index = match.start()
            token = match.group()

            if token in quotes:
                index = SourceComments._skip_literal(text, index + 1, token, length)
                continue

            if token == opener:
                close = text.find(closer, index + len(opener))
                end = length if close == -1 else close + len(closer)
                spans.append((index, end))
                index = end
                continue

            # A line comment: everything to the newline is neither code nor a block.
            newline = text.find("\n", index)
            index = length if newline == -1 else newline + 1
        return tuple(spans)

    @staticmethod
    def _skip_literal(text: str, index: int, quote: str, length: int) -> int:
        """The offset just past a string literal that opened at `index - 1`.

        A newline closes an unterminated literal, so one stray quote in a file does
        not swallow the rest of it, and a backslash escapes whatever follows it --
        including the closing quote, and including another backslash.
        """
        while index < length:
            char = text[index]
            if char == "\\":
                index += 2
                continue
            if char == quote or char == "\n":
                return index + 1
            index += 1
        return length

    @staticmethod
    def inside_spans(spans: tuple[tuple[int, int], ...], offset: int) -> bool:
        """Whether `offset` falls inside any of `spans`."""
        return any(start <= offset < end for start, end in spans)

    @staticmethod
    def comment_column(line: str, language: str | None) -> int | None:
        """The column at which a comment begins on this line, or `None` for none.

        A property of the line alone, which is the point: the answer does not depend
        on which column is being asked about, so a file with forty matches on one line
        can compute it once. `is_commented` was scanning the whole line on every call,
        and on a single-line bundle that is the whole file every time -- twenty-two
        million `startswith` calls on the ten-megabyte payload of the Shai-Hulud npm
        worm, which is most of the five-second budget that file then exceeded.

        `line` is one line, and the block-comment test is therefore a heuristic: a
        continuation line of a `/* ... */` block conventionally begins with `*`, which
        is what a documentation comment looks like in every C-family codebase. Opening
        the file and tracking block state from the top would be exact and would cost a
        pass over every file to change the answer for a handful of lines.
        """
        openers = LINE_COMMENT_OPENERS.get(language or "")
        if not openers:
            return None

        stripped = line.lstrip()
        if language in BLOCK_COMMENT_LANGUAGES and stripped.startswith(("*", "*/")):
            # Inside a `/* ... */`, or closing one. The whole line is comment.
            return 0
        if stripped.startswith("#!"):
            # A shebang is not a comment about code, it is how the file is run, and a
            # capability named in it is real.
            return None

        quote: str | None = None
        index = 0
        length = len(line)
        while index < length:
            char = line[index]
            if quote is not None:
                if char == "\\":
                    index += 2
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue
            if char in QUOTES:
                quote = char
                index += 1
                continue
            if line.startswith("//", index) and URL_SCHEME_BEFORE.search(
                line, max(0, index - 33), index
            ):
                # `https://`: a URL, not a comment. A line that begins inside a string opened on
                # an earlier line -- a template literal in a bundle -- has no quote to show for it,
                # and the first link in the text was read as the start of a comment: Amazon Q
                # 1.84.0's bundle hid its `q --trust-all-tools` command that way, behind
                # `https://docs.aws.amazon.com/...` earlier on the same line.
                index += 2
                continue
            if language in BLOCK_COMMENT_LANGUAGES and line.startswith("/*", index):
                return index
            for opener in openers:
                if line.startswith(opener, index):
                    return index
            index += 1
        return None

    @staticmethod
    def is_commented(line: str, column: int, language: str | None) -> bool:
        """Whether the 0-indexed `column` of `line` falls inside a comment."""
        start = SourceComments.comment_column(line, language)
        return start is not None and column >= start

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
    def manifest_metadata_spans(raw: bytes) -> tuple[tuple[int, int], ...]:
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
                end = SourceComments._json_string_end(raw, i)
                if depth == 1 and key is None and raw[end : end + 64].lstrip().startswith(b":"):
                    key = raw[i + 1 : end - 1]
                    named = named or key == b"name"
                elif depth == 1:
                    if key in SourceComments.METADATA_KEYS:
                        spans.append((i, end))
                    key = None
                i = end
                continue
            if c in (b"{", b"["):
                if depth == 1 and key in SourceComments.METADATA_KEYS:
                    end = SourceComments._json_value_end(raw, i)
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
                i = SourceComments._json_string_end(raw, i)
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
    def docstring_spans(raw: bytes, language: str | None) -> tuple[tuple[int, int], ...]:
        """Byte ranges of Python docstrings, and of a JSON manifest's project metadata
        (`manifest_metadata_spans`).

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
            return SourceComments.manifest_metadata_spans(raw)
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


__all__ = ["BLOCK_COMMENT_LANGUAGES", "LINE_COMMENT_OPENERS", "SourceComments"]
