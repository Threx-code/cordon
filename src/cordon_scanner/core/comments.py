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

HASH = ("#",)
SLASHES = ("//",)
DASHES = ("--",)
ANGLE = ("<!--",)

LINE_COMMENT_OPENERS: dict[str, tuple[str, ...]] = {
    "cmake": HASH,
    "dockerfile": HASH,
    "elixir": HASH,
    "makefile": HASH,
    "powershell": HASH,
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

    A pass over the file, cached by the caller, which is what `documentation_spans`
    and `test_module_spans` in the secrets detector already do for Python docstrings
    and Rust test modules. String literals are tracked so that `"/*"` inside one does
    not open a block, and a `//` line comment is skipped so that `// /*` does not
    either. An unterminated block runs to the end of the file, which is what a
    compiler would do with it.
    """
    if language not in BLOCK_COMMENT_LANGUAGES:
        return ()

    spans: list[tuple[int, int]] = []
    index = 0
    length = len(text)
    quote: str | None = None
    line_openers = LINE_COMMENT_OPENERS.get(language or "", ())
    while index < length:
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote or char == "\n":
                # A newline closes an unterminated literal, so one stray quote in a
                # file does not swallow the rest of it.
                quote = None
            index += 1
            continue
        if char in QUOTES:
            quote = char
            index += 1
            continue
        if text.startswith(BLOCK_OPEN, index):
            close = text.find(BLOCK_CLOSE, index + len(BLOCK_OPEN))
            end = length if close == -1 else close + len(BLOCK_CLOSE)
            spans.append((index, end))
            index = end
            continue
        if any(text.startswith(opener, index) for opener in line_openers):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue
        index += 1
    return tuple(spans)


def inside_spans(spans: tuple[tuple[int, int], ...], offset: int) -> bool:
    """Whether `offset` falls inside any of `spans`."""
    return any(start <= offset < end for start, end in spans)


def is_commented(line: str, column: int, language: str | None) -> bool:
    """Whether the 0-indexed `column` of `line` falls inside a comment.

    `line` is one line, and the block-comment test is therefore a heuristic: a
    continuation line of a `/* ... */` block conventionally begins with `*`, which
    is what a documentation comment looks like in every C-family codebase. Opening
    the file and tracking block state from the top would be exact and would cost a
    pass over every file to change the answer for a handful of lines.
    """
    openers = LINE_COMMENT_OPENERS.get(language or "")
    if not openers:
        return False

    stripped = line.lstrip()
    if language in BLOCK_COMMENT_LANGUAGES and stripped.startswith(("*", "*/")):
        # Inside a `/* ... */`, or closing one.
        return True
    if stripped.startswith("#!"):
        # A shebang is not a comment about code, it is how the file is run, and a
        # capability named in it is real.
        return False

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
        if language in BLOCK_COMMENT_LANGUAGES and line.startswith("/*", index):
            return column >= index
        for opener in openers:
            if line.startswith(opener, index):
                return column >= index
        index += 1
    return False


__all__ = [
    "BLOCK_COMMENT_LANGUAGES",
    "LINE_COMMENT_OPENERS",
    "block_comment_spans",
    "inside_spans",
    "is_commented",
]
