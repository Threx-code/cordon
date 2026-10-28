"""Secret detection.

Two rules govern this detector, and both are unusual enough to state plainly.

**No path is ever exempt.** Excluding a path from secret scanning inverts the
control. The usual reasoning is that ``.env`` and ``*.pem`` are ignored by
version control anyway, so flagging them is redundant -- but a committed copy of
one of those files is the single case a secret scanner exists to catch. It
happens through a forced add, a merge from a branch carrying different ignore
rules, a nested directory the pattern misses, or a rename. In every one of those
the file *is* committed, and a path exemption says "do not look".

**Findings never carry the secret.** Evidence is hash-only and cannot be
relaxed by configuration. A finding travels into CI logs, pull-request comments
and SARIF uploaded to third parties, all of which outlive and out-reach the
repository. The tool that finds a leaked credential must not be the mechanism
that spreads it. The match hash is still enough to deduplicate, to compare two
scans, and to confirm a rotation actually changed the value.

Allowlisting is therefore by literal value, never by path. Exempting the one
fixture that must look real is precise; exempting the file it lives in is not.
"""

from __future__ import annotations

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)

RULE_MATERIAL_CEILING = Severity.INFO
"""The most a finding inside another analyser's rule material may be reported at.

Lower than `FIXTURE_CEILING`, because the two say different things. A credential
under `tests/` is a real string that was probably generated for the suite and
might not have been. A credential on the line after `// ruleid: adafruit-api-key`
is a sample published so that a scanner can be tested against it -- the file
exists to be detected, and there is no version of that finding a reader acts on.

INFO rather than nothing, for the reason in `core.samples`: a predicate that
deleted findings would be a one-line bypass. INFO sits below the default
reporting threshold, so the finding is out of a reader's way by default and is
there for anyone who asks for it."""

FIXTURE_CONFIDENCE = Confidence.MEDIUM
"""And the most it may claim about being live.

This one is confidence rather than severity because it is a statement about
what the value is: a PEM private-key header under `tests/fixtures` is
certainly a private key and is very unlikely to be one that protects
anything."""


DOCUMENTED_NAMES = frozenset(
    {
        "DOCUMENTATION",
        "EXAMPLES",
        "RETURN",
        "RETURNS",
        "USAGE",
        "HELP",
        "EPILOG",
        "LONG_DESCRIPTION",
        "__doc__",
    }
)
"""Module-level names whose value is documentation rather than configuration.

`DOCUMENTATION`, `EXAMPLES` and `RETURN` are Ansible's module contract: every one
of its thousands of modules carries a YAML document inside a string, and the
examples in it are written the way examples are -- a `password` key with a
memorable phrase after it, a `token` key with a UUID, a `bootstrap_secret` with
another one.

`community.general` produced 29 findings and every one was inside such a block,
including the Slack module's own description of what a bot token looks like. The
path-based documentation test cannot see this: the file is `plugins/modules/
consul_token.py`, which is source, and the documentation is inside it.

Described rather than quoted, because this project scans itself and a faithful
copy of those three lines is three findings -- which is how the attribute-docstring
case below was found."""


class SourceSpans:
    """The documentation and test regions inside a source file."""

    @staticmethod
    def documentation_spans(text: str) -> tuple[tuple[int, int], ...]:
        """Byte ranges of this Python source that are documentation.

        Every docstring, and every module-level assignment of a string literal to one of
        `DOCUMENTED_NAMES`. Parsed rather than matched, because the question is which
        STRING a byte offset falls in and a regex cannot answer that about a language
        with three quoting styles and nesting.

        Returns nothing for anything that does not parse, which is the safe direction:
        an unparsable file gets no exemption.
        """
        import ast

        try:
            tree = PythonSyntax.shared(text)
        except (SyntaxError, ValueError, RecursionError):
            return ()

        encoded = text.encode("utf-8", errors="surrogatepass")
        starts = [0]
        for index, byte in enumerate(encoded):
            if byte == 0x0A:
                starts.append(index + 1)

        def span(node: ast.AST) -> tuple[int, int] | None:
            """The byte range a node occupies.

            `col_offset` is a UTF-8 byte offset within its line, which is what this needs
            and is the one thing about `ast` positions that is convenient here."""
            line = getattr(node, "lineno", None)
            end_line = getattr(node, "end_lineno", None)
            if line is None or end_line is None or not 0 < end_line <= len(starts):
                return None
            start = starts[line - 1] + getattr(node, "col_offset", 0)
            end = starts[end_line - 1] + getattr(node, "end_col_offset", 0)
            if end <= start:
                return None
            return start, min(end, len(encoded))

        found: list[tuple[int, int]] = []
        for node in PythonSyntax.nodes(tree):
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                # Every bare string statement, which is every docstring: a module's, a
                # class's, a function's, and the attribute docstrings PEP 258 describes --
                # the string that follows an assignment and documents it. A string
                # expression whose value is discarded does nothing at runtime; it is there
                # to be read.
                #
                # This project's own source made the case: the docstring under
                # `DOCUMENTED_NAMES` quotes the Ansible examples that prompted this, and
                # the self-scan reported three credentials in it. Collecting only the first
                # statement of each scope -- which is what "docstring" means to `ast` --
                # missed the convention this codebase is written in.
                bounds = span(node)
                if bounds:
                    found.append(bounds)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if not isinstance(node.value.value, str):
                    continue
                names = {target.id for target in node.targets if isinstance(target, ast.Name)}
                if names & DOCUMENTED_NAMES:
                    bounds = span(node)
                    if bounds:
                        found.append(bounds)
        return tuple(found)

    @staticmethod
    def _item_start(encoded: bytes, after: int) -> int:
        """Where the item a `#[cfg(test)]` applies to begins.

        Past the whitespace, the comments and any FURTHER attributes. The last of those is
        why this is a loop and not a `find`: `#[cfg(test)]` followed by `#[derive(Debug)]`
        has its first bracket inside the second attribute, and stopping there would make
        the span the derive and not the module.
        """
        index = after
        limit = min(len(encoded), after + ATTRIBUTE_SKIP)
        while index < limit:
            byte = encoded[index]
            if byte in b" \t\r\n":
                index += 1
            elif encoded.startswith(b"//", index):
                newline = encoded.find(b"\n", index)
                index = limit if newline < 0 else newline + 1
            elif encoded.startswith(b"/*", index):
                close = encoded.find(b"*/", index)
                index = limit if close < 0 else close + 2
            elif byte == 0x23:  # `#`, the start of another attribute
                end = SourceSpans._matching(encoded, encoded.find(b"[", index))
                if end < 0:
                    return index
                index = end
            else:
                return index
        return index

    @staticmethod
    def _matching(encoded: bytes, opening: int) -> int:
        """One past the bracket closing the one at `opening`, or -1 if it never closes.

        Counts all three bracket kinds together rather than only the one it was given,
        because a brace inside square brackets has to be paired before the square ones
        can close. Strings are not parsed, which is the approximation this accepts: a
        lone unpaired bracket inside a string literal moves the end of the span.
        """
        if opening < 0 or encoded[opening] not in OPENERS:
            return -1
        depth = 0
        index = opening
        while index < len(encoded):
            byte = encoded[index]
            if byte in OPENERS:
                depth += 1
            elif byte in (0x7D, 0x5D, 0x29):
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return -1

    @staticmethod
    def test_module_spans(text: str) -> tuple[tuple[int, int], ...]:
        """Byte ranges of Rust test code.

        From each `#[cfg(test)]` to the end of the item it introduces. Usually that item is
        `mod tests { ... }` and the end is the matching brace, but the attribute is legal on
        anything, and `atuinsh/atuin` puts it on a struct FIELD: every pattern in its
        redaction table carries a `#[cfg(test)] tests: &[Test { ... }, Test { ... }]` list of
        sample credentials. Taking the first brace ended that span inside the first element
        and reported the second, so the opener is whichever of `{`, `[` or `(` comes first.

        A statement has no brackets at all -- `#[cfg(test)] use super::*;` -- and ends at its
        semicolon. An item whose brackets never close ends the span at the end of the file,
        which is where a Rust test module conventionally ends anyway.
        """
        encoded = text.encode("utf-8", errors="surrogatepass")
        marker = TEST_MODULE_ATTRIBUTE.encode()
        if marker not in encoded[:MAX_TEST_MODULE_SCAN]:
            return ()

        spans: list[tuple[int, int]] = []
        position = 0
        while True:
            start = encoded.find(marker, position)
            if start < 0:
                break
            head = SourceSpans._item_start(encoded, start + len(marker))
            opening = -1
            for index in range(head, min(len(encoded), head + ATTRIBUTE_SKIP)):
                byte = encoded[index]
                if byte in OPENERS:
                    opening = index
                    break
                if byte == 0x3B:  # `;` -- a statement, which is the whole item
                    spans.append((start, index + 1))
                    break
            else:
                opening = -1
            if opening < 0:
                if not spans or spans[-1][0] != start:
                    spans.append((start, len(encoded)))
                position = spans[-1][1]
                continue
            end = SourceSpans._matching(encoded, opening)
            spans.append((start, len(encoded) if end < 0 else end))
            position = spans[-1][1]
        return tuple(spans)


TEST_MODULE_ATTRIBUTE = "#[cfg(test)]"
"""Rust's marker for code that only exists when the tests are built.

Rust keeps unit tests in the file they test, at the bottom, under
`#[cfg(test)] mod tests { ... }`. That is the language's convention rather than a
layout choice, so a path glob cannot see it: `rustfs/src/auth.rs` is source, and
its 51 credential findings were assertions about constant-time comparison using
`AKIAIOSFODNN7EXAMPLE` as a sample.

`rustfs` itself splits its own source on this exact string for its own tooling,
two hundred lines below one of the findings.
"""

MAX_TEST_MODULE_SCAN = 4_000_000
"""A bound on the brace matching below, so a pathological file cannot spin."""

OPENERS = {0x7B: 0x7D, 0x5B: 0x5D, 0x28: 0x29}
"""The three bracket pairs Rust delimits an item with: braces, square, round."""

ATTRIBUTE_SKIP = 4_000
"""How far past one `#[cfg(test)]` to look for the item it applies to.

Enough for a stack of attributes and a doc comment between the marker and the thing
it marks, and short enough that a marker applying to nothing cannot reach across a
file to the next unrelated block.
"""


__all__ = [
    "ATTRIBUTE_SKIP",
    "DOCUMENTED_NAMES",
    "FIXTURE_CONFIDENCE",
    "MAX_TEST_MODULE_SCAN",
    "OPENERS",
    "RULE_MATERIAL_CEILING",
    "TEST_MODULE_ATTRIBUTE",
    "SourceSpans",
]
