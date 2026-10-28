"""Obfuscation by encoding: readable text written as escapes or character codes.

Long runs of `\\xNN`, `\\uNNNN` or character codes that decode to ordinary text: there is no reason to
write a string that way except to keep it out of a search. What the run decodes to, and how much of a
file is encoded and how much of that is text, decide whether it is reported -- and a run inside a
comment is a remark, not code."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)
from cordon_scanner.foundation.text.comments import SourceComments

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.code.obfuscation.text import Hit

ESCAPE_RUN = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}")

ESCAPE_UNIT = re.compile(rb"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
"""One escaped byte. Counted file-wide when no single run is long enough."""

CHAR_CODE_UNIT = re.compile(
    rb"(?:String\.fromCharCode|chr)\s{0,4}\(\s{0,4}\d{1,6}(?:\s{0,4},\s{0,4}\d{1,6}){0,32}"
)
"""One `fromCharCode`/`chr` call with its arguments, of any length."""

NUMERIC_ARG = re.compile(rb"\d{1,6}")
"""One numeric argument inside a character-code call."""

PRINTABLE_SHARE = 0.8
"""Share of decoded characters that must be printable ASCII.

A concealed string decodes to something a person would have typed -- a URL, a
command, source. A legitimate byte table decodes to bytes nobody types. Eight in
ten is loose enough for a payload with a few control characters in it and tight
enough to leave `\x7fELF` and a confusables map alone."""

CUMULATIVE_ENCODED_UNITS = 16
"""File-wide count at which split encoding is reported.

Twice the single-run threshold, so a file has to be doing substantially more
than one borderline construct before this fires. A legitimate small byte table
(`\x00\x01\x02`) stays well under; a payload divided to duck the per-run
threshold does not, because the division does not reduce the total."""

CHAR_CODE_RUN = re.compile(
    rb"(?:String\.fromCharCode|chr)\s{0,4}\(\s{0,4}\d{1,6}(?:\s{0,4},\s{0,4}\d{1,6}){7,16}"
)
"""A long run of numeric character codes.

Every repeat is bounded, including the whitespace runs. `\\s*` and `\\d+`
inside `{7,}` is unbounded nesting -- the shape a rule pack is refused for --
and eight codes is already decisive, so upper bounds cost nothing here."""

CONCEALED_TEXT = re.compile(
    r"(?i)[a-z][a-z0-9+.-]{1,9}://"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b[a-z0-9-]{2,63}\.(?:com|net|org|io|xyz|ru|cn|top|info|biz|me|cc|tk|su|pw|online|site|app"
    r"|dev|link|club|shop|live|sh|ws)\b"
    r"|/bin/|/tmp/|/etc/|\.ssh|id_rsa|cmd\.exe|powershell"
    r"|\b(?:require|child_process|eval|exec|execSync|spawn|Function|atob|btoa|Buffer|process|env"
    r"|fromCharCode|https?|net|socket|fs|os|writeFile|readFile|unlink|import|__import__|subprocess"
    r"|system|popen|getattr|setattr|globals|compile|marshal|base64|zlib|cookie|localStorage"
    r"|XMLHttpRequest|fetch|WebSocket|token|password|passwd|wallet|discord|telegram|webhook|curl"
    r"|wget|chmod|crontab|whoami|hostname|homedir|platform)\b"
)
"""What concealed text decodes to: an address, a path, a command, or the name of something that
runs code, reaches the network or holds a secret. A run of escapes that decodes to none of these
is data written as escapes -- curl's `"0123456789ABCDEF"`, a regular expression's
`[\x21\x23-\x7e]`, libmagic's `\x00OpenTimestamps\x00`, TLS's `"DOWNGRD\x01"` -- and was the
only code warning on 116 of 11,005 benign units rescanned, while what malware hides behind escapes
is a module name, a host or a command (review 98)."""

MIN_DISTINCT_ENCODED = 6
"""How many distinct characters a run of escapes must decode to.

Below this the escapes are a serialiser's output rather than something hidden:
one repeated escape is a convention, and a payload is text."""


class EncodingFindings:
    """The obfuscation findings for text hidden in escapes and character codes."""

    @staticmethod
    def _decoded(raw: bytes, unit_pattern: re.Pattern[bytes]) -> str:
        """What the escapes or character codes decode to, joined in order."""
        values: list[int] = []
        if unit_pattern is CHAR_CODE_UNIT:
            for call in unit_pattern.finditer(raw):
                values.extend(int(n) for n in NUMERIC_ARG.findall(call.group(0)))
        else:
            values.extend(int(escape.group(0)[2:], 16) for escape in unit_pattern.finditer(raw))
        return "".join(chr(value) for value in values if 0 < value < 0x110000)

    @staticmethod
    def _encoded_units(raw: bytes, unit_pattern: re.Pattern[bytes]) -> tuple[int, int, int]:
        """How many encoded characters the file holds, how many are text, and
        how many distinct values they decode to.

        Characters, not constructs. `fromCharCode(72,101,108,108)` twice is
        eight encoded characters written as two calls, and counting the calls
        would put it at two -- the same per-construct blindness the cumulative
        count exists to remove, moved up one level.

        The second number is how many of them decode to printable ASCII, which
        is what separates a concealed string from a table of magic bytes.
        """
        values: list[int] = []
        if unit_pattern is CHAR_CODE_UNIT:
            for call in unit_pattern.finditer(raw):
                values.extend(int(n) for n in NUMERIC_ARG.findall(call.group(0)))
        else:
            for escape in unit_pattern.finditer(raw):
                text = escape.group(0)
                try:
                    values.append(int(text[2:], 16))
                except ValueError:  # pragma: no cover - the pattern guarantees hex
                    continue
        printable = sum(1 for value in values if 0x20 <= value <= 0x7E)
        return (len(values), printable, len(set(values)))

    @classmethod
    def escapes(cls, content: FileContent) -> Iterable[Hit]:
        for pattern, label, unit_pattern, needed in (
            (ESCAPE_RUN, "escape sequences", ESCAPE_UNIT, (b"\\x", b"\\u")),
            (CHAR_CODE_RUN, "character codes", CHAR_CODE_UNIT, (b"chr", b"fromCharCode")),
        ):
            if not any(literal in content.raw for literal in needed):
                # What every match of both patterns contains. Without it the run finds nothing
                # and the file-wide count is zero, under `CUMULATIVE_ENCODED_UNITS` -- the
                # `continue` below, reached without two scans of the file.
                continue
            match = pattern.search(content.raw)
            if match is None:
                # Nothing crosses the single-construct threshold. Count across
                # the whole file before concluding there is nothing here.
                #
                # The thresholds were per-construct, so splitting stayed under
                # them: two `fromCharCode` calls of four arguments each, or a
                # seven-escape run, produced nothing while a single eight did.
                # An attacker reads the threshold off the rule and writes one
                # fewer, which makes a per-construct count a number to duck
                # rather than a measurement.
                total, printable, distinct = cls._encoded_units(content.raw, unit_pattern)
                if total < CUMULATIVE_ENCODED_UNITS:
                    continue
                if distinct < MIN_DISTINCT_ENCODED:
                    # An encoder's convention, not concealment. Go's
                    # `encoding/json` writes `&`, `<` and `>` as `\u0026`,
                    # `\u003c` and `\u003e` by default, so every JSON document
                    # Go has ever written is a long run of escapes decoding to
                    # three characters. Hidden text is text: a payload written
                    # as escapes decodes to a URL or a command, and those have
                    # variety. Grafana's dashboard fixtures produced forty-four
                    # findings, all of them the ampersand in "Annotations &
                    # Alerts".
                    continue
                # What the escapes decode to is the discriminator.
                #
                # A file-wide count alone flags this project's own
                # `BINARY_MAGIC` table and its Unicode confusables map -- both
                # long runs of escapes, both entirely legitimate, because a
                # table of magic bytes is *supposed* to be arbitrary binary.
                #
                # Hidden text is not arbitrary. A payload written as escapes
                # decodes to source or a URL or a command, which is printable
                # ASCII; a byte table decodes to bytes nobody would type. That
                # is the difference between concealment and data, and it is
                # measurable rather than a matter of where the file lives.
                if printable < total * PRINTABLE_SHARE:
                    continue
                if not CONCEALED_TEXT.search(cls._decoded(content.raw, unit_pattern)):
                    # Printable, and still not something anybody hides: a table of hex digits,
                    # a regular expression's character range, a protocol constant
                    # (`"DOWNGRD\x01"`), a file-format signature. See `CONCEALED_TEXT`.
                    continue
                first = unit_pattern.search(content.raw)
                if first is None:  # pragma: no cover - findall implies a match
                    continue
                yield Hit(
                    rule_id="SUSPECT.OBFUSCATION.ENCODED.001",
                    title=f"String built from {label} spread across the file",
                    message=(
                        f"This file contains {total} {label} in total, split across "
                        f"several places so that no single run is long. Splitting is "
                        f"what makes the total worth reporting: the value still does "
                        f"not appear in the file, and the division has no purpose "
                        f"except that a per-construct threshold does not see it."
                    ),
                    remediation=(
                        "Write the strings as text. If a value must not be readable "
                        "in source, it is a secret and belongs in a secret store."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    start=first.start(),
                    end=first.end(),
                )
                return

            # The same discriminator the cumulative branch applies, and for the
            # same reason. It was applied only there, so a single long run
            # skipped it entirely -- and a Unicode codepoint table is exactly
            # that: `ਰਲਲ਼...` in XRegExp's script ranges is four
            # hundred escapes of Gurmukhi, which is data rather than a
            # concealed string. Concealment decodes to text somebody typed.
            run_total, run_printable, run_distinct = cls._encoded_units(
                match.group(0), unit_pattern
            )
            if run_printable < run_total * PRINTABLE_SHARE:
                continue
            if run_distinct < MIN_DISTINCT_ENCODED:
                continue
            if not CONCEALED_TEXT.search(cls._decoded(match.group(0), unit_pattern)):
                continue

            yield Hit(
                rule_id="SUSPECT.OBFUSCATION.ENCODED.001",
                title=f"String built from a long run of {label}",
                message=(
                    f"A string here is written as a long run of {label} rather than "
                    f"as text. That has no benefit for readability or correctness; "
                    f"its only effect is that the resulting value does not appear in "
                    f"the file and cannot be found by searching for it."
                ),
                remediation=(
                    "Write the string as text. If the value must not be readable in "
                    "source, it is a secret and belongs in a secret store."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                start=match.start(),
                end=match.end(),
            )
            return  # one encoding finding per file is enough to make the point

    @staticmethod
    def is_remark(
        content: FileContent,
        offset: int,
        language: str | None,
        spans: tuple[tuple[int, int], ...] | None = None,
    ) -> bool:
        """Whether this offset is inside a comment rather than in code.

        Both forms: a line comment, and a `/* ... */` whose continuation lines are
        indented prose rather than starting with `*`.

        `spans` is the block-comment map, which `block_comment_spans` documents as
        "a pass over the file, cached by the caller". This detector was not caching
        it: it recomputed the map for every candidate match, and the map is a
        character-by-character loop over the whole file. On the ten-megabyte payload
        of the Shai-Hulud npm worm that is ten million iterations per match.
        """
        if spans is None:
            spans = SourceComments.block_comment_spans(content.text, language)
        if SourceComments.inside_spans(spans, offset):
            return True
        start = content.comment_column(content.line_of(offset), language)
        return start is not None and content.column_of(offset) >= start


__all__ = [
    "CHAR_CODE_RUN",
    "CHAR_CODE_UNIT",
    "CONCEALED_TEXT",
    "CUMULATIVE_ENCODED_UNITS",
    "ESCAPE_RUN",
    "ESCAPE_UNIT",
    "MIN_DISTINCT_ENCODED",
    "NUMERIC_ARG",
    "PRINTABLE_SHARE",
    "EncodingFindings",
]
