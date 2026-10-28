"""The characters obfuscation hides in, and reading a file's text for them.

Directional controls that reorder what a reader sees, invisible characters that carry no glyph,
self-describing escapes, right-to-left ranges: the character classes the obfuscation checks look
for, and the text operations they share.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)

#: Directional embedding/isolate openers (not the overrides, not the pops): a balanced one laying
#: text out for display is not an attack, which needs an override or a span that re-reads the code.
_EMBED_OPEN = frozenset(map(chr, (0x202A, 0x202B, 0x2066, 0x2067, 0x2068)))  # LRE RLE LRI RLI FSI

_EMBED_CLOSE = frozenset(map(chr, (0x202C, 0x2069)))  # PDF PDI

_DIR_CONTROLS = frozenset(
    map(chr, (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069))
)  # all directional controls

#: The overrides, as UTF-8 bytes: the Trojan Source primitive. Their presence anywhere in a file
#: keeps every directional finding in it at full severity.
_OVERRIDE_BYTES = (b"\xe2\x80\xad", b"\xe2\x80\xae")  # LRO, RLO

#: Unicode ranges written right to left: Hebrew, Arabic, Syriac, Thaana, N'Ko,
#: Samaritan, Mandaic, their presentation forms, and Adlam.
RTL_RANGES = (
    (0x0590, 0x08FF),
    (0xFB1D, 0xFDFF),
    (0xFE70, 0xFEFF),
    (0x1E800, 0x1EFFF),
)

#: How far either side of the control to look for the text it is ordering.
RTL_WINDOW = 24

#: What share of a file's LETTERS must be right-to-left before the file is a
#: right-to-left resource rather than code containing a stray character.
#:
#: Measured. Thunderbird's Persian Android resources are 25.2% -- a translation file
#: caps somewhere near there, because the XML element and attribute names around the
#: translated text are Latin. `dimagi/commcare-hq`'s 1.2MB webpack bundle is 0.01%,
#: and this project's own source is 0.00%. Three orders of magnitude between the two,
#: so the threshold is set well below the floor of a genuine translation rather than
#: just above the noise: a source file with a handful of Arabic test strings in it
#: does not become exempt, and a file that IS the translation does.
RTL_RESOURCE_SHARE = 0.10

#: Below this many letters a share means nothing, so the file is judged as code.
RTL_RESOURCE_MIN_LETTERS = 200


class ObfuscationText:
    """Measurements of text that tell obfuscation from ordinary content."""

    @staticmethod
    def inside_quotes(raw: bytes, offset: int) -> bool:
        """Whether a quote is open on this line before `offset`: padding in a string literal is a
        table or a message laid out in columns (curl's test strings, Prettier's lexer tables)."""
        line = raw[raw.rfind(b"\n", 0, offset) + 1 : offset + 1]
        line = re.sub(rb"\\.", b"", line)
        return any(line.count(quote) % 2 for quote in (b'"', b"'", b"`"))

    ASCII_LETTERS: ClassVar[bytes] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    NON_ASCII: ClassVar[re.Pattern[str]] = re.compile("[^\x00-\x7f]+")

    @staticmethod
    def _is_rtl_resource(raw: bytes) -> bool:
        """Whether this file is right-to-left text rather than code containing some.

        `_orders_rtl_text` asks whether the control sits BESIDE right-to-left script, and
        it is the right question almost everywhere. It cannot answer the case where the
        string being ordered contains no script at all. Thunderbird's Persian resources
        carry

            <string name="message_view_single_attachment_summary">&lt;RLE&gt;&lt;RLM&gt;
                <xliff:g id="name">%1$s</xliff:g> (<xliff:g id="size">%2$s</xliff:g>)</string>

        -- a translated string whose entire content is two substituted placeholders, a
        filename and a size. The embedding is there so that what gets substituted renders
        the right way round inside a right-to-left interface, which is exactly what RLE is
        for; there is no Persian within the window because there is no Persian in the
        string. The lines above and below it are unmistakably Persian, and so is the file.

        So the question is asked of the file as well. An override in a file that IS
        right-to-left text is doing its documented job; an override in a file of code is
        the attack, and Trojan Source needs the file to be code for the technique to have
        a reviewer to mislead.

        Deliberately a share of letters rather than a count, and deliberately not a path
        test. `values-fa/` and `/locales/ar/` are the conventions of two ecosystems out of
        many, and the content answers the question directly. See `RTL_RESOURCE_SHARE` for
        why the threshold sits where it does, and note what this does NOT excuse: the
        right-to-left OVERRIDE in a minified JavaScript bundle, which is 0.01%
        right-to-left and stays a high-severity finding.
        """
        # Counted without visiting each character in Python: a bundle is megabytes of ASCII,
        # and the per-character loop this replaces was 40% of the time on one 8.8MB page.
        # The ASCII letters are counted on the bytes -- the decoder never folds an ASCII
        # byte into a replaced sequence, so the count is the decoded text's -- and only the
        # characters above ASCII, where every right-to-left range lies, are looked at one
        # by one.
        letters = len(raw) - len(raw.translate(None, ObfuscationText.ASCII_LETTERS))
        right_to_left = 0
        for run in ObfuscationText.NON_ASCII.findall(raw.decode("utf-8", "replace")):
            for character in run:
                if character.isalpha():
                    letters += 1
                    code = ord(character)
                    right_to_left += any(low <= code <= high for low, high in RTL_RANGES)
        if letters < RTL_RESOURCE_MIN_LETTERS:
            return False
        return right_to_left / letters >= RTL_RESOURCE_SHARE

    @staticmethod
    def _orders_rtl_text(raw: bytes, start: int, end: int) -> bool:
        """Whether the control character is next to right-to-left script.

        This is the difference between the attack and the feature. Trojan Source works by
        putting an override beside LATIN text, so that the identifiers a reviewer reads are
        reordered from the ones the compiler sees. An override beside Arabic or Hebrew is
        the override doing the job it was added to Unicode for.

        `RikkaApps/Shizuku`, `tiann/KernelSU`, `MatsuriDayo/NekoBoxForAndroid`,
        `getgrav/grav` and `briannesbitt/Carbon` each carry exactly one of these, in an
        Arabic or Kurdish resource string, and Notepad++'s language table carries a POP
        DIRECTIONAL FORMATTING after the word Kurdish writes its own name with. Five of
        those are `values-ar/strings.xml`, which is where Android PUTS Arabic.

        A window rather than the whole file, and both sides of it: an attack hides the
        override in the middle of code, where the nearest characters are ASCII, and no
        amount of translated text elsewhere in the file changes that.
        """
        window = raw[max(0, start - RTL_WINDOW) : end + RTL_WINDOW]
        for char in window.decode("utf-8", errors="replace"):
            point = ord(char)
            if any(low <= point <= high for low, high in RTL_RANGES):
                return True
        return False

    @staticmethod
    def _is_lone_quoted_mark(raw: bytes, start: int, end: int) -> bool:
        """Whether the match is the entire contents of a quoted literal.

        `"\ufeff"` in a BOM-stripping parser, `'\u202e'` in a table of control characters.
        One character between two MATCHING quotes is a codepoint being handled; an attack
        needs the override to sit next to the code it reorders.
        """
        if start == 0:
            return False
        before = raw[start - 1 : start]
        return before in (b'"', b"'", b"`") and before == raw[end : end + 1]

    @staticmethod
    def _is_inert_embedded_data(raw: bytes, start: int) -> bool:
        r"""Whether the control at `start` opens a BALANCED embedding (opener ... matching pop)
        whose enclosed span is only inert text -- letters, digits, spaces and ordinary punctuation
        -- inside a string literal, in a file with no directional OVERRIDE anywhere.

        This is data laid out for display, not Trojan Source. A phone number wrapped in LRE..PDF in
        an iOS accessibility label (``'\u202a158 8020 6986\u202c'``) renders right-to-left-aware but
        reorders nothing a reviewer reads. The attack needs an OVERRIDE (LRO/RLO), or a span that
        carries a quote or comment delimiter so the code after it re-reads -- the stretched-string
        variant of CVE-2021-42574 -- and either of those keeps the finding (census D).
        """
        if any(override in raw for override in _OVERRIDE_BYTES):
            return False
        if not ObfuscationText.inside_quotes(raw, start):
            return False
        text = raw.decode("utf-8", "replace")
        index = len(raw[:start].decode("utf-8", "replace"))
        if index >= len(text) or text[index] not in _EMBED_OPEN:
            return False
        depth = 0
        for char in text[index:]:
            if char in _EMBED_OPEN:
                depth += 1
            elif char in _EMBED_CLOSE:
                depth -= 1
                if depth == 0:
                    return True
            elif char in _DIR_CONTROLS or not (char.isalnum() or char in " \t.,:!?"):
                # A stray control, a quote, a comment marker, a bracket, a semicolon or an
                # operator inside the span: it could change how the line reads. Keep the finding.
                return False
        return False  # never closed -- unbalanced, so keep the finding

    @staticmethod
    def _longest_padding_run(text: str) -> int:
        """The longest run of whitespace that follows something, in a line.

        Leading indentation is skipped: it is whitespace at the start of a line,
        which every formatter produces. What this counts is a gap in the middle,
        which is how a payload is pushed off the right-hand edge.
        """
        longest = 0
        run = 0
        seen_content = False
        for char in text:
            if char.isspace():
                if seen_content:
                    run += 1
                    longest = max(longest, run)
            else:
                seen_content = True
                run = 0
        return longest

    @staticmethod
    def _longest_unbroken_run(text: str) -> int:
        """The longest run of non-whitespace characters in a line."""
        longest = 0
        run = 0
        for char in text:
            if char.isspace():
                longest = max(longest, run)
                run = 0
            else:
                run += 1
        return max(longest, run)

    @staticmethod
    def _obfuscator_io(hit: Hit) -> bool:
        """Whether this is obfuscator.io's output, which no bundler produces.

        A bundle in `dist/` is build output and its minified shape is ceilinged for that reason. The
        hex identifiers and rotated string array of javascript-obfuscator are not minification: they
        are someone choosing to hide the code, and in a published bundle that is how the September
        2025 npm compromise of `@duckdb/duckdb-wasm` spliced a wallet drainer into `dist/*.worker.js`.
        """
        return hit.rule_id == "SUSPECT.OBFUSCATION.PACKED.001" and "obfuscator.io" in hit.title


@dataclass(frozen=True, slots=True)
class Hit:
    rule_id: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    start: int
    end: int
    offscreen: bool = False
    """Code placed after a run of padding, past the right edge of an editor."""


__all__ = [
    "RTL_RANGES",
    "RTL_RESOURCE_MIN_LETTERS",
    "RTL_RESOURCE_SHARE",
    "RTL_WINDOW",
    "Hit",
    "ObfuscationText",
]
