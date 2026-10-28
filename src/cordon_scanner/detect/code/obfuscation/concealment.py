"""Obfuscation by concealment: content placed where a reader does not see it.

Bidirectional controls that make code read differently from how it runs (Trojan Source), text spelled
in Unicode Tag characters, code pushed past the right edge of the screen by padding, and code placed
after hundreds of empty lines so a file opens on a screen that looks finished."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.code.obfuscation.text import Hit, ObfuscationText

# Bidirectional overrides and zero-width characters, as UTF-8 byte sequences.
# Matched as bytes so no decoding is required and no encoding surprise applies.
#
# These are the "Trojan Source" family: text that renders in one order and
# compiles in another, so a reviewer approves something different from what the
# compiler sees.
#
# Restricted to characters that actually reorder rendering. Zero-width space,
# non-joiner and joiner (U+200B-U+200D) were in this set and are not
# directional: ZWNJ is mandatory in Persian, Arabic and Hindi orthography, ZWJ
# is in every modern emoji sequence, and ZWSP is an ordinary line-break hint.
# Left- and right-to-left *marks* (U+200E/U+200F) are out for the same reason --
# they are ordinary in right-to-left text and override nothing. Including all
# five reported ninety-five findings across Django's translation catalogues
# alone, every one of them for text that is simply written correctly.
DIRECTIONAL_CONTROL = re.compile(
    # Embeddings, overrides and isolates: U+202A-U+202E and U+2066-U+2069.
    # None of these has a use in source code.
    rb"\xe2\x80[\xaa-\xae]"  # LRE, RLE, PDF, LRO, RLO
    rb"|\xe2\x81[\xa6-\xa9]"  # LRI, RLI, FSI, PDI
)
"""The characters that actually REORDER text, which is what Trojan Source is."""

NON_DIRECTIONAL_INVISIBLE = re.compile(
    # A BOM anywhere but the start. The assertion has to be a lookbehind: as a
    # lookahead placed after the bytes it is trivially true, because the
    # position it tests is the one *after* the BOM. Written that way it
    # excluded nothing, and every file a Windows editor saved with a byte-order
    # mark was reported as a Trojan Source attack -- fourteen of them in
    # PyYAML's own UTF-8 test corpus.
    # A BOM INSIDE a token, not merely after the first byte. The lookbehind used to be
    # "any preceding character", which caught every editor artefact: `actions/runner`
    # carries `using System;\n\n` and then a BOM before `namespace`, in four files,
    # because somebody's editor wrote one when the file was concatenated. That cannot
    # reorder anything -- a BOM is zero-width and has no directional semantics, which is
    # what separates it from the overrides above.
    #
    # A BOM between two non-space characters is a different matter: Grafana's Azure
    # dashboards carry one inside a URL, nine times, where it makes two URLs that look
    # identical different strings. That one is still reported.
    #
    # Nor straight after an opening quote, which is a string literal that BEGINS with a
    # BOM -- code handling the thing rather than hiding behind it. TrafficMonitor writes
    # `version_info.find(L"\ufeff<version>")` to strip one out of a downloaded file,
    # which is the same reasoning `_is_lone_quoted_mark` already applies to a quoted
    # override.
    rb"(?<=[^\s\"'`])\xef\xbb\xbf"
    rb"|\xef\xbf\xb9|\xef\xbf\xba|\xef\xbf\xbb"  # interlinear annotation marks
)
"""Invisible, and unable to reorder anything.

Separated from the directional controls because the two are different findings with
the same symptom. A zero-width no-break space cannot make source read one way and
compile another -- the rule's own message, about review seeing something the compiler
does not, is simply not true of it. What it can do is make two strings that render
identically compare unequal, which is a bug and occasionally a trick, and which is
worth reporting at a severity that does not stop a build.

Measured: of the fourteen repositories this rule touched at HIGH with three findings or
fewer, the non-directional half was every case where the character sat in code rather
than in translated text -- `content.replace(/^\ufeff/, '')` in a markdown parser,
`let s = "Hello\ufeffWorld"` in SwiftLint's own test samples for the rule that detects
invisible characters, a table of JavaScript whitespace codepoints in a Rust comment,
and one stray mark inside a URL literal in `hashicorp/vagrant`. The last of those is a
real defect in that repository and is still reported; none of the four is Trojan Source.
"""

TAG_RUN = re.compile(rb"(?:\xf3\xa0[\x80\x81][\x80-\xbf]){4,}")
"""Four or more Unicode Tag characters in a row (U+E0000 to U+E007F as UTF-8)."""

#: Words a file uses when it is ABOUT bidirectional control characters.
#:
#: Bandit's Trojan Source plugin, a threat model, a security runbook, a test fixture
#: with a name that says so. An attacker does not label the override -- it works
#: because a reviewer cannot see it, and a comment announcing its presence defeats the
#: technique entirely.
SELF_DESCRIBING = re.compile(
    rb"(?i)(?:trojan[\s_-]?source|bidirectional[\s_-]?(?:control|character|override)"
    rb"|\bbidi\b|U\+202[A-E]|U\+206[6-9]|CWE-838"
    rb"|right[\s_-]?to[\s_-]?left[\s_-]?override|left[\s_-]?to[\s_-]?right[\s_-]?override"
    rb"|\bRLO\b|\bLRO\b|\bPDI\b|byte[\s_-]?order[\s_-]?mark|\bBOM_BYTE)"
)

#: Languages whose long lines are prose rather than code. See `_long_lines`.
#:
#: Only Markdown is listed because only Markdown is identified: `.rst`, `.txt`,
#: `.adoc` and `.tex` resolve to no language at all and are already covered by the
#: `language is None` guard above it.
PROSE_LANGUAGES = frozenset({"markdown"})

TRANSLATION_PATHS = ("**/*.po", "**/*.mo", "**/*.pot", "**/LC_MESSAGES/**")
"""Message catalogues, which hold display text rather than code."""

MINIFIED_LINE_FOR_BIDI = 5_000
"""A line this long is generated output, as the long-line rule reads it."""


class ConcealmentFindings:
    """The obfuscation findings for content a reader is kept from seeing."""

    #: Code after a gap of padding in the middle of a line: `import os` followed by two hundred
    #: spaces and then the payload, which a reader's editor never shows without scrolling right.
    #: Not a gap before a comment, and not a gap at the end of a line. A `;` after the gap is a
    #: statement separator, which is how the samples carry on: `...;exec(...)`.
    OFFSCREEN_CODE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?m)\S[ \t]{200,4000}(?=[A-Za-z_$;(\[])(?!//|--)\S"
    )

    #: Code after hundreds of blank lines: the vertical form of the padding below, past the bottom
    #: of the screen instead of its right edge.
    BELOW_SCREEN_LINES: ClassVar[int] = 400

    @classmethod
    def below_screen_code(cls, content: FileContent, language: str | None) -> Iterable[Hit]:
        """Code placed after hundreds of empty lines, so a file opens on a screen of nothing and
        reads as ending where its visible part ends (review 98: bs58lite's preinstall runs its
        collector after 2,000 blank lines). Source languages only."""
        if language is None or language in PROSE_LANGUAGES or content.truncated:
            return
        # A linear count of consecutive blank lines, then the first line with code on it.
        raw = content.raw
        blank, offset = 0, 0
        found_at = -1
        for line in raw.split(b"\n"):
            if line.strip():
                if blank >= cls.BELOW_SCREEN_LINES:
                    found_at = offset
                    break
                blank = 0
            else:
                blank += 1
            offset += len(line) + 1
        if found_at < 0:
            return
        yield Hit(
            rule_id="SUSPECT.OBFUSCATION.LONGLINE.001",
            title="Code pushed below the screen",
            message=(
                f"Line {content.line_of(found_at)} continues the file after {blank} empty "
                "lines, so an editor shows the visible part and nothing of what follows. Blank lines "
                "in that number have no use in code except keeping something out of a reviewer's sight."
            ),
            remediation="Read to the end of the file. Remove the padding, or the code after it.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            start=found_at,
            end=min(len(raw), found_at + 200),
            offscreen=True,
        )

    @classmethod
    def offscreen_code(cls, content: FileContent, language: str | None) -> Iterable[Hit]:
        """Code pushed past the right edge of the screen by padding, whatever its entropy.

        The long-line rule wants the line to be high-entropy, because a long line of words is
        text. Padding is the other half of its own premise -- "a payload is either one token or
        pushed past the edge of the screen" -- and the pushed half needs no entropy: the Roblox
        cookie stealers in malregistry and `spl-types` hide plain Python after hundreds of
        spaces on an ordinary line (review 98). Source languages only; prose and data align
        columns with spaces."""
        if language is None or language in PROSE_LANGUAGES or content.truncated:
            return
        raw = content.raw
        found = next(
            (
                m
                for m in cls.OFFSCREEN_CODE.finditer(raw)
                if not ObfuscationText.inside_quotes(raw, m.start())
            ),
            None,
        )
        if found is None:
            return
        yield Hit(
            rule_id="SUSPECT.OBFUSCATION.LONGLINE.001",
            title="Code pushed past the edge of the screen",
            message=(
                f"Line {content.line_of(found.start())} continues with code after a run of "
                f"{found.end() - found.start() - 2} blank characters, so an editor shows the "
                f"start of the line and nothing of what follows it. Padding has no use in code "
                f"except keeping something out of a reviewer's sight."
            ),
            remediation="Read the whole line. Remove the padding, or the code after it.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            start=found.start(),
            end=min(found.end(), found.start() + 200),
            offscreen=True,
        )

    @classmethod
    def tag_smuggling(cls, content: FileContent) -> Iterable[Hit]:
        """Text spelled in Unicode Tag characters, outside a flag emoji.

        U+E0020 to U+E007E mirror printable ASCII and render as nothing, so a sentence written in
        them is invisible to a reader and legible to a language model: "ignore previous
        instructions" in a README the agent was told to read. Their one legitimate use is the
        subdivision flags (🏴 followed by tags), which are excluded. Any file, any language --
        agents read READMEs, docs and comments as readily as their own instruction files, which
        the agent-chain detector already covers.
        """
        from cordon_scanner.detect.agents.instructions import InstructionText
        from cordon_scanner.detect.agents.paths import INSTRUCTION_PATHS

        if b"\xf3\xa0" not in content.raw:
            # The lead bytes of every Tag character, so `TAG_RUN` cannot match without them: the
            # path globs and the search are skipped for the files that have none.
            return
        if any(PathGlob.matches(content.path.rpartition("!")[2], p) for p in INSTRUCTION_PATHS):
            return
        match = next(
            (
                m
                for m in TAG_RUN.finditer(content.raw)
                if not content.raw[max(0, m.start() - 4) : m.start()].endswith(b"\xf0\x9f\x8f\xb4")
            ),
            None,
        )
        if match is None:
            return
        hidden = InstructionText._decode_tags(match.group(0)).strip()[:120]
        yield Hit(
            rule_id="SUSPECT.OBFUSCATION.TAG_SMUGGLING.001",
            title="Invisible text written in Unicode Tag characters",
            message=(
                "This file carries text in Unicode Tag characters, which render as nothing to a "
                "person and read as ordinary text to a language model. Hidden here: "
                f"{hidden!r}."
            ),
            remediation="Remove the characters, and find out how they were introduced.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            start=match.start(),
            end=match.end(),
        )

    @classmethod
    def bidi(cls, content: FileContent, language: str | None = None) -> Iterable[Hit]:
        if content.raw.isascii():
            # Every alternative of both patterns consumes a byte above 0x7F, so neither can match
            # an ASCII file -- most files -- and the path globs and both searches are skipped.
            return
        # Translation catalogues are excluded. Trojan Source is about source
        # that renders differently from how it compiles, and a `.po` or `.mo`
        # for a right-to-left language legitimately embeds directional
        # characters in the text it will display. That text is data shown to a
        # user, not logic read by a reviewer, and Django ships hundreds of
        # such files.
        if any(PathGlob.matches(content.path, p) for p in TRANSLATION_PATHS):
            return

        # And so is anything that is not source, which is the same argument carried
        # to its conclusion. Trojan Source works because a REVIEWER reads one thing
        # and a COMPILER acts on another. A file nobody reviews as text cannot be
        # attacked that way, so a directional codepoint in one is a byte sequence,
        # not a deception.
        #
        # Measured across 535 repositories this rule produced 285 findings, and the
        # files were: DuckDB's `.parquet` test data, Bevy's `.glb` models, Wails's
        # compiled `Assets.car`, an After Effects `.aep`, an `.m4v`, a PhotoPrism
        # `.xmp` sidecar, and TensorFlow's `icu_conversion_data.c.gz.afu` -- which is
        # a character-encoding conversion table, a file whose entire purpose is to
        # contain every codepoint there is.
        #
        # `language is None` is the same gate `_long_lines` already applies, on the
        # same reasoning written there: a file with no identified language is data,
        # and the rule's claim is about source.
        if language is None:
            return

        # The directional half first, because it is the one the rule's message is
        # about. A file carrying both is reported for the override.
        match = DIRECTIONAL_CONTROL.search(content.raw)
        directional = match is not None
        if match is None:
            match = NON_DIRECTIONAL_INVISIBLE.search(content.raw)
        if match is None:
            return

        # A file that NAMES the attack it contains is documenting it.
        #
        # Bandit's `plugins/trojansource.py` is the plugin that detects Trojan Source,
        # and its docstring shows the sample output - so the override characters are
        # there, in prose, beside the words "trojansource", "bidirectional control
        # character" and "CWE-838". Every scanner in this category hits this on its own
        # corpus, and the same reasoning already exempts rule-definition files from the
        # mining and credential-store indicators.
        #
        # An attacker does not label the override. That is the whole point of one: it
        # works because a reviewer cannot see it, and a comment announcing its presence
        # defeats the technique. So the marker is weak evidence for an attack and strong
        # evidence for documentation - and this lowers the severity rather than
        # suppressing, so a labelled override is still in the report.
        #
        # A byte-order mark inside a one-character string literal is the second case and
        # the same argument. webpack's `WebManifestParser.js` strips a BOM before parsing
        # JSON and writes the check as `if (source[0] === "\ufeff")` with the character
        # itself. A BOM is invisible but not DIRECTIONAL: it cannot reorder anything,
        # which is what this rule's message is about, and any parser that handles one has
        # to name it.
        #
        # Both LOWER the severity rather than suppressing. The characters really are
        # present, a reviewer may still want to know, and a label is weak evidence for an
        # attack rather than proof against one -- so the finding stays in the report and
        # stops failing a build.
        documented = SELF_DESCRIBING.search(
            content.raw
        ) is not None or ObfuscationText._is_lone_quoted_mark(
            content.raw, match.start(), match.end()
        )

        # The third case, and the one that separates the attack from the feature: an
        # override beside right-to-left script is the override doing its documented
        # job. See `_orders_rtl_text`.
        ordering_text = directional and (
            ObfuscationText._orders_rtl_text(content.raw, match.start(), match.end())
            # Or the file itself is right-to-left text. See `_is_rtl_resource`, for the
            # translated string whose whole content is two placeholders.
            or ObfuscationText._is_rtl_resource(content.raw)
        )

        # The fourth case: a balanced embedding around inert text inside a string literal, in a
        # file with no override -- data laid out for display, not a reorder of code the reviewer
        # reads. See `_is_inert_embedded_data`.
        inert_data = directional and ObfuscationText._is_inert_embedded_data(
            content.raw, match.start()
        )

        if not directional:
            # A zero-width no-break space or an interlinear annotation mark. Reported,
            # and not as Trojan Source: it cannot reorder anything, so the claim above
            # -- that review sees one thing and the compiler another -- is not true of
            # it. What it does is make two strings that render identically compare
            # unequal, which is a defect and occasionally a trick. `hashicorp/vagrant`
            # has one inside a download URL; `Fission-AI/OpenSpec` has one inside the
            # regex that strips it.
            yield Hit(
                rule_id="SUSPECT.OBFUSCATION.BIDI.001",
                title="Invisible characters in source",
                message=(
                    "This file contains invisible characters that no reviewer can see "
                    "and no compiler ignores. They cannot reorder the source, so this "
                    "is not the Trojan Source attack; what they can do is make two "
                    "strings that render identically compare as different, which is "
                    "usually an editor artefact and occasionally deliberate."
                ),
                remediation=(
                    "Remove the characters, or write them as explicit escapes so they "
                    "are visible to the next reader."
                ),
                # Recorded: a defect it may be, a reordering it cannot be. In the long tail it
                # was mostly a BOM in iconv-lite's generated tables, KaTeX, CSV readers that
                # strip one, and bundles (review 98). Text hidden in invisible characters --
                # variation selectors, tag characters -- is `CAP.INVISIBLE_SMUGGLING.001`'s.
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                start=match.start(),
                end=match.end(),
            )
            return

        yield Hit(
            rule_id="SUSPECT.OBFUSCATION.BIDI.001",
            title="Bidirectional or invisible characters in source",
            message=(
                "This file contains characters that change how text is displayed "
                "without changing what it means to a compiler. Source that renders "
                "differently from how it executes defeats review directly: the "
                "reviewer approves what they see, and the compiler acts on what is "
                "there."
            )
            + (
                " The control sits beside right-to-left script, or in a file that is "
                "itself right-to-left text, which is what it was added to Unicode for, "
                "so this is most likely translated text rather than an attack and is "
                "reported below its usual severity."
                if ordering_text
                else ""
            ),
            remediation=(
                "Remove the control characters. If a right-to-left language is "
                "genuinely required in a string, use explicit escapes so the "
                "characters are visible in review."
            ),
            severity=(
                Severity.INFO
                if ConcealmentFindings._bundled_string(content, match.start()) or inert_data
                else Severity.LOW
                if documented or ordering_text
                else Severity.HIGH
            ),
            confidence=Confidence.HIGH,
            start=match.start(),
            end=match.end(),
        )

    BUNDLE_DIRECTORIES: ClassVar[tuple[str, ...]] = ("/static/", "/dist/", "/vendor/", "/build/")

    @staticmethod
    def _bundled_string(content: FileContent, offset: int) -> bool:
        """A bidi control inside a string literal of a bundled or minified file: display data a
        library carries -- KaTeX's right-to-left handling in `streamlit/static/js/katex.*.js` --
        not Trojan Source, which needs the control in a comment or between tokens of source
        somebody reads (review 98, FP-7)."""
        path = f"/{content.path.rpartition('!')[2]}"
        bundled = content.longest_line > MINIFIED_LINE_FOR_BIDI or any(
            directory in path for directory in ConcealmentFindings.BUNDLE_DIRECTORIES
        )
        if not bundled:
            return False
        raw = content.raw
        line_start = raw.rfind(b"\n", 0, offset) + 1
        before = raw[line_start:offset]
        open_quote = None
        index = 0
        while index < len(before):
            char = before[index : index + 1]
            if char == b"\\":
                index += 2
                continue
            if open_quote is None and char in (b'"', b"'", b"`"):
                open_quote = char
            elif char == open_quote:
                open_quote = None
            index += 1
        return open_quote is not None


__all__ = [
    "DIRECTIONAL_CONTROL",
    "MINIFIED_LINE_FOR_BIDI",
    "NON_DIRECTIONAL_INVISIBLE",
    "PROSE_LANGUAGES",
    "SELF_DESCRIBING",
    "TAG_RUN",
    "TRANSLATION_PATHS",
    "ConcealmentFindings",
]
