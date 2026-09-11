"""Obfuscation detection.

Obfuscation is not itself malicious, and this detector never claims it is. What
it reports is that content was deliberately made unreadable, which is
information regardless of intent: source code has no defensive reason to hide
from the person reviewing it, and an author who wanted a reviewer not to
understand something is worth a moment's attention.

Four signals, each with a distinct false-positive profile, which is why they are
separate rules rather than one score:

**Escape runs.** Long sequences of ``\\xNN`` or ``\\uNNNN`` that spell ordinary
ASCII. There is no reason to write a string that way except to keep it out of a
search.

**Bidirectional and invisible characters.** Source that renders differently from
how it compiles. A reviewer approves what they see; the compiler acts on what is
there.

**Extreme line length.** A payload appended to a file is very often one long
line, because that keeps it off-screen in a diff. This needs calibration against
minified bundles, which are legitimately made of long lines, so entropy and file
type both gate it.

**Packer signatures.** Recognisable output from known obfuscators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.core.walker import PathGlob
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import FIXTURE_CEILING, is_documentation, is_test_material

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit

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
BIDI_AND_INVISIBLE = re.compile(
    # Embeddings, overrides and isolates: U+202A-U+202E and U+2066-U+2069.
    # None of these has a use in source code.
    rb"\xe2\x80[\xaa-\xae]"  # LRE, RLE, PDF, LRO, RLO
    rb"|\xe2\x81[\xa6-\xa9]"  # LRI, RLI, FSI, PDI
    # A BOM anywhere but the start. The assertion has to be a lookbehind: as a
    # lookahead placed after the bytes it is trivially true, because the
    # position it tests is the one *after* the BOM. Written that way it
    # excluded nothing, and every file a Windows editor saved with a byte-order
    # mark was reported as a Trojan Source attack -- fourteen of them in
    # PyYAML's own UTF-8 test corpus.
    rb"|(?<=[\s\S])\xef\xbb\xbf"
    rb"|\xef\xbf\xb9|\xef\xbf\xba|\xef\xbf\xbb"  # interlinear annotation marks
)

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

#: Languages each packer signature can actually be the output of.
#:
#: Every shape below is JavaScript. Matching one in a file that cannot execute
#: JavaScript is a category error, and it is the error that reported four HIGH
#: findings across four repositories -- all of them on a shell script, and all of
#: them on the same line of it.
#:
#: The file was `scripts/security/scan-malware.sh`, a list of quoted regexes a
#: malware scanner greps for, with `# _$_1e42-style obfuscated identifiers` in a
#: comment beside one of them. Cordon read the comment as the thing the comment
#: describes. It is the canonical false positive for this rule class -- a security
#: tool's own signature file -- and every scanner in this category hits it.
#:
#: Note what this does NOT do: it does not exempt the path, or the file, or
#: anything named `scan-malware.sh`. A JavaScript payload appended to that same
#: file would still be reported, because the gate is the language the signature
#: belongs to and nothing about who owns the file.
JAVASCRIPT_LANGUAGES = frozenset({"javascript", "typescript", "jsx", "tsx", "vue", "svelte"})

#: (label, pattern, languages, minimum occurrences).
#:
#: The count matters for the two identifier schemes. `_0x4f2a` and `_$_1e42` are
#: how an obfuscator NAMES things, so real output carries hundreds of them; one
#: occurrence is a file talking about the scheme. The other three shapes are
#: specific enough that one is the real thing -- nobody writes
#: `eval(function(p,a,c,k,e` by accident -- so they keep a threshold of one.
PACKERS: tuple[tuple[str, re.Pattern[bytes], frozenset[str], int], ...] = (
    (
        "Dean Edwards packer",
        re.compile(rb"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e"),
        JAVASCRIPT_LANGUAGES,
        1,
    ),
    ("obfuscator.io", re.compile(rb"_0x[0-9a-f]{4,6}\s*[,;=\[]"), JAVASCRIPT_LANGUAGES, 8),
    (
        "hex identifier obfuscation",
        re.compile(rb"\b_\$_[0-9a-fA-F]{3,}"),
        JAVASCRIPT_LANGUAGES,
        8,
    ),
    (
        "JSFuck",
        re.compile(rb"\[\]\[\s*[\"'@]?\s*(?:filter|constructor)"),
        JAVASCRIPT_LANGUAGES,
        1,
    ),
    (
        "large encoded blob into a dynamic constructor",
        re.compile(rb"(?:new\s+)?Function\s*\(\s*[\"'][A-Za-z0-9+/=]{200,}"),
        JAVASCRIPT_LANGUAGES,
        1,
    ),
)

#: Languages whose long lines are prose rather than code. See `_long_lines`.
#:
#: Only Markdown is listed because only Markdown is identified: `.rst`, `.txt`,
#: `.adoc` and `.tex` resolve to no language at all and are already covered by the
#: `language is None` guard above it.
PROSE_LANGUAGES = frozenset({"markdown"})

# Minified output is legitimately long-lined, so length alone must not fire on
# it. These paths are exempt from the length rule only; every other rule still
# applies, because a payload committed inside a vendored bundle is exactly the
# thing worth finding.
MINIFIED_PATHS = (
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.bundle.js",
    # Generated and data formats that are one long line by construction. An SVG
    # exported by a drawing tool is a single 18-kilobyte line; so is a lockfile
    # hash table, a compiled translation catalogue and a test snapshot.
    # Reporting line length on these produced four hundred and fifty-five
    # findings across twenty-one real repositories, none of them about
    # anything.
    "**/*.svg",
    "**/*.mo",
    "**/*.po",
    "**/*.snap",
    "**/*.lock",
    "**/*-lock.json",
    # JSON is a data format. There is no reading of a long JSON line as source,
    # because there is no reading of JSON as source: a blob in it needs a loader
    # somewhere else, and that loader is what the other rules are for. Sigstore
    # bundles, CycloneDX schemas and API-response fixtures are all one long
    # value by construction.
    "**/*.json",
    # Workflow lockfiles, which are machine-written by construction.
    "**/*.lock.yml",
    "**/*.lock.yaml",
    # Directories whose contents are not this project's source. Only *line
    # length* is waived here -- a payload can hide in a vendored bundle, and
    # every other rule still reads these files.
    "**/vendor/**",
    "**/node_modules/**",
    "**/third_party/**",
    "**/deps/**",
    "**/dist/**",
    # Build output committed to the tree. Next.js keeps rolled-up copies of its
    # runtime dependencies under `compiled/`, which is what the name says.
    "**/compiled/**",
    # Test data. A fixture is a blob on purpose: a base64 source map, a captured
    # API response, a wasm module a test loads. Only line length is waived --
    # every other rule still reads them, which matters because a fixture
    # directory is a plausible place to hide something.
    "**/fixtures/**",
    "**/testdata/**",
    # Asset directories. Sphinx and Django both put bundled third-party
    # JavaScript under `_static/`, frequently minified without the `.min`
    # suffix that would otherwise identify it.
    "**/_static/**",
    "**/static/**",
    "**/assets/**",
    # Compiled output committed as a test fixture. React ships dozens under
    # `__compiled__/`, which is exactly what the directory name says they are.
    "**/__compiled__/**",
)

GENERATED_MARKER = re.compile(
    rb"(?i)(?:@generated|do not edit|code generated by|automatically generated"
    rb"|autogenerated|auto-generated|this file (?:was|is) generated)"
)
"""A file saying, in its own header, that a program wrote it.

Content rather than path, which is what makes it worth having: the convention
is near-universal because every code-review tool reads it too, and it is
correct in the directories no glob would have guessed. Line length in generated
output is a property of the generator."""

GENERATED_HEADER_BYTES = 4096
"""How far into a file to look for that. A marker further in than this is not a
header, and scanning the whole file for one would mean any file that mentions
the phrase is exempt."""


TRANSLATION_PATHS = ("**/*.po", "**/*.mo", "**/*.pot", "**/LC_MESSAGES/**")
"""Message catalogues, which hold display text rather than code."""

MIN_DISTINCT_ENCODED = 6
"""How many distinct characters a run of escapes must decode to.

Below this the escapes are a serialiser's output rather than something hidden:
one repeated escape is a convention, and a payload is text."""

LONG_LINE_THRESHOLD = 2000
ENTROPY_THRESHOLD = 4.5


@dataclass(frozen=True, slots=True)
class _Hit:
    rule_id: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    start: int
    end: int


class ObfuscationDetector(BaseDetector):
    """Reports content that was deliberately made unreadable."""

    id = "obfuscation"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.BIDI.001",
                title="Bidirectional or invisible Unicode in source",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationDetector.id,
                remediation="Remove the control characters. Source should read as it runs.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.PACKED.001",
                title="Packer or minifier signature in hand-written source",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ObfuscationDetector.id,
                remediation="Ship the readable source and generate the packed form at build time.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.ENCODED.001",
                title="Large encoded blob embedded in source",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationDetector.id,
                remediation="Store binary data as a file, not as a literal.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.LONGLINE.001",
                title="Line far longer than any hand-written source",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category=Category.SUSPICIOUS,
                detector=ObfuscationDetector.id,
                remediation="Exclude generated bundles, or configure scan.minified.",
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        hits: list[_Hit] = []
        hits.extend(self._bidi(content, unit.language))
        hits.extend(self._escapes(content))
        hits.extend(self._packers(content, unit.language))
        hits.extend(self._long_lines(content, ctx, unit.language))

        return [self._finding(hit, unit, ctx) for hit in hits]

    # -- Signals ---------------------------------------------------------

    def _bidi(self, content: FileContent, language: str | None = None) -> Iterable[_Hit]:
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

        match = BIDI_AND_INVISIBLE.search(content.raw)
        if not match:
            return
        yield _Hit(
            rule_id="SUSPECT.OBFUSCATION.BIDI.001",
            title="Bidirectional or invisible characters in source",
            message=(
                "This file contains characters that change how text is displayed "
                "without changing what it means to a compiler. Source that renders "
                "differently from how it executes defeats review directly: the "
                "reviewer approves what they see, and the compiler acts on what is "
                "there."
            ),
            remediation=(
                "Remove the control characters. If a right-to-left language is "
                "genuinely required in a string, use explicit escapes so the "
                "characters are visible in review."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            start=match.start(),
            end=match.end(),
        )

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

    def _escapes(self, content: FileContent) -> Iterable[_Hit]:
        for pattern, label, unit_pattern in (
            (ESCAPE_RUN, "escape sequences", ESCAPE_UNIT),
            (CHAR_CODE_RUN, "character codes", CHAR_CODE_UNIT),
        ):
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
                total, printable, distinct = self._encoded_units(content.raw, unit_pattern)
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
                first = unit_pattern.search(content.raw)
                if first is None:  # pragma: no cover - findall implies a match
                    continue
                yield _Hit(
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
            run_total, run_printable, run_distinct = self._encoded_units(
                match.group(0), unit_pattern
            )
            if run_printable < run_total * PRINTABLE_SHARE:
                continue
            if run_distinct < MIN_DISTINCT_ENCODED:
                continue

            yield _Hit(
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

    def _packers(self, content: FileContent, language: str | None = None) -> Iterable[_Hit]:
        for label, pattern, languages, minimum in PACKERS:
            if language not in languages:
                continue
            matches = pattern.findall(content.raw)
            if len(matches) < minimum:
                continue
            match = pattern.search(content.raw)
            if not match:  # pragma: no cover - findall and search cannot disagree
                continue
            yield _Hit(
                rule_id="SUSPECT.OBFUSCATION.PACKED.001",
                title=f"Output of an obfuscator ({label})",
                message=(
                    f"This file matches the output shape of {label}. Obfuscated code "
                    f"cannot be reviewed, so whatever it does is outside every "
                    f"process that depends on reading it."
                ),
                remediation=(
                    "Obtain the original source and review that. If the file is a "
                    "vendored build artefact, build it from source that is reviewed."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                start=match.start(),
                end=match.end(),
            )
            return

    def _long_lines(
        self, content: FileContent, ctx: ScanContext, language: str | None = None
    ) -> Iterable[_Hit]:
        """Report an extremely long line, with the minified case excluded.

        Length alone is a weak signal and a strong irritant: minified bundles
        are entirely made of long lines. So the rule applies to source-shaped
        files only, and requires high entropy as well, since ordinary long lines
        (a data table, a long string) are far more repetitive than a payload.
        """
        # `scan.minified` is added to the built-in list. The setting was
        # parsed, validated, provenance-tracked, included in the config
        # fingerprint and in `to_dict()`, and read nowhere -- so a user who
        # configured `minified:` to silence long-line findings on their bundles
        # got silence of a different kind.
        # "Source-shaped" was the stated condition and was never checked. A
        # file with no identified language is data -- a MaxMind database, an
        # XML fixture, a text dump -- and a long line in data is what data
        # looks like.
        if language is None:
            return
        if language in PROSE_LANGUAGES:
            # Prose is not source-shaped either, and the same argument covers it.
            # The rule's whole reasoning is "a payload appended to a source file
            # keeps itself off-screen in a diff" -- which needs the file to be
            # something that runs. Nothing executes a Markdown document.
            #
            # A 3,333-character architecture table in `SYSTEM_DESIGN.md` was
            # reported as a very long high-entropy line in a source file. It is a
            # table. Mixed case, punctuation and pipe separators put any table row
            # over the entropy floor, so tightening the floor would not have
            # separated them and would have cost real detections elsewhere.
            #
            # Only the length rule is skipped. Bidi, escapes and the packer shapes
            # still apply to prose, which is right: a Trojan Source override in a
            # README is a live attack on whoever copies a command out of it.
            return

        patterns = (*MINIFIED_PATHS, *ctx.config.minified)
        if any(PathGlob.matches(content.path, p) for p in patterns):
            return
        if content.truncated:
            return  # the longest line cannot be known from a prefix
        if GENERATED_MARKER.search(content.raw[:GENERATED_HEADER_BYTES]):
            # The file says it is generated. Line length in generated output is
            # a property of the generator, and the convention for saying so is
            # near-universal because every code-review tool reads it too.
            return

        if content.longest_line <= LONG_LINE_THRESHOLD:
            return

        index, length = self._longest_line_index(content)
        if index is None:
            return

        text = content.line_text(index)
        if Redactor.shannon_entropy(text[:4000]) < ENTROPY_THRESHOLD:
            return
        if "sourceMappingURL=data:" in text[:4000]:
            # An inline source map. Every bundler that has ever emitted one
            # wrote a single base64 line of exactly this shape, and it is a
            # comment: nothing reads it but a debugger.
            return

        start = content.line_starts[index - 1]
        yield _Hit(
            rule_id="SUSPECT.OBFUSCATION.LONGLINE.001",
            title="Very long high-entropy line in a source file",
            message=(
                f"Line {index} is {length} characters of high-entropy content in a "
                f"file that is not minified output. A payload appended to a source "
                f"file is very often a single long line, because that keeps it "
                f"off-screen in a diff and out of a reviewer's eye."
            ),
            remediation=(
                "Read the line. If it is generated or vendored, move it into a "
                "build artefact so it is not reviewed as source."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            start=start,
            end=min(start + 200, len(content.raw)),
        )

    @staticmethod
    def _longest_line_index(content: FileContent) -> tuple[int | None, int]:
        longest = 0
        index: int | None = None
        starts = content.line_starts
        for i, start in enumerate(starts, 1):
            end = starts[i] if i < len(starts) else len(content.raw)
            length = end - start
            if length > longest:
                longest, index = length, i
        return index, longest

    # -- Construction ----------------------------------------------------

    def _finding(self, hit: _Hit, unit: FileUnit, ctx: ScanContext) -> Finding:
        content = unit.content
        # The same ceiling the secrets detector and the composites apply, and these
        # rules need it for a reason of their own: a file that DETECTS an obfuscation
        # technique has to contain the technique.
        #
        # Bandit's `plugins/trojansource.py` and `examples/trojansource.py` were both
        # reported at HIGH for bidirectional characters in source. The first is the
        # plugin that finds Trojan Source attacks; the second is the example it was
        # written against. Every scanner in this category hits this on its own corpus
        # and on every repository that vendors security rules, and telling those users
        # their rule set is an attack is how a tool teaches people to ignore it.
        #
        # A ceiling rather than a path exemption: the characters really are there, and
        # a real override smuggled into a fixture directory is still worth finding.
        # What changes is whether it fails a build.
        severity = hit.severity
        if is_test_material(content.path) or is_documentation(content.path):
            severity = min(severity, FIXTURE_CEILING)
        return Finding(
            rule_id=hit.rule_id,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=hit.confidence,
            message=hit.message,
            location=Location(
                path=content.path,
                line=content.line_of(hit.start),
                column=content.column_of(hit.start),
                byte_start=hit.start,
                byte_end=hit.end,
                project=unit.project,
            ),
            evidence=Redactor.build_evidence(content, hit.start, hit.end, RedactionMode.MASKED)
            if hit.rule_id != "SUSPECT.OBFUSCATION.BIDI.001"
            else Evidence(
                # A bidi snippet would render in the report exactly as it renders
                # in the editor, which is the problem being reported. Only the
                # position and the hash are emitted.
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.slice(hit.start, hit.end)),
                redaction=RedactionMode.HASH_ONLY,
                span=(hit.start, hit.end),
            ),
            remediation=hit.remediation,
            explanation=Explanation(summary=hit.title, matched_rule=hit.rule_id),
            risk=ctx.scorer.score(
                hit.severity,
                hit.confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    is_obfuscated=True,
                    capabilities=frozenset({Capability.DECODE}),
                ),
            ),
            detector=self.id,
            capabilities=(Capability.DECODE,),
        )


__all__ = ["ObfuscationDetector"]
