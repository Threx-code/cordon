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
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.text.comments import SourceComments
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.code.obfuscation.concealment import (
    DIRECTIONAL_CONTROL,
    NON_DIRECTIONAL_INVISIBLE,
    PROSE_LANGUAGES,
    ConcealmentFindings,
)
from cordon_scanner.detect.code.obfuscation.findings import ObfuscationFinding
from cordon_scanner.detect.code.obfuscation.text import Hit, ObfuscationText

BIDI_AND_INVISIBLE = re.compile(
    DIRECTIONAL_CONTROL.pattern + rb"|" + NON_DIRECTIONAL_INVISIBLE.pattern
)
"""Either kind, for callers that only ask whether a file carries one at all."""


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
    # The same tool with identifiers renamed (`--identifier-names-generator mangled` or a
    # dictionary): no `_0x` names left, but the string array still rotates itself into place with
    # `arr['push'](arr['shift']())`, in brackets because the method names are strings it hides.
    # Minifiers write `.push`; `1imit` and its siblings (review 98) are this, around an `eval` of a
    # server's reply.
    (
        "obfuscator.io, identifiers renamed",
        re.compile(
            rb"\[\s*[\"']push[\"']\s*\]\s*\(\s*[\w$]+\s*\[\s*[\"']shift[\"']\s*\]\s*\(\s*\)\s*\)"
        ),
        JAVASCRIPT_LANGUAGES,
        1,
    ),
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

BUNDLER_PRELUDE = re.compile(
    rb"var [\w$]{1,4}=Object\.create;var [\w$]{1,4}=Object\.defineProperty;"
    rb"|__webpack_require__|webpackBootstrap|/\*{6}/ "
)
"""The opening a bundler writes, not a person: esbuild's `var X=Object.create;var k=
Object.defineProperty;` helper prelude, and webpack's runtime. Read within
`GENERATED_HEADER_BYTES`. Across 1,943 legitimate editor extensions this rule alone blocked 90, and
the ones read were esbuild output in `out/` -- the folder TypeScript and esbuild write to; the three
malicious extensions it was the only signal for were esbuild output too, with no payload on the
line it reported."""

GENERATED_HEADER_BYTES = 4096
"""How far into a file to look for that. A marker further in than this is not a
header, and scanning the whole file for one would mean any file that mentions
the phrase is exempt."""


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

LONG_LINE_THRESHOLD = 2000

ENTROPY_THRESHOLD = 4.5

UNBROKEN_RUN_THRESHOLD = 250
"""How long a run of non-whitespace makes a long line a payload rather than text.

A payload kept off-screen in a diff is usually one token: a base64 blob, a hex
string, a packed function body. A long line made of ordinary short words
separated by spaces is a DOCUMENT embedded in a string, and configuration
formats are full of them -- a CloudFormation `DashboardBody` holding a JSON
dashboard, an `Fn::Sub` holding a shell script, a Kubernetes CRD holding a
paragraph of API documentation.

Entropy cannot separate those, for the reason the prose exclusion below already
records: mixed case and punctuation put any sentence over the floor. Measured
against the infrastructure corpus, where five of seven findings were one of
those three shapes: their longest unbroken runs were 24, 45, 45 and 171
characters, and the one real finding -- a packed `eval(function(p,a,c,k,e,d)`
loader -- was 3,195."""

PADDING_RUN_THRESHOLD = 80
"""How much consecutive whitespace inside a line means it was padded.

The other way a payload is kept off-screen, and the one an unbroken-run test on
its own misses. Measured against 1,000 real malicious npm and PyPI releases:
two packages closed a statement with `});`, padded the line with about a
hundred and fifty spaces, and put a scrambled loader after it -- `var
mfa=ZML(mGB,cag ); mfa(9993)`. The payload is deliberately broken up with
spaces, so its longest unbroken run was 206 and 224 characters and it read as
prose to a length test.

Nothing writes a hundred consecutive spaces in the middle of a line on purpose.
An indented line is whitespace at the START, which is not this: the run has to
come after something."""


class ObfuscationDetector(BaseDetector):
    """Reports content that was deliberately made unreadable."""

    id = ObfuscationFinding.DETECTOR
    # 0.2.0: a file that names the attack it contains, or carries a lone quoted
    # control character, reports it at LOW; and generated output is ceilinged.
    # 0.5.0: a directional control in a file that is itself right-to-left text is
    # ordering that text, even when the string it sits in holds only placeholders.
    # 0.6.0: a third party's minified library is ceilinged like other material this
    # repository did not write.
    version = "0.6.0"
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
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "This file contains characters that change how text is displayed without "
                    "changing what is compiled or interpreted. Source that reads one way to a "
                    "reviewer and runs another way is the whole of the attack."
                ),
                references=(references.TROJAN_SOURCE, references.HOMOGLYPH),
                remediation="Remove the control characters. Source should read as it runs.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.TAG_SMUGGLING.001",
                title="Invisible text written in Unicode Tag characters",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "Text written in Unicode Tag characters is invisible to a reader and legible to "
                    "a language model: the ASCII-smuggling form of prompt injection."
                ),
                references=(references.HOMOGLYPH,),
                remediation="Remove the characters, and find out how they were introduced.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.PACKED.001",
                title="Packer or minifier signature in hand-written source",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "A packer's output signature appears in a file that is not build output. "
                    "Packing exists to make code unreadable until it runs, which in a source "
                    "tree removes the review that source is there to receive."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Ship the readable source and generate the packed form at build time.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.ENCODED.001",
                title="Large encoded blob embedded in source",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "A long encoded literal sits inside source. The bytes are not code until "
                    "something decodes them, so they pass through review as a string and become "
                    "whatever they are at runtime."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Store binary data as a file, not as a literal.",
            ),
            DeclaredRule(
                id="SUSPECT.OBFUSCATION.LONGLINE.001",
                title="Line far longer than any hand-written source",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category=Category.SUSPICIOUS,
                detector=ObfuscationFinding.DETECTOR,
                message=(
                    "One line is longer than hand-written source runs to, in a file that does "
                    "not look like build output. A payload appended to a source file is very "
                    "often a single long line, because that keeps it off-screen in a diff."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
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

        hits: list[Hit] = []
        hits.extend(ConcealmentFindings.bidi(content, unit.language))
        hits.extend(ConcealmentFindings.tag_smuggling(content))
        hits.extend(self._escapes(content))
        hits.extend(self._packers(content, unit.language))
        long_lines = list(self._long_lines(content, ctx, unit.language))
        # Padding is the stronger reading of the same line: a long line is often a bundle, code
        # after six hundred spaces never is. When both fire the padded one is reported, so the
        # entry-point and install grading see it (review 98: gluestack's `react-native-aria`
        # releases appended their payload after 630 spaces in `lib/commonjs/index.js`, the
        # package's `main`, and were reported LOW as a long line).
        offscreen = list(ConcealmentFindings.offscreen_code(content, unit.language)) or list(
            ConcealmentFindings.below_screen_code(content, unit.language)
        )
        hits.extend(offscreen or long_lines)

        return [ObfuscationFinding.finding(hit, unit, ctx) for hit in hits]

    # -- Signals ---------------------------------------------------------

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

    def _escapes(self, content: FileContent) -> Iterable[Hit]:
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
                if not CONCEALED_TEXT.search(self._decoded(content.raw, unit_pattern)):
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
            run_total, run_printable, run_distinct = self._encoded_units(
                match.group(0), unit_pattern
            )
            if run_printable < run_total * PRINTABLE_SHARE:
                continue
            if run_distinct < MIN_DISTINCT_ENCODED:
                continue
            if not CONCEALED_TEXT.search(self._decoded(match.group(0), unit_pattern)):
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
    def _is_remark(
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

    def _packers(self, content: FileContent, language: str | None = None) -> Iterable[Hit]:
        # Computed once for the file, and only if a packer signature is actually
        # present -- most files match none and never pay for it.
        spans: tuple[tuple[int, int], ...] | None = None

        for label, pattern, languages, minimum in PACKERS:
            if language not in languages:
                continue
            # Bounded. The question is whether there are at least `minimum`
            # occurrences and where the first one in real code is, and both answers
            # are reachable from a prefix of the matches -- but this asked for all
            # of them with `findall` and then walked the file a second time with
            # `finditer`. An obfuscated file is exactly the case where that is
            # ruinous: every identifier is a match, so a ten-megabyte file produced
            # hundreds of thousands of them, twice.
            #
            # The cost was not theoretical. `bun_environment.js`, the payload the
            # Shai-Hulud worm ships beside a `preinstall` hook, exhausted the
            # five-second per-file budget here and the obfuscation detectors never
            # ran on it -- so the worst npm compromise on record was reported as
            # "this package has a preinstall script", the same finding `bcrypt`
            # gets, and the evidence that would have separated them was the part
            # that timed out. A limit that an attacker can reach by making the
            # payload bigger is a limit that rewards making the payload bigger.
            found: re.Match[bytes] | None = None
            seen = 0
            for match in pattern.finditer(content.raw):
                seen += 1
                if found is None and not self._is_remark(
                    content,
                    match.start(),
                    language,
                    spans
                    if spans is not None
                    else (spans := SourceComments.block_comment_spans(content.text, language)),
                ):
                    found = match
                if seen >= minimum and found is not None:
                    break
            if seen < minimum or found is None:
                continue
            # The first occurrence that is actually code. `binary-husky/gpt_academic`
            # keeps a Dean Edwards packer preamble in `themes/waifu_plugin/
            # waifu-tips.js` behind a `//`, where a previous author left the packed form
            # of a widget beside the readable one. The claim this rule makes is that
            # obfuscated code cannot be reviewed; a commented-out blob is not code, and
            # the readable version is right there.
            #
            # This detector was the only one with no comment test at all, so the
            # signature matched wherever it appeared.
            yield Hit(
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
                start=found.start(),
                end=found.end(),
            )
            return

    def _long_lines(
        self, content: FileContent, ctx: ScanContext, language: str | None = None
    ) -> Iterable[Hit]:
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
        if BUNDLER_PRELUDE.search(content.raw[:GENERATED_HEADER_BYTES]) or (
            SourcePaths.is_editor_extension(content.path) and "/out/" in content.path
        ):
            # Bundler output, by what it opens with or by where an extension's build writes it.
            # A long line is what a bundle is made of; the other rules still read it.
            return
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
        if (
            ObfuscationText._longest_unbroken_run(text) < UNBROKEN_RUN_THRESHOLD
            and ObfuscationText._longest_padding_run(text) < PADDING_RUN_THRESHOLD
        ):
            # Long, but made of words and not padded out. A payload is either
            # one token or pushed past the edge of the screen; this is neither.
            return
        if "sourceMappingURL=data:" in text[:4000]:
            # An inline source map. Every bundler that has ever emitted one
            # wrote a single base64 line of exactly this shape, and it is a
            # comment: nothing reads it but a debugger.
            return

        start = content.line_starts[index - 1]
        yield Hit(
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
            # Recorded, not raised, unless an install hook runs the file (raised to HIGH below):
            # a long line elsewhere is what minified and generated code is made of, and what
            # decodes and runs a payload is reported by the rules that see it do so. At MEDIUM
            # it was the only code warning on 4,841 of 234,509 benign units -- jQuery, Ace's
            # `src-min-noconflict`, R vignettes -- and decided no block (review 98).
            severity=Severity.LOW,
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

    """A package description's value, keyword or dict entry: the README a build tool inlined."""


__all__ = [
    "BIDI_AND_INVISIBLE",
    "BUNDLER_PRELUDE",
    "CHAR_CODE_RUN",
    "CHAR_CODE_UNIT",
    "CONCEALED_TEXT",
    "CUMULATIVE_ENCODED_UNITS",
    "ENTROPY_THRESHOLD",
    "ESCAPE_RUN",
    "ESCAPE_UNIT",
    "GENERATED_HEADER_BYTES",
    "GENERATED_MARKER",
    "JAVASCRIPT_LANGUAGES",
    "LONG_LINE_THRESHOLD",
    "MINIFIED_PATHS",
    "MIN_DISTINCT_ENCODED",
    "NUMERIC_ARG",
    "PACKERS",
    "PADDING_RUN_THRESHOLD",
    "PRINTABLE_SHARE",
    "UNBROKEN_RUN_THRESHOLD",
    "ObfuscationDetector",
]
