"""Obfuscation by packing: code run through a packer or minified past reading, where it should not be.

The output of a known packer (Dean Edwards' p,a,c,k,e,d, JSFuck, obfuscator.io and kin), and lines too
long, too dense or too random to have been written by hand -- with the minified build output that
looks the same for an innocent reason excluded by path, header and source-map trailer."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import ScanContext
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)
from cordon_scanner.foundation.text.comments import SourceComments
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.code.obfuscation.concealment import (
    PROSE_LANGUAGES,
)
from cordon_scanner.detect.code.obfuscation.encoding import EncodingFindings
from cordon_scanner.detect.code.obfuscation.text import Hit, ObfuscationText

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


class PackingFindings:
    """The obfuscation findings for packed and unreadably long code."""

    @classmethod
    def packers(cls, content: FileContent, language: str | None = None) -> Iterable[Hit]:
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
                if found is None and not EncodingFindings.is_remark(
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

    @classmethod
    def long_lines(
        cls, content: FileContent, ctx: ScanContext, language: str | None = None
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

        index, length = cls._longest_line_index(content)
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
        yield PackingFindings._long_line_hit(content, index, start, length)

    @staticmethod
    def _long_line_hit(content: FileContent, index: int, start: int, length: int) -> Hit:
        """The finding for one extremely long line."""
        return Hit(
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


__all__ = [
    "BUNDLER_PRELUDE",
    "ENTROPY_THRESHOLD",
    "GENERATED_HEADER_BYTES",
    "GENERATED_MARKER",
    "JAVASCRIPT_LANGUAGES",
    "LONG_LINE_THRESHOLD",
    "MINIFIED_PATHS",
    "PACKERS",
    "PADDING_RUN_THRESHOLD",
    "UNBROKEN_RUN_THRESHOLD",
    "PackingFindings",
]
