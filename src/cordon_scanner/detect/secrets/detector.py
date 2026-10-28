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

import base64
import binascii
import functools
import re
from typing import TYPE_CHECKING

from cordon_scanner.decide.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
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
from cordon_scanner.foundation.samples import SampleKinds
from cordon_scanner.foundation.text.comments import SourceComments
from cordon_scanner.foundation.text.literals import LiteralGate
from cordon_scanner.foundation.text.prose import Prose
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.detect.secrets.names import NOT_A_SECRET, SecretNames
from cordon_scanner.detect.secrets.patterns import (
    ASSIGNMENT,
    CONNECTION_STRING,
    CREDENTIAL_NAME,
    LOCAL_OR_RESERVED_HOST,
    MIN_KEY_BODY,
    PEM_ARMOUR_ONLY,
    PROVIDER_PATTERNS,
    ROTATE,
    SecretPattern,
)
from cordon_scanner.detect.secrets.secrets import (
    FIXTURE_CONFIDENCE,
    RULE_MATERIAL_CEILING,
    SourceSpans,
)
from cordon_scanner.detect.secrets.values import CLIENT_CONFIG_RULES, PLACEHOLDER, SecretValues

CANONICAL_UUID = re.compile(
    rb"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
"""A UUID, exactly and nothing else.

Reported at MEDIUM rather than HIGH, and reported rather than dismissed. Both halves
are deliberate.

A UUID genuinely is a secret in some systems -- `vimagick/dockerfiles` sets
`SESSION_SECRET` to one and PhotoPrism sets `PHOTOPRISM_OIDC_SECRET` to one, in compose
files anybody can read -- so dismissing the shape would be a miss.

But it is also the commonest identifier format in computing and the one an example
value is generated in: those two compose files are examples, and `JamesWoolfenden/pike`
has a third in a Terraform fixture. 122 bits in a format whose purpose is
identification is weaker evidence than forty characters of base62, whose only purpose
is to be a key, and the severity should say so."""

MINIFIED_LINE = 1000
"""How long a line has to be before the file is build output rather than source.

The same number the capability detector uses, stated here rather than imported for the
same reason the key-corpus ceilings are: `detect.secrets` is where the path predicates
live and it must not depend on a sibling detector for a constant.

A minified bundle has no line breaks, so one line is the whole file. Nothing anybody
writes by hand reaches a thousand characters on one line -- and the files that do and
are not minified, a data table or a long base64 blob, are build output too."""

MIN_ASSIGNMENT_ENTROPY = 2.8
"""Entropy floor for a credential-shaped assignment.

Below this the value is a word or a placeholder rather than a generated secret.

Lowered from 3.2. Shannon entropy over a short sample is bounded by log2(len),
so a genuine 21-character credential scores about 3.05 and was discarded by the
old floor -- the docstring's premise, that real key material sits well above
3.5, holds only for long values. The floor is compensated by a character-class
diversity test, which distinguishes `S3cr3tP4ssw0rdXyz9Qq` from `passwordpassword`
far better than entropy alone does at this length.
"""

MIN_ASSEMBLED_ENTROPY = 4.0
"""Entropy floor for a value built by concatenation.

Higher than the floor for a plain assignment, and deliberately so. Assembly is
also how ordinary code builds paths, messages and URLs, so the bar for calling
one a credential on entropy alone has to sit above anything a human wrote by
hand. A value with a known credential prefix skips this entirely -- the prefix
is the evidence."""

MIN_ASSEMBLED_LENGTH = 20
"""How long an assembled value must be before entropy is consulted.

Shannon entropy over a short sample is bounded by log2 of its length, so a
15-character value cannot reach the floor above whatever it contains. Testing
it would only produce a number that means nothing."""

CREDENTIAL_PREFIXES = (
    b"AKIA",
    b"ASIA",
    b"ghp_",
    b"gho_",
    b"ghu_",
    b"ghs_",
    b"ghr_",
    b"github_pat_",
    b"glpat-",
    b"xox",
    b"sk_live_",
    b"sk-",
    b"npm_",
    b"AIza",
    # Private key headers only. `-----BEGIN` also opens a CERTIFICATE, which
    # is public by design and is committed on purpose in every TLS test suite
    # -- it produced thirty-nine findings in OkHttp alone.
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN DSA PRIVATE KEY",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN PGP PRIVATE KEY",
    b"-----BEGIN ENCRYPTED PRIVATE KEY",
)
"""Prefixes that exist to make a credential format recognisable.

A value starting with one of these is a credential regardless of what its
entropy says, which matters because a padded or low-variety token sits below any
sensible entropy floor while still being live."""

MIN_CHARACTER_CLASSES = 2
"""How many of {lower, upper, digit, symbol} a value must use.

Generated key material almost always mixes at least two. A dictionary word or a
repeated filler string uses one, and those are what the entropy floor was
carrying alone."""

LONE_KEY_ID_NOTE = (
    " No secret access key appears beside it, and an access key id on its own cannot "
    "authenticate -- it is the public name of a credential rather than the credential. "
    "Reported below its usual severity for that reason: it still identifies an account, "
    "and if the secret half is held somewhere a reader can reach, the pair is live."
)
"""Said on the finding, because a reader who is not told why will assume a mistake."""

CLIENT_APP_LANGUAGES = frozenset({"kotlin", "java", "swift", "objective-c", "dart", "html"})
"""Languages whose source becomes a client app -- Android, iOS, Flutter, a web page. A Google API
key there is in every installed copy; NewPipe, Telegram and every YouTube client carry one."""

CLIENT_APP_EXTENSIONS = (".html", ".htm", ".m", ".mm")
"""Web pages and Objective-C, which have no language entry of their own."""

CLIENT_APP_KEY_NOTE = (
    " It is in client-app source, so it ships inside every installed copy and anyone can read it; "
    "Google documents such keys as protected by API and application restrictions, not by secrecy. "
    "Reported below the gate: confirm the key is restricted to the APIs and apps that need it."
)

CLIENT_ID_ASSIGNED = re.compile(rb"(?i)client[_-]?id[\"']?[ \t]{0,8}[:=]")

_WHITESPACE = re.compile(rb"\s")
"""Any space in a value.

Separates prose and SQL from key material better than entropy does at these
lengths, because a generated credential is a single token by construction."""


class SecretDetector(BaseDetector):
    """Finds committed credentials."""

    id = "secrets"
    # 0.2.1: the assignment pattern no longer matches across a newline. The bump is not
    # cosmetic - `ScanCache.detector_signature` is `id@version`, and it is the ONLY thing that
    # invalidates a cached result when a detector's behaviour changes. Without it, everyone who
    # upgrades keeps being served the false positives this release removes, out of a cache whose
    # other inputs (file content, rulepack hash, config) are all unchanged.
    # 0.3.0: documentation embedded in source is recognised, the credential keyword
    # has to end a word, and several expression shapes are no longer credentials. Same
    # reasoning as the note above: the version is what invalidates a cached result.
    # 0.13.0: a URL's host is matched as a host, so the reserved-host exclusion is
    # no longer defeated by the quote that ends the string the URL sits inside; and a
    # key on the line above its own value is read.
    # 0.14.0: a space separates words in a directory name, so meson's `test cases/`
    # is the test directory it says it is.
    version = "0.15.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def __init__(self) -> None:
        self._documentation: dict[str, tuple[tuple[int, int], ...]] = {}
        """Documentation spans, by path. See `_inside_documentation`."""

        self._test_modules: dict[str, tuple[tuple[int, int], ...]] = {}
        """Rust test-module spans, by path. See `_inside_test_module`."""

        self._blocks: dict[str, tuple[tuple[int, int], ...]] = {}
        """`/* ... */` spans, by path. See `_is_commented`."""

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    @functools.cache
    def provider_gate() -> LiteralGate | None:
        """Any provider pattern's literal at all; None if some pattern has no prefilter."""
        if not all(spec.prefilter for spec in PROVIDER_PATTERNS):
            return None
        return LiteralGate([literal for spec in PROVIDER_PATTERNS for literal in spec.prefilter])

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        findings: list[Finding] = []
        seen: set[str] = set()

        raw = content.raw

        # Every provider pattern has a prefilter, so a file holding none of their literals at all
        # can skip all of them. One gate over the union finds that with a few shared core searches
        # (`LiteralGate`) where the per-pattern loop searched for all 103 literals: 1.85 s against
        # 8.1 s over ten thousand files of ordinary packages, and 60% of files stop here.
        gate = SecretDetector.provider_gate()
        specs = PROVIDER_PATTERNS if gate is None or gate.present(raw) else ()
        for spec in specs:
            # Every provider credential has a fixed prefix; that is what makes
            # the format recognisable. A substring test is orders of magnitude
            # cheaper than the regex and rejects almost every file.
            if spec.prefilter and not any(lit in raw for lit in spec.prefilter):
                continue
            for match in spec.pattern.finditer(raw):
                # Named distinctly from `raw`. Reusing that name here rebinds
                # the file content to the matched token, so every later
                # prefilter tests the previous match instead of the file and
                # silently stops finding anything.
                matched = match.group(0)
                if PLACEHOLDER.search(matched) or SecretValues.is_published_credential(matched):
                    continue
                if SecretValues.is_client_configuration(unit.path, spec.rule_id):
                    continue
                if spec.rule_id in CLIENT_CONFIG_RULES and SecretValues.is_firebase_web_config(
                    raw, match.start(), match.end()
                ):
                    # Firebase's published web configuration. See
                    # `is_firebase_web_config`; scoped to the same rule the file-name
                    # test is, because nothing else in a `.env` is excused by it.
                    continue
                if SecretValues.looks_sequential(matched):
                    # The alphabet in order, inside a provider prefix. `TryGhost/Ghost`
                    # documents Stripe with `sk_live_abcdefghij...XYZ` and
                    # `headroomlabs` writes `Bearer sk-ant-api03-abcdefghij...`. This
                    # test has always been applied to the generic rule and not to these.
                    continue
                if SecretValues.is_illustrated_by_its_key(raw, match.start()):
                    continue
                if SecretValues.is_presigned_credential(raw, match.start()):
                    continue
                if SecretValues.decodes_to_prose(matched):
                    # The body is base64 for a sentence. See `decodes_to_prose`.
                    continue
                if (
                    SecretValues.holds_published_key(raw, match.start())
                    or SecretValues.holds_illustrative_key(raw, match.start())
                    # Or the name in front of it says it is a sample. See
                    # `key_name_is_illustrative`: `holds_illustrative_key` reads the BODY
                    # and cannot help when the body is a real key of real length, which
                    # is what `vapor` ships in its development target.
                    or SecretValues.key_name_is_illustrative(raw, match.start())
                ):
                    continue
                digest = Evidence.hash_bytes(matched)
                if digest in seen:
                    continue
                seen.add(digest)
                # An access key id with no secret beside it is graded, not dropped. See
                # `is_lone_access_key_id`.
                lone = SecretValues.is_lone_access_key_id(
                    raw, match.start(), match.end(), spec.rule_id
                )
                # A Google key in an app's own source ships inside every installed copy.
                client_app = spec.rule_id in CLIENT_CONFIG_RULES and (
                    unit.language in CLIENT_APP_LANGUAGES
                    or unit.path.lower().endswith(CLIENT_APP_EXTENSIONS)
                )
                findings.append(
                    self._finding(
                        spec,
                        unit,
                        ctx,
                        match.start(),
                        match.end(),
                        matched,
                        grade=Severity.MEDIUM if lone or client_app else None,
                        note=LONE_KEY_ID_NOTE
                        if lone
                        else CLIENT_APP_KEY_NOTE
                        if client_app
                        else "",
                    )
                )

        findings.extend(self._assembled_findings(unit, ctx, seen))
        findings.extend(self._assignment_findings(unit, ctx, seen))
        findings.extend(self._connection_findings(unit, ctx, seen))
        return self._one_per_credential(findings)

    #: A line of a doctest or an interactive transcript, which is documentation.
    #:
    #: Django's template parser documents itself with a doctest line assigning a
    #: filter expression -- `variable`, a pipe, `default:` and a quoted default --
    #: to a local called `token`. The assignment rule read the filter expression as
    #: a credential assigned to `token` and reported it at HIGH. A transcript is
    #: prose that happens to be executable, and a value in one is an illustration
    #: of a format by construction.
    #:
    #: The example is described rather than quoted, because this file is scanned by
    #: the tool it configures and the literal form trips the rule it documents.
    #:
    #: `>>>` and `...` are Python's doctest prompts; `$` and `#` are a shell
    #: transcript; `In [n]:` is IPython's; `iex>` and `iex(1)>` are Elixir's (its doctests
    #: run them -- Phoenix.Token's documentation signs with an example secret that way);
    #: `irb(main):001:0>` and `pry(main)>` are Ruby's.
    EXAMPLE_PROMPT = re.compile(
        r"""^\s*(?:>>>|\.\.\.|\$\s|#\s|In\s\[\d+\]:|iex(?:\(\d+\))?>|"""
        r"""irb\([^)\n]{1,40}\)(?::\d+){1,2}>|pry\([^)\n]{1,40}\)>)""",
    )

    def _inside_test_module(self, unit: FileUnit, offset: int) -> bool:
        """Whether this offset falls in a Rust `#[cfg(test)]` module.

        The language's own convention for where unit tests live, which is the file they
        test. `rustfs/src/auth.rs` supplied 51 findings that way -- assertions about
        constant-time comparison, using AWS's documented example key as a sample.

        Cached per file for the same reason the documentation spans are.
        """
        if unit.language != "rust":
            return False
        cached = self._test_modules.get(unit.path)
        if cached is None:
            cached = SourceSpans.test_module_spans(unit.content.text)
            self._test_modules[unit.path] = cached
        return any(start <= offset < end for start, end in cached)

    def _inside_documentation(self, unit: FileUnit, offset: int) -> bool:
        """Whether this offset falls in documentation embedded in the source itself.

        A docstring, or one of Ansible's `DOCUMENTATION`/`EXAMPLES`/`RETURN` blocks.
        The path test cannot answer this -- `plugins/modules/consul_token.py` is
        source, and the example token is inside it -- and `community.general` produced
        29 findings that way, every one an example written the way examples are.

        Cached per file, because a module with a documentation block usually has
        several findings in it and the parse is the expensive half.
        """
        if unit.language != "python":
            return False
        cached = self._documentation.get(unit.path)
        if cached is None:
            cached = SourceSpans.documentation_spans(unit.content.text)
            self._documentation[unit.path] = cached
        return any(start <= offset < end for start, end in cached)

    def _is_commented(self, unit: FileUnit, offset: int) -> bool:
        """Whether this assignment is a remark rather than an assignment.

        Applied to the GENERIC rule only, and not to the provider patterns. This
        rule's evidence is a credential-ish name beside a high-entropy value, which
        prose defeats: a TensorFlow header explains in a comment what a compiler pass
        renames instructions to, in a sentence ending "pass" and a colon and an
        example name, and that reads to this rule as a credential assignment.

        A provider pattern is different and is left alone. A GitHub token prefix
        followed by thirty-six characters is a token wherever it sits, including on a
        line somebody commented out instead of rotating. See `core.comments`.
        """
        content = unit.content
        line = content.line_text(content.line_of(offset))
        if SourceComments.is_commented(line, content.column_of(offset) - 1, unit.language):
            return True

        # And the block the per-line test cannot see. Its heuristic asks whether the
        # line begins with `*`, which is what a documentation comment looks like and
        # not what a paragraph of prose looks like. Cached per file for the reason
        # `_inside_documentation` is: a file with a long comment usually has several
        # matches inside it, and the pass over the text is the expensive half.
        cached = self._blocks.get(unit.path)
        if cached is None:
            cached = SourceComments.block_comment_spans(content.text, unit.language)
            self._blocks[unit.path] = cached
        return SourceComments.inside_spans(cached, offset)

    @staticmethod
    def _is_example_line(content: FileContent, offset: int) -> bool:
        """Whether this offset is on a line that is a transcript, not code."""
        line = content.line_text(content.line_of(offset))
        return bool(line) and SecretDetector.EXAMPLE_PROMPT.match(line) is not None

    @staticmethod
    def _one_per_credential(findings: list[Finding]) -> list[Finding]:
        """Collapse findings of the same rule over overlapping bytes.

        Deduplication inside each path is by the hash of the matched VALUE, and two
        paths that match different slices of one credential do not share it. Celery's
        test keypairs came back eight times, and two of those were the same key
        reported twice: spans [158, 199] and [168, 200] on the same line, one from the
        provider pattern matching the PEM header and one from the assembled-literal
        path folding the Python triple-quoted string around it. Different bytes,
        different hash, same key, and nothing in the report to tell a reader that
        from two keys.

        The PEM header is named rather than written, for the same reason as above.

        A post-filter rather than a check inside each path, because the duplication is
        BETWEEN paths and a per-path guard cannot see across them -- which is how the
        first attempt at this missed it entirely.

        The widest span wins. Both findings describe one credential and the longer
        match is the one that located more of it, so it is the more useful evidence to
        keep.
        """
        ordered = sorted(
            findings,
            key=lambda f: (
                f.rule_id,
                -((f.evidence.span or (0, 0))[1] - (f.evidence.span or (0, 0))[0]),
                (f.evidence.span or (0, 0))[0],
            ),
        )
        kept: list[Finding] = []
        claimed: dict[str, list[tuple[int, int]]] = {}
        for finding in ordered:
            span = finding.evidence.span
            if span is None:
                kept.append(finding)
                continue
            ranges = claimed.setdefault(finding.rule_id, [])
            if any(start < span[1] and span[0] < end for start, end in ranges):
                continue
            ranges.append(span)
            kept.append(finding)
        # Back to the order the paths produced them in, so output stays stable.
        order = {id(f): i for i, f in enumerate(findings)}
        return sorted(kept, key=lambda f: order[id(f)])

    def _assembled_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        """Credentials split across a concatenation.

        Every pattern above needs a contiguous run of bytes, and `"ghp_" + "..."`
        is not one. The value is identical to the interpreter and invisible to
        the regex, which makes a `+` the cheapest way to commit a live
        credential past a secret scanner -- cheaper than encoding it, since the
        code still reads as ordinary.

        Folding first and matching afterwards means these need no patterns of
        their own: the provider shapes are matched against the assembled value
        exactly as they are against a literal one, and report the same rule.
        """
        for start, end, value, assembled, name in self._folded_values(unit):
            if PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if not assembled and PEM_ARMOUR_ONLY.match(value):
                # A literal the analyser merely resolved, not one built from parts.
                # `assembled` is the whole distinction: the armour on its own is how
                # PEM-handling code names its delimiters, and the armour SPLIT across
                # a concatenation is how somebody gets a key past a scanner.
                continue

            digest = Evidence.hash_bytes(value)
            if digest in seen:
                # Already reported from a contiguous match. The hash is over the
                # value rather than its spelling, so the split and whole forms of
                # one credential are recognised as the same secret.
                continue

            spec = self._assembled_spec(value, assembled=assembled, name=name)
            if spec is None:
                continue

            seen.add(digest)
            yield self._finding(spec, unit, ctx, start, end, value)

    @staticmethod
    def _assembled_spec(
        value: bytes, *, assembled: bool = True, name: str | None = None
    ) -> SecretPattern | None:
        """What an assembled value is, if it is anything.

        A provider shape is decisive on its own: those prefixes exist to make
        the format recognisable, and nothing else produces them. Beyond that the
        bar is deliberately higher than for a contiguous literal, because
        assembly is also how ordinary code builds paths, messages and URLs. The
        entropy floor is the one from the audit rather than the assignment
        floor, so `"pre" + "fix" + "-" + slug` cannot reach it.
        """
        for provider in PROVIDER_PATTERNS:
            if provider.prefilter and not any(lit in value for lit in provider.prefilter):
                continue
            if provider.pattern.search(value):
                return provider

        # The prefix followed by the key, not the prefix alone: litellm declares
        # `LITELLM_VIRTUAL_KEY_PREFIX: Final = "sk-"` to test bearer tokens against.
        # A PEM armour header is decisive alone: it opens a key block.
        if any(
            value.startswith(prefix)
            and (prefix.startswith(b"-----") or len(value) - len(prefix) >= MIN_KEY_BODY)
            for prefix in CREDENTIAL_PREFIXES
        ):
            return SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name="credential assembled from parts",
                pattern=ASSIGNMENT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation=ROTATE,
            )

        if not assembled:
            # A plain literal, carried here only because Python joins adjacent
            # literals with no operator. The provider shapes and prefixes above
            # apply to it; the entropy heuristic below does not, because its
            # justification is that building a value from pieces is not how a
            # URL or an identifier is written -- and applied to every constant
            # it reports every long URL in the project as a credential.
            return None

        if len(value) < MIN_ASSEMBLED_LENGTH:
            return None

        if not (name and CREDENTIAL_NAME.search(name.encode("utf-8", "replace"))):
            # The contiguous path reaches this rule only through a pattern that
            # requires a credential-shaped *name*, and the assembled path
            # dropped that requirement -- so any high-entropy concatenation
            # anywhere qualified, and jQuery, Guava's cache tests and a great
            # deal of ordinary string building were reported as credentials.
            #
            # Provider shapes and known prefixes above still fire whatever the
            # name is, which is right: a GitHub token is one regardless of what
            # it was assigned to. Entropy alone is not, and needs the name to
            # mean anything.
            return None

        if _WHITESPACE.search(value):
            # Key material is one token. Entropy alone cannot tell a credential
            # from a sentence -- Shannon entropy rewards a varied alphabet, and
            # `"SELECT id, name" + " FROM packages"` scores 4.48, well above any
            # floor prose is supposed to sit below. What actually separates them
            # is that a generated secret never contains a space.
            return None

        decoded = value.decode("utf-8", errors="replace")
        if Redactor.shannon_entropy(decoded) < MIN_ASSEMBLED_ENTROPY:
            return None
        if SecretDetector._character_classes(decoded) < MIN_CHARACTER_CLASSES:
            return None

        return SecretPattern(
            rule_id="SECRET.GENERIC.ASSIGNMENT.001",
            name="high-entropy value assembled from parts",
            pattern=ASSIGNMENT,
            severity=Severity.HIGH,
            # Assembly is the signal. A value of this entropy could be a hash or
            # an identifier, but building one out of pieces is not how either is
            # written, and it is exactly how a credential is hidden.
            confidence=Confidence.MEDIUM,
            remediation=ROTATE,
        )

    @staticmethod
    def _folded_values(unit: FileUnit) -> Iterable[tuple[int, int, bytes, bool, str | None]]:
        """Concatenated string values, folded to what they evaluate to.

        Python goes through the AST, which folds `+` chains, `"".join` and
        f-strings of constants, and knows an assignment from an expression.
        Everything else -- and any Python that will not parse -- falls back to
        joining adjacent literals in the bytes, which handles the common form
        without pretending to understand the language.
        """
        content = unit.content

        # First, and unconditionally. The Python branch below returns early for
        # a file that parses, so anything yielded after it is yielded for every
        # language except the one with the best analysis -- which is where this
        # was, and why an encoded token in a `.py` was still missed after the
        # decoder existed.
        yield from SecretDetector._decoded_values(content)

        if unit.language == "python":
            from cordon_scanner.analysis.python.pyfacts import PythonFacts

            starts = content.line_starts
            for item in PythonFacts.assembled(content.text):
                if not item.value:
                    continue
                index = min(max(item.line - 1, 0), len(starts) - 1)
                start = starts[index]
                end = starts[index + 1] if index + 1 < len(starts) else len(content.raw)
                yield (
                    start,
                    end,
                    item.value.encode("utf-8", "surrogatepass"),
                    item.assembled,
                    item.name,
                )
            if PythonFacts.parses(content.text):
                return

        for start, end, value in SecretValues.fold_concatenations(content.raw):
            # The byte fold has no name to offer. Provider shapes and prefixes
            # still apply; the entropy branch does not, which is the honest
            # consequence of not knowing what the value was called.
            yield start, end, value, True, None

    _PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\n\r"

    @staticmethod
    def _is_mostly_printable(data: bytes) -> bool:
        """Whether decoded bytes read as text rather than as a binary blob.

        Base64 decodes anything. Without this, every embedded PNG, font and
        compiled fixture in a repository would be searched for credentials,
        and the ratio is what separates "somebody hid a string here" from
        "this is an image".
        """
        printable = sum(1 for byte in data if byte in SecretDetector._PRINTABLE)
        return printable / len(data) > 0.9

    ENCODED_BLOB = re.compile(rb"""["']([A-Za-z0-9+/]{24,4096}={0,2})["']""")
    """A quoted run of base64, long enough to hold a credential.

    Twenty-four characters is the floor because sixteen bytes is the shortest
    thing worth hiding, and anything shorter matches identifiers, hashes
    fragments and CSS class names in quantity."""

    MAX_DECODED_BLOBS = 64
    """How many blobs to decode per file. A file with more encoded strings than
    this is a data file, and the cost of decoding all of them is paid on every
    scan for a case the first sixty-four already covers."""

    @staticmethod
    def _decoded_values(content: FileContent) -> Iterable[tuple[int, int, bytes, bool, str | None]]:
        """Credentials hidden inside a base64 literal.

        Splitting a token across a `+` was already handled -- the fold above
        evaluates it the way the interpreter does. Encoding it was not: every
        secret pattern matches a contiguous run of the credential's own
        alphabet, and base64 is a different alphabet, so

            TOKEN = base64.b64decode("Z2hwX0JCQkJCQkJC...").decode()

        committed a live GitHub token past a scanner that catches the same
        token written plainly and catches it again when split in two. One
        decode step, and the shape the pattern is built around is simply not
        present in the file.

        Yielded as NOT assembled, which is what keeps this quiet: only the
        provider shapes and the known credential prefixes apply, and those are
        decisive on their own. The entropy branch is deliberately out of reach
        -- base64 of anything scores high by construction, so admitting it here
        would report every embedded certificate, icon and test fixture in the
        world.
        """
        decoded_count = 0
        for match in SecretDetector.ENCODED_BLOB.finditer(content.raw):
            if decoded_count >= SecretDetector.MAX_DECODED_BLOBS:
                return
            blob = match.group(1)
            try:
                plain = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            decoded_count += 1
            if not plain or not SecretDetector._is_mostly_printable(plain):
                continue
            yield match.start(), match.end(), plain, False, None

    # What every `ASSIGNMENT` match contains, read off the pattern and matched against the
    # lower-cased file: a credential word (`api_key`, `client_secret` and the rest each contain one
    # of these five), at most forty name characters, a colon or an equals sign, and a value of
    # twelve characters from the quoted value's class -- which the unquoted value's is a subset of.
    # It opens on literals, so the engine skips to them; the pattern itself opens on a lazy name
    # run it tries at every byte. Over ten thousand files of ordinary packages: 20.8 s to 5.2 s,
    # with the same matches in every file. 573 files pass it; 12 have a match.
    ASSIGNMENT_GATE = re.compile(
        rb"(?:pass|secret|token|key|credential)[a-z0-9_.\-]{0,40}[ \t]*[:=][ \t]*[\"']?[^\"'\s;<>]{12}"
    )

    # A credential-shaped assignment needs one of these words present. Checking
    # for them first avoids running a large alternation over files that cannot
    # match it.
    ASSIGNMENT_PREFILTER = (
        b"pass",
        b"Pass",
        b"PASS",
        b"secret",
        b"Secret",
        b"SECRET",
        b"token",
        b"Token",
        b"TOKEN",
        b"key",
        b"Key",
        b"KEY",
        b"auth",
        b"Auth",
        b"AUTH",
    )

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        """Every rule this detector can emit, provider shapes included.

        `cordon rules show SECRET.AWS.ACCESS_KEY.001` answered "no such rule"
        for a rule the tool emits, which is the plainest possible statement that
        the rule set was not reviewable.
        """
        declared = [
            DeclaredRule(
                id=spec.rule_id,
                title=f"Committed credential: {spec.name}",
                severity=spec.severity,
                confidence=spec.confidence,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                # One sentence, generated from the provider name, because the
                # claim is the same for all of them and the shape is what
                # differs. The per-finding message says where and what; this is
                # what `cordon rules show` answers before a scan has run.
                message=(
                    f"This file carries a credential in the format of {spec.name}, "
                    f"which is the shape its provider issues. Anything committed is "
                    f"in git history and in every clone, so it must be treated as "
                    f"public from the moment it landed -- whether or not it is still "
                    f"in the working tree."
                ),
                remediation=spec.remediation,
                references=(references.HARDCODED_CREDENTIALS, references.OWASP_SECRETS_MANAGEMENT),
            )
            for spec in PROVIDER_PATTERNS
        ]
        declared.append(
            DeclaredRule(
                id="SECRET.GENERIC.ASSIGNMENT.001",
                title="Credential-shaped value assigned to a credential-shaped name",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                message=(
                    "A value with the length and character mix of a credential is "
                    "assigned to a name that says it is one. No provider format "
                    "identifies it, so the name and the entropy are the whole of "
                    "the evidence -- which is why the value has to clear an "
                    "entropy floor and the name has to be a whole word."
                ),
                remediation=ROTATE,
                references=(
                    references.HARDCODED_CREDENTIALS,
                    references.OWASP_SECRETS_MANAGEMENT,
                ),
            )
        )
        declared.append(
            DeclaredRule(
                id="SECRET.URL.CREDENTIAL.001",
                title="Credential embedded in a URL",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                message=(
                    "A URL carries a user name and a password before the host, "
                    "which is the conventional way such URLs are written and puts "
                    "a live credential somewhere no assignment pattern looks. It "
                    "reaches logs, error messages and anything that echoes the "
                    "connection string."
                ),
                remediation=ROTATE,
                references=(
                    references.HARDCODED_CREDENTIALS,
                    references.CLEARTEXT_TRANSMISSION,
                ),
            )
        )
        # The history pass and the opt-in liveness check emit under this detector too: they are
        # findings about the same credentials, read from history or confirmed by their issuer.
        from cordon_scanner.detect.secrets.secret_history import SecretHistoryRules

        declared.extend(SecretHistoryRules.declared())
        # Deduplicated: several provider shapes share a rule id on purpose,
        # because they are the same finding about the same kind of credential.
        unique: dict[str, DeclaredRule] = {}
        for rule in declared:
            unique.setdefault(rule.id, rule)
        return tuple(unique.values())

    @staticmethod
    def _character_classes(value: str) -> int:
        """How many of {lower, upper, digit, symbol} the value uses."""
        return sum(
            (
                any(c.islower() for c in value),
                any(c.isupper() for c in value),
                any(c.isdigit() for c in value),
                any(not c.isalnum() for c in value),
            )
        )

    def _connection_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        """Passwords embedded in a URL's userinfo.

        See CONNECTION_STRING. A worked example is deliberately not written out
        here, for the reason given there.
        """
        raw = unit.content.raw
        if b"://" not in raw:
            return
        for match in CONNECTION_STRING.finditer(raw):
            value = match.group(1)
            # An identifier in the credential position is a field name rather
            # than a credential. Connection documentation is written with the
            # field names themselves standing in for the values -- the AWS key
            # id and secret spelled out where the credentials would go -- and
            # reading that as a leak produced fifty-two findings across
            # SQLAlchemy's, httpx's and Celery's documentation.
            if PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if LOCAL_OR_RESERVED_HOST.match(match.group(2)):
                continue
            # One character class is a word, not a generated credential.
            # `strongpassword` and `urlpass` are what documentation writes
            # where a password goes, and neither has a digit, a capital or a
            # symbol in it. The assignment rule has carried this test for the
            # same reason; this one had only the placeholder list, which cannot
            # enumerate every way somebody spells "put your password here".
            if self._character_classes(value.decode("utf-8", "replace")) < MIN_CHARACTER_CLASSES:
                continue
            # Or the name declaring the URL says it is an example. The provider
            # patterns have asked this since `vapor`'s sample key; this rule
            # never did, and a connection string is the form documentation shows
            # most often, because it is the form a user has to type.
            if SecretValues.key_name_is_illustrative(raw, match.start()):
                continue
            digest = Evidence.hash_bytes(value)
            if digest in seen:
                continue
            seen.add(digest)
            spec = SecretPattern(
                rule_id="SECRET.URL.CREDENTIAL.001",
                name="credential embedded in a URL",
                pattern=CONNECTION_STRING,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                remediation=ROTATE,
            )
            yield self._finding(spec, unit, ctx, match.start(), match.end(), value)

    def _assignment_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        raw = unit.content.raw
        if not any(lit in raw for lit in self.ASSIGNMENT_PREFILTER):
            return
        if not self.ASSIGNMENT_GATE.search(raw.lower()):
            return
        for match in ASSIGNMENT.finditer(raw):
            # Group 1 is the name; 2 the quoted value, 3 the unquoted one.
            value = match.group(2) or match.group(3)
            if not value or PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if SecretValues.reads_as_words(value):
                # The value is words rather than a generated run. See `reads_as_words`.
                continue
            if SecretValues.decoded_is_not_a_secret(value):
                # The base64 decodes to something already refused. See
                # `decoded_is_not_a_secret`.
                continue
            if SecretValues.is_firebase_web_config(raw, match.start(1), match.end()):
                # Firebase's published web configuration. The provider path has asked
                # this since the eighth pass; `excalidraw` assigns the whole object to
                # one variable, so the generic rule sees `apiKey` inside a JSON blob and
                # had to ask it too.
                continue
            if SecretValues.is_published_credential(value) or SecretValues.decodes_to_prose(value):
                # Both tests were on the provider path only, which is backwards: a
                # vendor's published default is usually assigned to an ordinary name
                # rather than carrying a provider prefix. Supabase's self-host
                # `docker-compose.yml` assigns its `SECRET_KEY_BASE` that way, and every
                # project that copies the file copies the value.
                continue

            decoded = value.decode("utf-8", errors="replace")
            if Redactor.shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
                continue
            if SecretValues.looks_sequential(value):
                # An alphabet, not a secret. See `looks_sequential`.
                continue
            if self._character_classes(decoded) < MIN_CHARACTER_CLASSES:
                # Carries what the entropy floor used to carry alone. A
                # dictionary word or a repeated filler uses one class; generated
                # key material almost always mixes at least two.
                continue

            digest = Evidence.hash_bytes(value)
            if digest in seen:
                continue
            seen.add(digest)

            if (
                PEM_ARMOUR_ONLY.match(value)
                or SecretValues.is_public_by_design(value)
                or SecretValues.is_password_hash(value)
            ):
                continue

            name = match.group(1).decode("utf-8", errors="replace")
            if (
                SecretNames.names_configuration(name)
                or SecretNames.names_placeholder(name)
                or SecretNames.names_public_by_contract(name)
                or SecretNames.names_identifier(name)
            ):
                continue
            if SecretValues._decoded_text(value) and SecretNames.value_restates_the_name(
                name, SecretValues._decoded_text(value)
            ):
                # The base64 decodes to the name plus almost nothing. `harvester` writes
                # `db-password: ZGJwYXNzd29yZDEx`, which is `dbpassword11`, and the
                # question `value_restates_the_name` asks could not see through the
                # encoding.
                continue
            if SecretNames.value_restates_the_name(name, decoded):
                # The value is the name plus a word or a number. See
                # `value_restates_the_name`, and `value_is_the_name` for why the plain
                # containment test this narrows is refused.
                continue
            if SecretNames.value_is_the_name(name, decoded):
                # An enum member, a feature flag, a storage key: the value is the name
                # written the way the wire spells it. See `value_is_the_name`.
                continue
            if SecretDetector._is_example_line(unit.content, match.start(1)):
                continue
            if SecretValues.is_inside_example_literal(raw, match.start(1), unit.language):
                # A Go raw string the author named as example or help text. See
                # `is_inside_example_literal`.
                continue
            if self._is_commented(unit, match.start(1)):
                continue
            # The name's own offset, not the match's. The pattern opens with
            # `(?:^|[^\w.])`, which on every line but the first consumes the
            # newline that ended the line before -- so `match.start()` sits on
            # the previous line and every finding from this rule pointed one
            # line above the credential.
            spec = SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name=f"credential assigned to {name!r}",
                pattern=ASSIGNMENT,
                # A UUID is graded down rather than dismissed. See `CANONICAL_UUID`:
                # it really is the secret in some systems, and it is also the format an
                # example value is generated in.
                severity=(
                    Severity.MEDIUM
                    if CANONICAL_UUID.match(value)
                    or SecretValues.is_url_parameter(raw, match.start(1))
                    # rclone, alist and every desktop or CLI OAuth client ship a client secret
                    # beside its client ID, because the app cannot keep one: RFC 8252 treats
                    # such a client as public. Worth a look, and not a build failure.
                    or (
                        SecretNames.names_client_secret(name)
                        and CLIENT_ID_ASSIGNED.search(raw) is not None
                    )
                    # A query parameter of a URL is a signed link. Graded for the same
                    # reason a UUID is -- it is usually not a credential and sometimes
                    # is. See `is_url_parameter`.
                    else Severity.HIGH
                ),
                # Medium, not high: a high-entropy string assigned to something
                # named `token` is usually a credential and is sometimes a hash,
                # an identifier or a fixture. The finding is worth a look and is
                # not worth failing a build on its own.
                confidence=Confidence.MEDIUM,
                remediation=ROTATE,
            )
            yield self._finding(spec, unit, ctx, match.start(1), match.end(), value)

    def _finding(
        self,
        spec: SecretPattern,
        unit: FileUnit,
        ctx: ScanContext,
        start: int,
        end: int,
        raw: bytes,
        grade: Severity | None = None,
        note: str = "",
    ) -> Finding:
        content = unit.content
        line = content.line_of(start)
        rule_material = content.is_rule_material
        fixture = not rule_material and (
            SourcePaths.is_test_material(content.path) or self._inside_test_module(unit, start)
        )
        documentation = not (rule_material or fixture) and (
            SourcePaths.is_documentation(content.path) or self._inside_documentation(unit, start)
        )
        # Generated output, which this detector was the only one not to ceiling.
        # Jest vendors `.yarn/releases/yarn-4.18.0.cjs` -- five megabytes of bundled
        # JavaScript -- and a credential-shaped assignment inside a bundle belongs to
        # whichever library was bundled, not to the repository that committed the
        # artefact.
        # A media extractor, which holds the key the site's own web player holds. Asked
        # before the generated-output family because the caveat is a different claim: the
        # value is real and is not the project's to rotate. See
        # `core.samples.is_media_extractor`.
        extractor = not (
            rule_material or fixture or documentation
        ) and SampleKinds.is_media_extractor(content.raw)
        generated = not (rule_material or fixture or documentation or extractor) and (
            SourcePaths.is_generated_artefact(content.path)
            or SourcePaths.is_vendored(content.path)
            # Or a dataset: twenty thousand rows of scraped web pages is not source
            # somebody wrote, and it is graded for the same reason build output is.
            # See `is_bulk_data`.
            or SourcePaths.is_bulk_data(content.path, content.line_count)
            # Or minified, which is build output that was not given a build output's
            # name. `alibaba/nacos` serves `console/src/main/resources/static/legacy/
            # js/main.js`, a bundle on one line of 300KB, and `**/*.min.js` cannot see
            # it. The capability detector has ceilinged on this since it measured the
            # same thing; this detector was comparing names only.
            or content.longest_line > MINIFIED_LINE
        )
        ceilinged = rule_material or fixture or documentation or generated or extractor
        ceiling = RULE_MATERIAL_CEILING if rule_material else FIXTURE_CEILING
        severity = min(spec.severity, ceiling) if ceilinged else spec.severity
        # A grade the caller worked out from the value itself, rather than from where
        # the file sits. It lowers and never raises, so it composes with the ceilings
        # above in either order.
        if grade is not None:
            severity = min(severity, grade)
        confidence = min(spec.confidence, FIXTURE_CONFIDENCE) if ceilinged else spec.confidence
        caveat = ""
        if rule_material:
            caveat = (
                " The file is another analyser's rule material -- a rule set, or a test "
                "case annotated for one -- so a credential-shaped string in it was "
                "published in order to be detected. Reported for the record only."
            )
        elif fixture:
            caveat = (
                " It sits under a path that holds test material, where a credential "
                "of this shape is usually generated for the test suite, so it is "
                "reported below its usual severity -- but a real key committed here "
                "leaks exactly as far as one committed anywhere else."
            )
        elif generated:
            caveat = (
                " It sits in generated build output or in bulk data rather than in "
                "source somebody wrote, so a credential-shaped string in it came from "
                "whatever was bundled or exported, and it is reported below its usual "
                "severity."
            )
        elif extractor:
            caveat = (
                " It sits in a media extractor, which holds the key the site's own web "
                "player holds -- read out of a public page, still in that page, and not "
                "this project's to rotate. Reported below its usual severity for that "
                "reason: it is a real credential, and the party who can act on it is the "
                "one who published it."
            )
        elif documentation:
            caveat = (
                " It sits in documentation, where a credential-shaped string is "
                "usually an example of the format rather than a live value, so it is "
                "reported below its usual severity -- but a real key pasted into a "
                "README leaks exactly as far as one in a settings file, and plenty "
                "have been."
            )

        return Finding(
            rule_id=spec.rule_id,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=confidence,
            message=(
                f"{Prose.article(spec.name).capitalize()} {spec.name} appears in this file. "
                + (
                    # In an image the exposure is the image itself: every layer and the
                    # configuration go to everyone who pulls it, a file a later layer deleted too.
                    "Everything in an image's layers and configuration ships to everyone who "
                    "pulls it -- a file a later layer deleted included -- so it must be treated "
                    "as public from the moment the image was pushed."
                    if ctx.image is not None
                    else "Anything committed is in git history and in every clone, so it must "
                    "be treated as public from the moment it landed, whether or not it is "
                    "still in the working tree."
                )
                + f"{caveat}{note}"
            ),
            location=Location(
                path=content.path,
                line=line,
                column=content.column_of(start),
                byte_start=start,
                byte_end=end,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.secret_hash(raw),
                # Hash-only, and not overridable. `--evidence full` is typed by
                # somebody debugging a false positive, not by somebody thinking
                # about where the log ends up.
                redaction=RedactionMode.HASH_ONLY,
                span=(start, end),
                metadata=(("kind", spec.name),),
            ),
            remediation=spec.remediation,
            explanation=Explanation(
                summary=f"Detected a {spec.name}.",
                matched_rule=spec.rule_id,
                escalations=("the value is withheld from this report; the hash identifies it",),
            ),
            risk=ctx.scorer.score(
                severity,
                confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    capabilities=frozenset(),
                ),
            ),
            detector=self.id,
        )


__all__ = [
    "CANONICAL_UUID",
    "CLIENT_APP_EXTENSIONS",
    "CLIENT_APP_KEY_NOTE",
    "CLIENT_APP_LANGUAGES",
    "CLIENT_ID_ASSIGNED",
    "CREDENTIAL_PREFIXES",
    "LONE_KEY_ID_NOTE",
    "MINIFIED_LINE",
    "MIN_ASSEMBLED_ENTROPY",
    "MIN_ASSEMBLED_LENGTH",
    "MIN_ASSIGNMENT_ENTROPY",
    "MIN_CHARACTER_CLASSES",
    "SecretDetector",
]
