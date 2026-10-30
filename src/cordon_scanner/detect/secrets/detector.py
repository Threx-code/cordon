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

import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets.assembly import MIN_CHARACTER_CLASSES, SecretAssembly
from cordon_scanner.detect.secrets.names import NOT_A_SECRET, SecretNames
from cordon_scanner.detect.secrets.patterns import (
    ASSIGNMENT,
    CONNECTION_STRING,
    LOCAL_OR_RESERVED_HOST,
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
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.samples import SampleKinds
from cordon_scanner.foundation.scoring import ScoringContext
from cordon_scanner.foundation.text.comments import SourceComments
from cordon_scanner.foundation.text.literals import LiteralGate
from cordon_scanner.foundation.text.prose import Prose
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent

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


class SecretDetector(BaseDetector):
    """Finds committed credentials."""

    id = "secrets"
    # 0.2.1: the assignment pattern no longer matches across a newline. The bump is not
    # cosmetic - `CacheSignature.detector_signature` is `id@version`, and it is the ONLY thing that
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
    @OneOff.cache
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
                self._provider_finding(ctx, findings, match, raw, seen, spec, unit)

        findings.extend(self._assembled_findings(unit, ctx, seen))
        findings.extend(self._assignment_findings(unit, ctx, seen))
        findings.extend(self._connection_findings(unit, ctx, seen))
        return SecretAssembly.one_per_credential(findings)

    def _provider_finding(
        self,
        ctx: ScanContext,
        findings: list[Finding],
        match: re.Match[bytes],
        raw: bytes,
        seen: set[str],
        spec: SecretPattern,
        unit: FileUnit,
    ) -> None:
        """One provider-pattern match: kept unless the value or its place says it is not a credential, and reported once per value."""
        matched = match.group(0)
        if PLACEHOLDER.search(matched) or SecretValues.is_published_credential(matched):
            return
        if SecretValues.is_client_configuration(unit.path, spec.rule_id):
            return
        if spec.rule_id in CLIENT_CONFIG_RULES and SecretValues.is_firebase_web_config(
            raw, match.start(), match.end()
        ):
            # Firebase's published web configuration. See
            # `is_firebase_web_config`; scoped to the same rule the file-name
            # test is, because nothing else in a `.env` is excused by it.
            return
        if SecretValues.looks_sequential(matched):
            # The alphabet in order, inside a provider prefix. `TryGhost/Ghost`
            # documents Stripe with `sk_live_abcdefghij...XYZ` and
            # `headroomlabs` writes `Bearer sk-ant-api03-abcdefghij...`. This
            # test has always been applied to the generic rule and not to these.
            return
        if SecretValues.is_illustrated_by_its_key(raw, match.start()):
            return
        if SecretValues.is_presigned_credential(raw, match.start()):
            return
        if SecretValues.decodes_to_prose(matched):
            # The body is base64 for a sentence. See `decodes_to_prose`.
            return
        if (
            SecretValues.holds_published_key(raw, match.start())
            or SecretValues.holds_illustrative_key(raw, match.start())
            # Or the name in front of it says it is a sample. See
            # `key_name_is_illustrative`: `holds_illustrative_key` reads the BODY
            # and cannot help when the body is a real key of real length, which
            # is what `vapor` ships in its development target.
            or SecretValues.key_name_is_illustrative(raw, match.start())
        ):
            return
        digest = Evidence.hash_bytes(matched)
        if digest in seen:
            return
        seen.add(digest)
        # An access key id with no secret beside it is graded, not dropped. See
        # `is_lone_access_key_id`.
        lone = SecretValues.is_lone_access_key_id(raw, match.start(), match.end(), spec.rule_id)
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
                note=LONE_KEY_ID_NOTE if lone else CLIENT_APP_KEY_NOTE if client_app else "",
            )
        )

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
        for start, end, value, assembled, name in SecretAssembly.folded_values(unit):
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

            spec = SecretAssembly.assembled_spec(value, assembled=assembled, name=name)
            if spec is None:
                continue

            seen.add(digest)
            yield self._finding(spec, unit, ctx, start, end, value)

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
        from cordon_scanner.detect.secrets.secrets import SecretHistoryRules

        declared.extend(SecretHistoryRules.declared())
        # Deduplicated: several provider shapes share a rule id on purpose,
        # because they are the same finding about the same kind of credential.
        unique: dict[str, DeclaredRule] = {}
        for rule in declared:
            unique.setdefault(rule.id, rule)
        return tuple(unique.values())

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
            if (
                SecretAssembly.character_classes(value.decode("utf-8", "replace"))
                < MIN_CHARACTER_CLASSES
            ):
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
            yield from self._assignment_finding(ctx, match, raw, seen, unit)

    def _assignment_finding(
        self, ctx: ScanContext, match: re.Match[bytes], raw: bytes, seen: set[str], unit: FileUnit
    ) -> Iterator[Finding]:
        """The finding for one assignment of a credential-shaped value, unless the value, its name or its place says it is not one."""
        value = match.group(2) or match.group(3)
        if not value or PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
            return
        if SecretValues.reads_as_words(value):
            # The value is words rather than a generated run. See `reads_as_words`.
            return
        if SecretValues.decoded_is_not_a_secret(value):
            # The base64 decodes to something already refused. See
            # `decoded_is_not_a_secret`.
            return
        if SecretValues.is_firebase_web_config(raw, match.start(1), match.end()):
            # Firebase's published web configuration. The provider path has asked
            # this since the eighth pass; `excalidraw` assigns the whole object to
            # one variable, so the generic rule sees `apiKey` inside a JSON blob and
            # had to ask it too.
            return
        if SecretValues.is_published_credential(value) or SecretValues.decodes_to_prose(value):
            # Both tests were on the provider path only, which is backwards: a
            # vendor's published default is usually assigned to an ordinary name
            # rather than carrying a provider prefix. Supabase's self-host
            # `docker-compose.yml` assigns its `SECRET_KEY_BASE` that way, and every
            # project that copies the file copies the value.
            return

        decoded = value.decode("utf-8", errors="replace")
        if Redactor.shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
            return
        if SecretValues.looks_sequential(value):
            # An alphabet, not a secret. See `looks_sequential`.
            return
        if SecretAssembly.character_classes(decoded) < MIN_CHARACTER_CLASSES:
            # Carries what the entropy floor used to carry alone. A
            # dictionary word or a repeated filler uses one class; generated
            # key material almost always mixes at least two.
            return

        digest = Evidence.hash_bytes(value)
        if digest in seen:
            return
        seen.add(digest)

        if (
            PEM_ARMOUR_ONLY.match(value)
            or SecretValues.is_public_by_design(value)
            or SecretValues.is_password_hash(value)
        ):
            return

        name = match.group(1).decode("utf-8", errors="replace")
        if (
            SecretNames.names_configuration(name)
            or SecretNames.names_placeholder(name)
            or SecretNames.names_public_by_contract(name)
            or SecretNames.names_identifier(name)
        ):
            return
        if SecretValues._decoded_text(value) and SecretNames.value_restates_the_name(
            name, SecretValues._decoded_text(value)
        ):
            # The base64 decodes to the name plus almost nothing. `harvester` writes
            # `db-password: ZGJwYXNzd29yZDEx`, which is `dbpassword11`, and the
            # question `value_restates_the_name` asks could not see through the
            # encoding.
            return
        if SecretNames.value_restates_the_name(name, decoded):
            # The value is the name plus a word or a number. See
            # `value_restates_the_name`, and `value_is_the_name` for why the plain
            # containment test this narrows is refused.
            return
        if SecretNames.value_is_the_name(name, decoded):
            # An enum member, a feature flag, a storage key: the value is the name
            # written the way the wire spells it. See `value_is_the_name`.
            return
        if SecretDetector._is_example_line(unit.content, match.start(1)):
            return
        if SecretValues.is_inside_example_literal(raw, match.start(1), unit.language):
            # A Go raw string the author named as example or help text. See
            # `is_inside_example_literal`.
            return
        if self._is_commented(unit, match.start(1)):
            return
        spec = SecretDetector._assignment_pattern(match, name, raw, value)
        yield self._finding(spec, unit, ctx, match.start(1), match.end(), value)

    @staticmethod
    def _assignment_pattern(
        match: re.Match[bytes], name: str, raw: bytes, value: bytes
    ) -> SecretPattern:
        """The pattern an assigned credential is reported under: its provider's when the value has a provider's shape, else a generic assignment's, graded by the name it is assigned to."""
        # The name's own offset, not the match's. The pattern opens with
        # `(?:^|[^\w.])`, which on every line but the first consumes the
        # newline that ended the line before -- so `match.start()` sits on
        # the previous line and every finding from this rule pointed one
        # line above the credential.
        return SecretPattern(
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
        caveat = SecretDetector._caveat(
            caveat, documentation, extractor, fixture, generated, rule_material
        )

        return self._scored(
            caveat, confidence, content, ctx, end, line, note, raw, severity, spec, start, unit
        )

    @staticmethod
    def _caveat(
        caveat: str,
        documentation: bool,
        extractor: bool,
        fixture: bool,
        generated: bool,
        rule_material: bool,
    ) -> str:
        """What the message adds about where the credential sits: rule material, a fixture, documentation, generated output or an extractor's own pattern."""
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
        return caveat

    def _scored(
        self,
        caveat: str,
        confidence: Confidence,
        content: FileContent,
        ctx: ScanContext,
        end: int,
        line: int,
        note: str,
        raw: bytes,
        severity: Severity,
        spec: SecretPattern,
        start: int,
        unit: FileUnit,
    ) -> Finding:
        """The secret finding, scored: its value never in the evidence, only a hash and the masked shape, and the rotation advice."""
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
    "LONE_KEY_ID_NOTE",
    "MINIFIED_LINE",
    "MIN_ASSIGNMENT_ENTROPY",
    "SecretDetector",
]
