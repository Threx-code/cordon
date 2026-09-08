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
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon.core.models import (
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
from cordon.core.redact import Redactor
from cordon.core.scoring import ScoringContext
from cordon.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A recognisable credential shape."""

    @staticmethod
    def _p(pattern: str) -> re.Pattern[bytes]:
        return re.compile(pattern.encode("utf-8"), re.MULTILINE)

    rule_id: str
    name: str
    pattern: re.Pattern[bytes]
    severity: Severity
    confidence: Confidence
    remediation: str
    prefilter: tuple[bytes, ...] = ()
    """Literals, one of which must be present for this pattern to match.

    Every provider credential has a fixed prefix -- that is what makes the
    format recognisable in the first place -- so the gate is exact rather than
    heuristic. Without it the detector ran every provider regex over every file,
    which profiling showed to be the single largest cost in a scan.
    """


ROTATE = (
    "Revoke this credential now, then rotate it. Removing it from the working "
    "tree is not enough: it remains in git history and in every clone, so it "
    "must be treated as public from the moment it was committed."
)

# Provider-specific shapes. These carry high confidence because the format is
# distinctive enough that a match is almost never a coincidence, and because a
# leaked provider credential is immediately usable by whoever finds it.
PROVIDER_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "SECRET.AWS.ACCESS_KEY.001",
        "AWS access key id",
        SecretPattern._p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"AKIA", b"ASIA", b"ABIA", b"ACCA"),
    ),
    SecretPattern(
        "SECRET.GITHUB.TOKEN.001",
        "GitHub token",
        SecretPattern._p(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
    ),
    SecretPattern(
        "SECRET.SLACK.TOKEN.001",
        "Slack token",
        SecretPattern._p(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"xox",),
    ),
    SecretPattern(
        "SECRET.STRIPE.KEY.001",
        "Stripe secret key",
        SecretPattern._p(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"),
    ),
    SecretPattern(
        "SECRET.GOOGLE.API_KEY.001",
        "Google API key",
        SecretPattern._p(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"AIza",),
    ),
    SecretPattern(
        "SECRET.NPM.TOKEN.001",
        "npm access token",
        SecretPattern._p(r"\bnpm_[A-Za-z0-9]{36}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Revoke the token immediately. An npm publish token turns one leak into "
        "poisoned releases of every package the account maintains.",
        (b"npm_",),
    ),
    SecretPattern(
        "SECRET.PYPI.TOKEN.001",
        "PyPI API token",
        SecretPattern._p(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Revoke the token immediately. A PyPI token turns one leak into poisoned "
        "releases of every project the account maintains.",
        (b"pypi-AgEIcHlwaS5vcmc",),
    ),
    SecretPattern(
        "SECRET.PRIVATE_KEY.001",
        "Private key block",
        SecretPattern._p(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Treat the key as compromised. Generate a replacement, distribute it, "
        "and revoke the old one before removing it from the tree.",
        (b"PRIVATE KEY-----",),
    ),
    SecretPattern(
        "SECRET.JWT.001",
        "JSON Web Token",
        SecretPattern._p(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "If this token is live, revoke it. A committed JWT is often an expired "
        "example, which is why this is reported at medium confidence.",
        (b"eyJ",),
    ),
    SecretPattern(
        "SECRET.SLACK.WEBHOOK.001",
        "Slack webhook URL",
        SecretPattern._p(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}"),
        Severity.MEDIUM,
        Confidence.HIGH,
        "Delete the webhook in Slack. Anyone holding the URL can post as it.",
        (b"hooks.slack.com/services/",),
    ),
)

# A credential-shaped assignment. Much weaker on its own, so it is gated on
# entropy: `password = "changeme"` in an example is not a leak, and reporting it
# is how a secret detector earns a blanket exception.
ASSIGNMENT = SecretPattern._p(
    r"""(?ix)
    (?:^|[^\w.])
    (                                     # 1: the whole variable name
      (?:[a-z_][a-z0-9_\-]{0,40}?)?
      (?:pass(?:wo?rd)?|secret|token|api[_\-]?key|auth[_\-]?token|
         access[_\-]?key|private[_\-]?key|client[_\-]?secret|credential)
      [a-z0-9_\-]{0,30}
    )
    \s*[:=]\s*
    (?:
        ["']([^"'\s]{12,120})["']         # 2: quoted
      | ([^\s"'#,;()}\[\]=<>]{12,120})    # 3: unquoted
        (?=\s*(?:\#|$))                    #    ...and only to end of line
    )
    """
)
"""A credential-shaped name assigned a value, quoted or not.

The unquoted alternative is the whole point. The pattern required quotes, and
nothing in a `.env` file, a plain YAML file, a `.properties` file, a Makefile or
a connection string is quoted -- so `.env`, the single highest-yield location for
a committed credential, produced nothing at all.

The unquoted branch must reach the end of the line. Without that anchor it
matched code: `API_KEY = os.environ.get("API_KEY", "your-api-key-here")` gave
the "value" `os.environ.get(`, which has the entropy and character mix of a
credential and is a function call. A config assignment ends at the line; a call
does not.

The name is matched as a whole identifier that *contains* a credential word,
rather than as a word boundary before one. `\bsecret` cannot match inside
`API_SECRET`, because the character before it is an underscore and `\b` needs a
non-word character -- so the two most common environment-variable spellings,
`API_SECRET` and `AWS_SECRET_ACCESS_KEY`, matched nothing."""

CONNECTION_STRING = SecretPattern._p(
    r"""(?ix)
    \b[a-z][a-z0-9+.\-]{1,30}://
    [^\s:@/]{1,64} : ([^\s:@/]{6,120}) @
    """
)
"""A password embedded in a URL's userinfo.

A database URL that carries userinfo -- a user name and a password, separated by
a colon, before the host -- holds a live credential in a form no assignment
pattern sees, and that is the conventional way such URLs are written.

Described rather than shown. This project scans itself, and a complete example
here would be a true positive: the tool should not need an exception for its own
source."""

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

MIN_CHARACTER_CLASSES = 2
"""How many of {lower, upper, digit, symbol} a value must use.

Generated key material almost always mixes at least two. A dictionary word or a
repeated filler string uses one, and those are what the entropy floor was
carrying alone."""

# Values that look like secrets and are not. Matched by literal value, never by
# path, because a path exemption would also hide a real credential that happened
# to land in the same file.
PLACEHOLDER = re.compile(
    rb"(?i)(example|sample|dummy|placeholder|redacted|your[_\-]?|"
    rb"changeme|xxxx|test[_\-]?only|fake|not[_\-]?a[_\-]?real|\.\.\.|"
    # Any brace interpolation, not just `{{` and `${`. An f-string such as
    # `f"https://x:{TOKEN}@host"` is a template, and the braces say so; the
    # value that ends up there at runtime is not in this file.
    rb"<[^>]{3,}>|\{[^}]{0,64}\}|\$\{)"
)


NOT_A_SECRET = re.compile(
    rb"""(?x)
    ^(?:
        [A-Za-z_][\w.]*:[A-Za-z_][\w.]*      # module:attribute, an entry point
      | [A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*){2,}  # a dotted module path
      | [0-9a-f]{32,}                        # a hex digest
      | [A-Za-z_-]+(?:/[A-Za-z_.-]+)+        # a path
    )$
    """
)
"""Values with a credential-shaped *name* that are plainly not credentials.

Matched by shape, not by path. `secrets = "cordon.detect.secrets:SecretDetector"`
in this project's own `pyproject.toml` has a name containing `secret`, a quoted
value of 36 characters, high entropy and three character classes -- everything
the generic assignment rule looks for, and it is an entry-point declaration.

Kept narrow and anchored: each alternative must match the whole value, so a
credential that merely contains a dot is unaffected."""


class SecretDetector(BaseDetector):
    """Finds committed credentials."""

    id = "secrets"
    version = "0.2.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        findings: list[Finding] = []
        seen: set[str] = set()

        raw = content.raw

        for spec in PROVIDER_PATTERNS:
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
                if PLACEHOLDER.search(matched):
                    continue
                digest = Evidence.hash_bytes(matched)
                if digest in seen:
                    continue
                seen.add(digest)
                findings.append(self._finding(spec, unit, ctx, match.start(), match.end(), matched))

        findings.extend(self._assignment_findings(unit, ctx, seen))
        findings.extend(self._connection_findings(unit, ctx, seen))
        return findings

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
                remediation=spec.remediation,
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
                remediation=ROTATE,
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
                remediation=ROTATE,
            )
        )
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
            if PLACEHOLDER.search(value):
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
        for match in ASSIGNMENT.finditer(raw):
            # Group 1 is the name; 2 the quoted value, 3 the unquoted one.
            value = match.group(2) or match.group(3)
            if not value or PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue

            decoded = value.decode("utf-8", errors="replace")
            if Redactor.shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
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

            name = match.group(1).decode("utf-8", errors="replace")
            spec = SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name=f"credential assigned to {name!r}",
                pattern=ASSIGNMENT,
                severity=Severity.HIGH,
                # Medium, not high: a high-entropy string assigned to something
                # named `token` is usually a credential and is sometimes a hash,
                # an identifier or a fixture. The finding is worth a look and is
                # not worth failing a build on its own.
                confidence=Confidence.MEDIUM,
                remediation=ROTATE,
            )
            yield self._finding(spec, unit, ctx, match.start(), match.end(), value)

    def _finding(
        self,
        spec: SecretPattern,
        unit: FileUnit,
        ctx: ScanContext,
        start: int,
        end: int,
        raw: bytes,
    ) -> Finding:
        content = unit.content
        line = content.line_of(start)

        return Finding(
            rule_id=spec.rule_id,
            category=Category.SUSPICIOUS,
            severity=spec.severity,
            confidence=spec.confidence,
            message=(
                f"A {spec.name} appears in this file. Anything committed is in git "
                f"history and in every clone, so it must be treated as public from "
                f"the moment it landed, whether or not it is still in the working "
                f"tree."
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
                match_hash=Evidence.hash_bytes(raw),
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
                spec.severity,
                spec.confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    capabilities=frozenset(),
                ),
            ),
            detector=self.id,
        )


__all__ = ["MIN_ASSIGNMENT_ENTROPY", "PROVIDER_PATTERNS", "SecretDetector"]
