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
from cordon.core.redact import shannon_entropy
from cordon.core.scoring import ScoringContext
from cordon.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A recognisable credential shape."""

    rule_id: str
    name: str
    pattern: re.Pattern[bytes]
    severity: Severity
    confidence: Confidence
    remediation: str


def _p(pattern: str) -> re.Pattern[bytes]:
    return re.compile(pattern.encode("utf-8"), re.MULTILINE)


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
        "SECRET.AWS.ACCESS_KEY.001", "AWS access key id",
        _p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL, Confidence.HIGH, ROTATE,
    ),
    SecretPattern(
        "SECRET.GITHUB.TOKEN.001", "GitHub token",
        _p(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
        Severity.CRITICAL, Confidence.HIGH, ROTATE,
    ),
    SecretPattern(
        "SECRET.SLACK.TOKEN.001", "Slack token",
        _p(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH, Confidence.HIGH, ROTATE,
    ),
    SecretPattern(
        "SECRET.STRIPE.KEY.001", "Stripe secret key",
        _p(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
        Severity.CRITICAL, Confidence.HIGH, ROTATE,
    ),
    SecretPattern(
        "SECRET.GOOGLE.API_KEY.001", "Google API key",
        _p(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.HIGH, Confidence.HIGH, ROTATE,
    ),
    SecretPattern(
        "SECRET.NPM.TOKEN.001", "npm access token",
        _p(r"\bnpm_[A-Za-z0-9]{36}\b"),
        Severity.CRITICAL, Confidence.HIGH,
        "Revoke the token immediately. An npm publish token turns one leak into "
        "poisoned releases of every package the account maintains.",
    ),
    SecretPattern(
        "SECRET.PYPI.TOKEN.001", "PyPI API token",
        _p(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
        Severity.CRITICAL, Confidence.HIGH,
        "Revoke the token immediately. A PyPI token turns one leak into poisoned "
        "releases of every project the account maintains.",
    ),
    SecretPattern(
        "SECRET.PRIVATE_KEY.001", "Private key block",
        _p(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"),
        Severity.CRITICAL, Confidence.HIGH,
        "Treat the key as compromised. Generate a replacement, distribute it, "
        "and revoke the old one before removing it from the tree.",
    ),
    SecretPattern(
        "SECRET.JWT.001", "JSON Web Token",
        _p(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        Severity.MEDIUM, Confidence.MEDIUM,
        "If this token is live, revoke it. A committed JWT is often an expired "
        "example, which is why this is reported at medium confidence.",
    ),
    SecretPattern(
        "SECRET.SLACK.WEBHOOK.001", "Slack webhook URL",
        _p(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}"),
        Severity.MEDIUM, Confidence.HIGH,
        "Delete the webhook in Slack. Anyone holding the URL can post as it.",
    ),
)

# A credential-shaped assignment. Much weaker on its own, so it is gated on
# entropy: `password = "changeme"` in an example is not a leak, and reporting it
# is how a secret detector earns a blanket exception.
ASSIGNMENT = _p(
    r"""(?ix)
    \b(pass(?:wo?rd)?|secret|token|api[_\-]?key|auth[_\-]?token|
       access[_\-]?key|private[_\-]?key|client[_\-]?secret)
    \s*[:=]\s*
    ["']([^"'\s]{12,120})["']
    """
)

MIN_ASSIGNMENT_ENTROPY = 3.2
"""Entropy floor for a credential-shaped assignment.

Below this the value is a word or a placeholder rather than a generated secret.
Set from the observation that real key material over a base64-ish alphabet sits
well above 3.5, while `changeme`, `your-password-here` and `xxxxxxxxxxxx` sit
below 3.
"""

# Values that look like secrets and are not. Matched by literal value, never by
# path, because a path exemption would also hide a real credential that happened
# to land in the same file.
PLACEHOLDER = re.compile(
    rb"(?i)(example|sample|dummy|placeholder|redacted|your[_\-]?|"
    rb"changeme|xxxx|test[_\-]?only|fake|not[_\-]?a[_\-]?real|\.\.\.|"
    rb"<[^>]{3,}>|\{\{|\$\{)"
)


class SecretDetector(BaseDetector):
    """Finds committed credentials."""

    id = "secrets"
    version = "0.1.0"
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

        for spec in PROVIDER_PATTERNS:
            for match in spec.pattern.finditer(content.raw):
                raw = match.group(0)
                if PLACEHOLDER.search(raw):
                    continue
                digest = Evidence.hash_bytes(raw)
                if digest in seen:
                    continue
                seen.add(digest)
                findings.append(
                    self._finding(spec, unit, ctx, match.start(), match.end(), raw)
                )

        findings.extend(self._assignment_findings(unit, ctx, seen))
        return findings

    def _assignment_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        for match in ASSIGNMENT.finditer(unit.content.raw):
            value = match.group(2)
            if PLACEHOLDER.search(value):
                continue

            decoded = value.decode("utf-8", errors="replace")
            if shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
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
            yield self._finding(
                spec, unit, ctx, match.start(), match.end(), value
            )

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
                escalations=(
                    "the value is withheld from this report; the hash identifies it",
                ),
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
