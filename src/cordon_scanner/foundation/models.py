"""Core domain model.

This module is the centre of the architecture and it deliberately depends on
nothing. It imports no Cordon module, performs no I/O, and knows nothing about
detectors, rules, reporters or ecosystems. Everything else in the system depends
inward on these types; nothing here depends outward.

That direction is what makes the rest of the design possible. SARIF rendering,
policy gates, suppression, deduplication, baselines, pull-request comments and
risk scoring are each a pure function of the types defined here, which means each
can be developed, tested and replaced independently, and two of them can never
disagree about what a scan found.

Invariants that hold for every type in this module:

* **Immutable.** Frozen and slotted. A caller cannot mutate a result and
  re-serialise it as though a scan produced it. This also makes every value
  hashable and safe to pass between worker processes.
* **Content-free by default.** A finding carries redacted evidence, never raw
  source. See :class:`RedactionMode`.
* **Deterministic.** No timestamps, no object identity, no reliance on dict
  ordering in anything that reaches serialised output. Identical inputs must
  produce byte-identical results, because baselines, incremental caching and
  reproducible CI gates all depend on it.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.renames import Renamed
from cordon_scanner.foundation.taxonomy import AttackCategory, Taxonomy, ThreatDomain

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Category(enum.StrEnum):
    """The kind of claim a finding makes.

    Separating these is what keeps the tool usable. A published CVE in a test-only
    dependency, an obfuscated blob appended to a build config, and an unpinned
    version range are three different problems with three different owners and
    three different urgencies. A scanner that reports them through one channel
    gets a blanket exception added to it, and then it is protecting nothing.

    ``OPERATIONAL`` is not decoration. A scan that timed out, or skipped files it
    could not read, is neither clean nor compromised, and it must be able to say
    so. Without this category a degraded scan has only two options, both wrong:
    report success (a false negative that looks like a pass) or fail the build
    (which trains people to ignore the tool when a runtime is briefly missing).
    """

    MALICIOUS = "malicious"
    """Evidence of intent to harm. Known-bad package, credential exfiltration in
    an install hook, command-and-control protocol."""

    SUSPICIOUS = "suspicious"
    """A capability with no legitimate explanation in this context. Obfuscation,
    decode-then-execute, credential access combined with network egress."""

    VULNERABLE = "vulnerable"
    """A known weakness in something depended upon. CVE, GHSA, OSV."""

    POLICY = "policy"
    """An organisational rule rather than a security property. Missing lockfile,
    unpinned dependency, expired suppression."""

    OPERATIONAL = "operational"
    """The scan itself was degraded. Limit reached, parser failed, optional
    capability unavailable. Always reported, never silent."""


class Severity(enum.IntEnum):
    """Impact if the finding is real.

    Deliberately independent of :class:`Confidence`. Fusing the two into a single
    "priority" is the most common modelling error in this space, and it makes a
    rule set unshippable: a dynamic-execution call is high impact and only
    moderately indicative on its own, so a single axis forces the author to
    choose between never firing and firing constantly. Two axes let the same rule
    be reported loudly in an application and quietly in a bundler, without being
    rewritten.

    ``IntEnum`` so that thresholds are ordinary comparisons and the sort order is
    the obvious one.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from None

    def demote(self) -> Severity:
        """One step down, and never below `INFO`.

        For the case where a rule's shape is present and the control it asks for is
        present too: a verified download is still a download, so the finding stays in
        the report and stops failing a build. Clamped rather than wrapped, because
        `Severity(INFO - 1)` raises and a report is not the place to find that out.
        """
        return Severity(max(Severity.INFO, self.value - 1))

    def __str__(self) -> str:
        return self.name.lower()


class Confidence(enum.IntEnum):
    """Probability that the finding is real.

    ``HIGH`` carries a specific, enforced meaning: the rule was evaluated against
    the benign corpus and matched nothing. A rule with a non-zero baseline cannot
    declare it, and the rule loader refuses the pack if one tries. This turns
    false-positive control from a review-time judgement into a load-time
    invariant.

    ``CONFIRMED`` is reserved for cryptographic identity: a known-bad artefact
    hash, or an exact package-and-version match against the threat-intelligence
    database. No heuristic ever reaches it.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CONFIRMED = 3

    @classmethod
    def parse(cls, value: str | int | Confidence) -> Confidence:
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(c.name.lower() for c in cls)
            raise ValueError(f"unknown confidence {value!r}; expected one of: {valid}") from None

    def __str__(self) -> str:
        return self.name.lower()


class RedactionMode(enum.StrEnum):
    """How much of a matched value may appear in output.

    A scanner reports into CI logs, pull-request comments and SARIF files that
    are frequently uploaded to third-party platforms. All three are more durable
    and more widely readable than the repository itself.

    The failure this prevents is specific: a rule fires *because* a line contains
    a credential, and the tool then copies that line into every one of those
    destinations. The tool that finds a leaked secret must not be the tool that
    spreads it.
    """

    NONE = "none"
    """Raw matched text. Requires an explicit flag and is refused outright for
    secret-category rules."""

    MASKED = "masked"
    """Structure preserved, high-entropy runs masked. The default."""

    HASH_ONLY = "hash_only"
    """No snippet at all, only the match hash. Mandatory for secret rules."""


class EvidenceKind(enum.StrEnum):
    SNIPPET = "snippet"
    HASH = "hash"
    METADATA = "metadata"
    GRAPH = "graph"


class Scope(enum.StrEnum):
    """Dependency scope. Drives the ``dev_only`` risk factor."""

    RUNTIME = "runtime"
    DEV = "dev"
    BUILD = "build"
    OPTIONAL = "optional"
    PEER = "peer"
    TEST = "test"
    TOOL = "tool"
    """A tool the build runs (Go `tool` directives, a Gradle or Maven plugin, a Cargo or
    Terraform provider), not code linked into the product."""
    PLATFORM = "platform"
    """A requirement on the platform itself (`php`, `ext-json`, an SDK, a compiler), not a
    package anyone downloads."""
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Location and evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding is.

    Carries a line and column pair for humans and SARIF regions, and a byte span
    for exact evidence extraction. Both are needed: line numbers are what a
    developer navigates by, byte offsets are what survive a re-render.

    ``symbol`` is populated only when an abstract syntax tree is available. It is
    what allows a finding's identity to survive a function being moved within a
    file.
    """

    path: str
    """Repository-relative, forward-slashed, normalised. Never absolute, so that
    results are comparable across machines and safe to publish."""

    line: int | None = None
    """1-indexed."""

    column: int | None = None
    """1-indexed."""

    end_line: int | None = None
    end_column: int | None = None

    byte_start: int | None = None
    byte_end: int | None = None

    symbol: str | None = None
    """Enclosing function or class, when known."""

    project: str | None = None
    """Which project within a monorepo this path belongs to."""

    package: str | None = None
    """Package URL, when the finding concerns a dependency rather than a file."""

    def __str__(self) -> str:
        base = self.package or self.path
        if self.line is None:
            return base
        if self.column is None:
            return f"{base}:{self.line}"
        return f"{base}:{self.line}:{self.column}"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        for name in (
            "line",
            "column",
            "end_line",
            "end_column",
            "byte_start",
            "byte_end",
            "symbol",
            "project",
            "package",
        ):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out


@dataclass(frozen=True, slots=True)
class Evidence:
    """What was matched, in a form that is safe to transport.

    ``match_hash`` is always present and is the SHA-256 of the raw matched bytes.
    It is what makes two scans comparable and what lets a responder confirm that
    today's finding is the same artefact as last week's, without the tool ever
    moving the value itself. Under ``HASH_ONLY`` it is the only thing emitted,
    and it is still sufficient for correlation.
    """

    kind: EvidenceKind
    match_hash: str
    redaction: RedactionMode
    snippet: str | None = None
    span: tuple[int, int] | None = None
    metadata: tuple[tuple[str, str], ...] = ()
    """Sorted key/value pairs. A tuple rather than a mapping so the value stays
    hashable and its serialisation order is fixed."""

    @staticmethod
    def hash_bytes(raw: bytes) -> str:
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    @staticmethod
    def secret_hash(raw: bytes) -> str:
        """A credential's evidence hash, keyed per install so a published hash cannot be checked
        against guesses. See `core.evidence_key`."""
        from cordon_scanner.foundation.evidence_key import EvidenceKey

        return EvidenceKey.digest(raw)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": str(self.kind),
            "match_hash": self.match_hash,
            "redaction": str(self.redaction),
        }
        if self.snippet is not None:
            out["snippet"] = self.snippet
        if self.span is not None:
            out["span"] = list(self.span)
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One term in a risk score, carrying the reason it applied.

    Every factor explains itself. A score a user cannot reconstruct by hand is a
    score they will not trust, and a score they do not trust is one they will
    configure away. The explanation is therefore part of the value, not
    presentation logic that a different reporter might omit.
    """

    name: str
    points: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": self.points, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A deterministic, explainable score from 0 to 100.

    Not a model, and deliberately so. It is a declared sum of integer factors
    over a severity base scaled by a confidence weight, then clamped. Integer
    arithmetic throughout, because a float accumulated in traversal order is not
    reproducible across parallel workers, and reproducibility is what makes
    baselines and cache reuse safe.
    """

    value: int
    base: int
    confidence_multiplier: float
    factors: tuple[RiskFactor, ...] = ()

    def explain(self) -> Iterator[str]:
        """Yield the derivation, line by line, in the order it was computed."""
        scaled = int(self.base * self.confidence_multiplier)
        yield f"base {self.base} x {self.confidence_multiplier:.2f} confidence = {scaled}"
        for factor in self.factors:
            sign = "+" if factor.points >= 0 else ""
            yield f"{factor.name} {sign}{factor.points} ({factor.reason})"
        yield f"total (clamped 0-100) = {self.value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "base": self.base,
            "confidence_multiplier": self.confidence_multiplier,
            "factors": [f.to_dict() for f in self.factors],
        }


@dataclass(frozen=True, slots=True)
class Explanation:
    """Why this finding exists, in the reviewer's terms.

    Separate from ``message`` because they answer different questions. The
    message states what is wrong; the explanation states what the scanner
    observed and what it inferred from it. The second is what somebody triaging a
    suspected false positive actually needs, and burying it in prose makes it
    unavailable to any consumer that is not a human reading a terminal.
    """

    summary: str
    matched_rule: str
    contributing: tuple[str, ...] = ()
    """Fingerprints of the findings that fed a composite rule."""
    escalations: tuple[str, ...] = ()
    """Context-driven escalations, such as execution during install."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"summary": self.summary, "matched_rule": self.matched_rule}
        if self.contributing:
            out["contributing"] = list(self.contributing)
        if self.escalations:
            out["escalations"] = list(self.escalations)
        return out


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Suppression:
    """A recorded, expiring decision to accept a specific finding.

    The shape is chosen carefully. A suppression names **a rule and a path
    together**, never one alone. A rule-only suppression disables a detection
    everywhere, including in the file where it would have mattered. A path-only
    suppression -- the familiar directory exclusion -- exempts that location from
    every rule, and vendored or generated directories are precisely where a
    payload prefers to sit. The pair exempts one known-good combination and
    leaves everything else about that file still covered.

    ``justification``, ``approved_by`` and ``expires`` exist because a
    suppression is a security decision, and a security decision with no author,
    no reason and no end date outlives everyone who understood it. Expiry forces
    the question to be asked again while somebody still remembers the answer.
    """

    rule: str
    path: str
    justification: str
    expires: str
    """ISO date, required. An expired suppression stops suppressing and emits a
    POLICY finding, so it fails loudly rather than persisting unnoticed."""
    approved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "rule": self.rule,
            "path": self.path,
            "justification": self.justification,
            "expires": self.expires,
        }
        if self.approved_by:
            out["approved_by"] = self.approved_by
        return out


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single claim made by a detector. The unit of everything downstream."""

    FILE_HASH_KEY: ClassVar[str] = "file_sha256"
    """Metadata key holding the hash of the file a finding came from.

    Recorded so that two findings can be told apart by the bytes they came out of
    rather than by the bytes they matched. `ResultFolding.repeats` is the only
    reader, and the distinction matters: every 2048-bit RSA key begins with the same
    twelve characters, so the matched value cannot tell one committed key from
    another."""

    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    message: str
    location: Location
    evidence: Evidence
    remediation: str
    explanation: Explanation
    risk: RiskScore
    detector: str
    rule_version: str = "0.0.0"
    rulepack: str = "cordon-builtin"
    references: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    occurrences: int = 1
    suppressed: Suppression | None = None
    capabilities: tuple[Capability, ...] = ()

    threat_domain: ThreatDomain | None = None
    """Where in the supply chain this finding lives.

    Derived from the rule id when not supplied, so no detector can emit an
    unclassified finding by forgetting an argument. See `core/taxonomy.py` for
    why that derivation is the default rather than a per-call-site field."""

    attack_category: AttackCategory | None = None
    """What is being attempted. Derived the same way, and kept separate from
    the domain because typosquatting and dependency confusion share a domain
    and are different attacks."""

    always_report: bool = False
    """Whether a reporting threshold may hide this finding.

    True only for findings that describe the scan rather than the code: a
    detector that failed, a file that could not be read, a configuration that
    excluded everything. Hiding one of those behind a severity threshold turns
    "we did not look" into "we looked and found nothing", which is the single
    failure this project exists to prevent -- and it would be reachable by one
    line in a configuration file that the scan target itself supplies.

    A field rather than a rule-id prefix so it survives a rule being renamed,
    and so a reporter or a filter cannot get the test subtly wrong.
    """

    degrades_coverage: bool = False
    """Whether producing this finding means the scan examined less than it should.

    Set by a detector that reached a limit of its own -- a query ceiling, a time
    budget, an unreachable service -- and read by the engine, which clears
    `ScanResult.complete`. The engine can see that a file was unreadable or that
    a walk was cut short, and it cannot see that a detector asked about two
    hundred of two hundred and fifty dependencies and gave up on the rest.

    Without this the registry detector reported that packages had gone unchecked
    while the result still said `complete: true`, so `--fail-on-incomplete`
    passed a scan whose entire network layer had failed.
    """

    fingerprint: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        # Derived rather than supplied, so it can never disagree with the finding
        # it identifies. object.__setattr__ is the standard escape hatch for
        # computed fields on a frozen dataclass.
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())
        if self.threat_domain is None:
            object.__setattr__(self, "threat_domain", Taxonomy.domain_of(self.rule_id))
        if self.attack_category is None:
            object.__setattr__(self, "attack_category", Taxonomy.category_of(self.rule_id))

    def compute_fingerprint(self) -> str:
        """A stable identity that survives reformatting and code movement.

        Four separate features depend on this field: deduplication, baseline
        comparison, suppression matching, and SARIF ``partialFingerprints``,
        which is what stops a code-scanning platform raising a fresh alert for
        every existing finding each time a file is reformatted.

        Line and column are deliberately excluded. Including position is the
        common mistake, and it is fatal to adoption: adding an import at the top
        of a file shifts every line below it, every alert in that file re-fires
        as new, and people learn to dismiss the tool in bulk.

        The inputs are the rule, the path, the enclosing symbol when known, and
        the matched text with whitespace runs collapsed. Identifiers are
        preserved, because a renamed variable genuinely is a different match.
        """
        normalized_match = ""
        if self.rule_id.startswith("SECRET."):
            # Not the value, in any form. A fingerprint is published (SARIF partialFingerprints,
            # baselines, uploads) and rule, path and symbol are known to anyone who can read the
            # report, so a fingerprint over the value's hash is a guessing oracle for the value.
            # Two credentials of one kind in one file share a fingerprint and are reported once,
            # with the occurrence count.
            normalized_match = ""
        elif self.evidence.snippet:
            normalized_match = _WHITESPACE.sub(" ", self.evidence.snippet).strip()
        elif self.evidence.match_hash:
            normalized_match = self.evidence.match_hash

        parts = (
            Renamed.first(self.rule_id),  # a renamed rule keeps the fingerprints it had
            self.location.package or self.location.path,
            self.location.symbol or "",
            normalized_match,
        )
        digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
        return digest[:16]

    @property
    def is_suppressed(self) -> bool:
        return self.suppressed is not None

    def with_suppression(self, suppression: Suppression) -> Finding:
        """Return a suppressed copy.

        Suppressed findings are marked, never dropped. They remain in the JSON
        and SARIF output because an auditor's first question is what the tool was
        told to ignore, and that must be answerable from a report alone rather
        than by reading every repository's configuration.
        """
        return replace(self, suppressed=suppression)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "category": str(self.category),
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "message": self.message,
            "location": self.location.to_dict(),
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "explanation": self.explanation.to_dict(),
            "risk": self.risk.to_dict(),
            "fingerprint": self.fingerprint,
            "detector": self.detector,
            "rule_version": self.rule_version,
            "rulepack": self.rulepack,
            # Always emitted, never conditionally. A consumer filtering by
            # threat class must be able to rely on the field being present:
            # an absent key and an unclassified finding are indistinguishable
            # to a filter, and one of them is a hole.
            "threat_domain": str(self.threat_domain.value if self.threat_domain else "unspecified"),
            "attack_category": str(
                self.attack_category.value if self.attack_category else "unspecified"
            ),
        }
        if self.references:
            out["references"] = list(self.references)
        if self.related:
            out["related"] = list(self.related)
        if self.capabilities:
            out["capabilities"] = [str(c) for c in self.capabilities]
        if self.occurrences != 1:
            out["occurrences"] = self.occurrences
        if self.suppressed is not None:
            out["suppressed"] = self.suppressed.to_dict()
        if self.always_report:
            out["always_report"] = True
        return out

    def sort_key(self) -> tuple[Any, ...]:
        """Total ordering for deterministic output.

        Severity descending, then risk descending, then path, line, rule and
        fingerprint ascending. Never completion order, which varies with worker
        scheduling and would make output non-reproducible.
        """
        return (
            -int(self.severity),
            -self.risk.value,
            self.location.path,
            self.location.line or 0,
            self.rule_id,
            self.fingerprint,
        )

    # ---------------------------------------------------------------------------
    # Rules
    # ---------------------------------------------------------------------------

    def with_file_hash(self, sha256: str) -> Finding:
        """A copy of this finding recording the hash of the file it came from.

        Applied once per file by whichever scan path produced the finding -- the serial
        one in the engine and the worker in `ParallelScanner`, which is why it lives
        here rather than in either. A finding about the repository or about a dependency
        has no file and is returned unchanged.
        """
        if any(key == Finding.FILE_HASH_KEY for key, _ in self.evidence.metadata):
            return self
        return replace(
            self,
            evidence=replace(
                self.evidence,
                metadata=(*self.evidence.metadata, (Finding.FILE_HASH_KEY, sha256)),
            ),
        )


# ---------------------------------------------------------------------------
# Repository inventory
# ---------------------------------------------------------------------------


CONSUMER_TIME_HOOKS = frozenset({"preinstall", "install", "postinstall"})
"""Lifecycle names a package manager runs when the package is installed AS A DEPENDENCY.

These run on every machine that ever installs the package, transitively, as the user,
with no review in between. `postinstall` is the npm attack shape."""

AUTHOR_TIME_HOOKS = frozenset(
    {
        "prepare",
        "prepublish",
        "prepack",
        "prepublishonly",
        "postpack",
        "postpublish",
        "dependencies",
    }
)
"""Lifecycle names that run on the AUTHOR's machine rather than on a consumer's.

npm has documented the difference since version 7. `prepare` runs on a local install in
the package's own directory and before `npm pack`; the publish hooks run only while
publishing. None of them fires for a package installed from a registry tarball, which is
how every transitive dependency arrives. `postpack` runs beside `prepack`, `postpublish` after a
publish, and `dependencies` when the author's own `node_modules` changes; graded as consumer
hooks, `postpack` scripts were what blocked two benign MCP servers (review 98).

Read in two places, and the second one took a further pass to find. The manifest detector
grades `SUSPECT.INSTALL.SCRIPT.001` by it; the engine excludes the SCRIPT THESE NAME from
`install_hook_paths`, because marking the target file install-time is what put
`MALWARE.ANTI_ANALYSIS.001` at critical on `n8n`'s three-line `scripts/prepare.mjs` --
the file the anti-analysis composite's own comment cites as the false positive it was
corrected for.

What this gives up is the git-dependency case: `prepare` does run for a dependency
installed from a git URL. That risk is reported by the rule that is actually about it --
`SUSPECT.DEPENDENCY.SOURCE.001`, a dependency from a non-registry source -- rather than
by treating every author-time script in every repository as install-time code."""

INSTALL_TIME_HOOKS = CONSUMER_TIME_HOOKS | AUTHOR_TIME_HOOKS
"""Every lifecycle name that runs without anybody asking for it."""


@dataclass(frozen=True, slots=True)
class Hook:
    """A path that executes during install, build, or a version-control action.

    First-class in the inventory because execution context is the largest single
    risk multiplier in the scoring model.

    The same capability pair means different things in different places. Reading
    an environment variable and making an HTTP request is what an application
    does all day. The identical pair inside a package's install hook is a
    credential harvester, because that code runs unprompted, as the developer,
    with the developer's full environment, before any test, review, container
    boundary or network policy has had a chance to apply.

    Identifying these paths up front is therefore not a convenience. It is what
    lets the same rule be quiet in application code and decisive where it counts.
    """

    kind: str
    """postinstall | preinstall | prepare | build | githook | ci | make | startup (a `.pth` file)"""
    path: str
    name: str
    command: str = ""
    ecosystem: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {"kind": self.kind, "path": self.path, "name": self.name}
        if self.command:
            out["command"] = self.command
        if self.ecosystem:
            out["ecosystem"] = self.ecosystem
        return out


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


__all__ = [
    "Category",
    "Confidence",
    "Evidence",
    "EvidenceKind",
    "Explanation",
    "Finding",
    "Hook",
    "Location",
    "RedactionMode",
    "RiskFactor",
    "RiskScore",
    "Scope",
    "Severity",
    "Suppression",
]
