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
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.taxonomy import AttackCategory, ThreatDomain, category_of, domain_of

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


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
    UNKNOWN = "unknown"


class MatchKind(enum.StrEnum):
    """How a rule decides whether it applies. Selects the matching strategy."""

    LITERAL = "literal"
    REGEX = "regex"
    ENTROPY = "entropy"
    STRUCTURAL = "structural"
    AST = "ast"
    GRAPH = "graph"
    COMPOSITE = "composite"


class Capability(enum.StrEnum):
    """Portable behavioural primitives.

    This enum is the mechanism that makes the detection engine language-agnostic,
    and it is the single most important abstraction in the system.

    Signature-based detection does not generalise. A rule written against a
    specific campaign's indicators stops working the moment the campaign changes
    a string, and it never worked for any other language in the first place.

    Capability-based detection does generalise, because the primitives are forced
    by the objective rather than chosen by the attacker. To exfiltrate data, code
    must read something sensitive and send it somewhere. To run a second stage,
    it must decode a payload and execute it. Those requirements hold in every
    language, and there are only a handful of them.

    So each language plugin supplies patterns for these six names, and composite
    rules are written **once** against the names. Adding a language means adding
    pattern data, not rewriting the rule set: a new ecosystem inherits every
    behavioural rule the moment its primitives are defined.
    """

    DECODE = "decode"
    """Turns encoded data back into code or commands."""

    EXECUTE = "execute"
    """Evaluates code from a string or deserialises into executable objects."""

    SPAWN = "spawn"
    """Starts a process or invokes a shell."""

    CREDENTIAL = "credential"
    """Reads environment variables, key material, or cloud and registry tokens."""

    EGRESS = "egress"
    """Opens an outbound network connection."""

    PERSIST = "persist"
    """Installs itself somewhere that survives a reboot or a new shell."""

    DYNAMIC_DISPATCH = "dynamic_dispatch"
    """Reaches a function by a name computed at runtime.

    Emitted when reflective access -- `getattr`, `globals()[...]`,
    `__import__` -- is used with an argument that could not be resolved
    statically, into a namespace where that has no ordinary purpose.

    It exists so that evading the name match costs something. An attacker who
    writes `getattr(os, decode(blob))()` defeats every pattern that looks for
    `os.system`, and the shape they are forced into is itself the evidence:
    reflective dispatch on a computed name into `os` or `subprocess` has almost
    no benign analogue, while `getattr(self, method_name)` on a plugin object
    has plenty -- which is why the namespace is part of the condition.
    """

    FETCH_EXEC = "fetch_exec"
    """Network output flows directly into an interpreter.

    Distinct from `egress` plus `spawn`, and that distinction is the point.
    Those two co-occurring describe an enormous amount of ordinary operations
    code -- a deploy script that pushes and posts to Slack, a health check that
    runs `systemctl` and pings a status page -- because nothing in the pair
    requires the thing executed to be the thing fetched.

    A pipe does require it. `curl ... | sh` is not two capabilities that happen
    to share a file; it is one construct whose output is the other's input, and
    that is the actual dropper shape rather than a proxy for it.
    """

    ANTI_ANALYSIS = "anti_analysis"
    """Checks whether it is being observed, and can act on the answer.

    Sandbox and virtual-machine probes, debugger checks, CI or hostname gating,
    and long delays before doing anything. Individually each has a benign use:
    software legitimately behaves differently in CI, and a retry legitimately
    sleeps.

    What has no benign use is the combination with a payload. Code that asks
    "am I being watched?" and then decodes, spawns or reaches the network is
    describing its own evasion, and the check is the part that cannot be
    explained away -- an ordinary program has no reason to care.

    It is also the static counterpart to the residual a sandbox leaves. A
    payload that sleeps past an analysis window defeats dynamic observation and
    lights this up instead, so the two tiers cover each other's blind spot.
    """

    MINE = "mine"
    """Consumes compute for a cryptocurrency.

    Unlike the other primitives this is closer to a signature than a
    capability -- mining is identifiable by its pools, protocols and wallet
    formats rather than by a language operation. It is modelled as a capability
    anyway so that it composes with the rest: mining inside an install hook is
    a different finding from mining in an application, and the existing context
    machinery already knows how to say that.
    """


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

    fingerprint: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        # Derived rather than supplied, so it can never disagree with the finding
        # it identifies. object.__setattr__ is the standard escape hatch for
        # computed fields on a frozen dataclass.
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())
        if self.threat_domain is None:
            object.__setattr__(self, "threat_domain", domain_of(self.rule_id))
        if self.attack_category is None:
            object.__setattr__(self, "attack_category", category_of(self.rule_id))

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
        if self.evidence.snippet:
            normalized_match = _WHITESPACE.sub(" ", self.evidence.snippet).strip()
        elif self.evidence.match_hash:
            normalized_match = self.evidence.match_hash

        parts = (
            self.rule_id,
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


@dataclass(frozen=True, slots=True)
class RuleProvenance:
    """Where a rule came from, and how protected it is.

    Mandatory for ``category: malicious``.

    Rules derived from a real incident are qualitatively different from rules
    derived from reasoning: they are the only ones known to have matched
    something that actually arrived. They are also the easiest to lose, because
    they often look arbitrary out of context -- an opaque string constant with no
    obvious meaning is exactly what a well-intentioned cleanup deletes, and a
    refactor that reorganises a rule set can drop one while the diff appears to
    show nothing but an improvement.

    Marking provenance as ``incident`` makes such a rule structurally protected:
    ``cordon rules diff`` fails when one is removed or weakened without an
    explicit review trailer on the commit.
    """

    kind: str
    """incident | research | advisory | community | synthetic"""
    reference: str = ""
    note: str = ""

    @property
    def protected(self) -> bool:
        return self.kind == "incident"

    def to_dict(self) -> dict[str, Any]:
        out = {"kind": self.kind}
        if self.reference:
            out["reference"] = self.reference
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True, slots=True)
class RuleTests:
    """Samples proving a rule fires, and samples proving it does not overfire.

    Mandatory. A pack containing a rule without at least one positive and one
    negative case fails to load.

    This is not process ceremony. Detection rules fail silently by nature: a path
    filter that no longer matches, a pattern invalidated by a syntax change, an
    escaping error introduced during a refactor. The rule stops matching
    anything, the scan still exits successfully, and nothing anywhere reports a
    problem. The gate looks green precisely because the check is broken.

    Executable samples turn that silent failure into a load-time error.
    """

    positive: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    """A loaded, validated detection rule.

    Rules are data, not code. They are authored in YAML, versioned independently
    of the engine, signed as a pack, and reviewable by a security team without
    reading Python. That separation is what lets detection content ship on its
    own cadence and be approved by the people qualified to approve it.
    """

    id: str
    category: Category
    severity: Severity
    confidence: Confidence
    title: str
    message: str
    remediation: str
    match_kind: MatchKind
    version: str = "0.0.0"
    rulepack: str = "cordon-builtin"
    languages: tuple[str, ...] = ()
    ecosystems: tuple[str, ...] = ()
    paths_include: tuple[str, ...] = ()
    paths_exclude: tuple[str, ...] = ()
    evidence_policy: RedactionMode = RedactionMode.MASKED
    capability: Capability | None = None
    provenance: RuleProvenance | None = None
    tests: RuleTests = field(default_factory=RuleTests)
    references: tuple[str, ...] = ()
    enabled: bool = True
    baseline_hits: int = 0
    """Matches recorded against the benign corpus. A rule with a non-zero
    baseline may not declare ``confidence: high``; the loader enforces it."""

    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)
    """The rule's source mapping, retained for pattern compilation and for
    ``cordon rules show``."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "version": self.version,
            "rulepack": self.rulepack,
            "category": str(self.category),
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "title": self.title,
            "message": self.message,
            "remediation": self.remediation,
            "match_kind": str(self.match_kind),
        }
        if self.languages:
            out["languages"] = list(self.languages)
        if self.ecosystems:
            out["ecosystems"] = list(self.ecosystems)
        if self.capability:
            out["capability"] = str(self.capability)
        if self.provenance:
            out["provenance"] = self.provenance.to_dict()
        if self.references:
            out["references"] = list(self.references)
        return out


# ---------------------------------------------------------------------------
# Repository inventory
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LanguageStat:
    language: str
    files: int
    bytes: int
    share: float
    evidence: tuple[str, ...] = ()
    """What led to this conclusion. Inventory that cannot explain itself cannot
    be debugged when it is wrong."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "files": self.files,
            "bytes": self.bytes,
            "share": round(self.share, 4),
            "evidence": list(self.evidence),
        }


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
    """postinstall | preinstall | prepare | build | githook | ci | make"""
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


@dataclass(frozen=True, slots=True)
class Project:
    """A subtree with its own manifest.

    A monorepo is N projects, not one repository with a mixed file list. Modelling
    it that way is what makes detector selection correct: a Python service and a
    TypeScript front end in the same tree get different detectors, different
    ecosystem parsers and different language rules, scoped to their own subtree.

    Without this, a polyglot repository gets the union of every rule applied to
    every file, which produces both false positives (JavaScript rules firing on
    Python strings) and false negatives (a rule disabled because it was noisy
    somewhere unrelated).
    """

    path: str
    ecosystem: str | None = None
    manifests: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    framework: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        for key in ("name", "ecosystem", "framework"):
            value = getattr(self, key)
            if value:
                out[key] = value
        for key in ("manifests", "lockfiles", "languages"):
            value = getattr(self, key)
            if value:
                out[key] = list(value)
        return out


@dataclass(frozen=True, slots=True)
class Repository:
    """What the scan target actually is.

    Produced by the inventory phase and consumed by every detector's
    applicability check, which is what makes scanner selection automatic rather
    than configured. A user should not have to declare that their repository
    contains Terraform; the tool should observe it and act accordingly.
    """

    root: str
    """Absolute path to the scan target.

    Serialised as its basename. `Location.path` promises results are "safe to
    publish", and the absolute root is what makes them not: in CI it exposes
    runner directory layouts, internal project names and sometimes usernames,
    into artefacts routinely uploaded to third parties and attached to pull
    requests. The name of the thing scanned is the part that carries meaning
    across machines."""

    is_git: bool = False
    revision: str | None = None
    remote: str | None = None
    branch: str | None = None
    languages: tuple[LanguageStat, ...] = ()
    projects: tuple[Project, ...] = ()
    ecosystems: tuple[str, ...] = ()
    ci_systems: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    containers: tuple[str, ...] = ()
    iac: tuple[str, ...] = ()
    hooks: tuple[Hook, ...] = ()
    file_count: int = 0
    total_bytes: int = 0

    @property
    def public_root(self) -> str:
        """The scan target's name, without the path that led to it."""
        cleaned = self.root.replace("\\", "/").rstrip("/")
        return cleaned.rpartition("/")[2] or cleaned or "."

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.public_root,
            "is_git": self.is_git,
            "revision": self.revision,
            "remote": self.remote,
            "branch": self.branch,
            "languages": [x.to_dict() for x in self.languages],
            "projects": [p.to_dict() for p in self.projects],
            "ecosystems": list(self.ecosystems),
            "ci_systems": list(self.ci_systems),
            "build_systems": list(self.build_systems),
            "containers": list(self.containers),
            "iac": list(self.iac),
            "hooks": [h.to_dict() for h in self.hooks],
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Dependency:
    """One node in the resolved dependency graph.

    Built by parsing the lockfile, never by invoking the package manager and
    never by resolving over the network. Running the ecosystem's own resolver to
    learn the graph would mean executing untrusted tooling against
    attacker-controlled metadata, inside the tool whose entire purpose is to
    avoid exactly that. It would also make results non-reproducible, since a
    resolver consults a live registry.

    ``integrity`` is the lockfile's own hash for the artefact. Comparing it
    against a baseline enables one of the highest-signal checks available: an
    integrity hash that changed while the version did not means the registry
    content was replaced under a name that had already been reviewed.
    """

    purl: str
    """Package URL. The cross-ecosystem identity, so findings, intelligence and
    advisories can be correlated without per-ecosystem special cases."""

    ecosystem: str
    name: str
    version: str | None = None
    direct: bool = False
    depth: int = 0
    scope: Scope = Scope.RUNTIME
    resolved_from: str | None = None
    integrity: str | None = None
    parents: tuple[str, ...] = ()
    declared_spec: str | None = None
    project: str | None = None

    repository: str | None = None
    """The source repository this package claims, as its manifest records it.

    Carried so it can be compared with what the registry says the artefact was
    built from. The two disagreeing is the shape of a package that points
    reviewers at code it was not built from: reading the linked repository
    proves nothing about what was published, and the link is the thing most
    people check."""

    declared_in: str | None = None
    """The lockfile that resolved this dependency.

    Findings about a dependency had `Location(path=dep.project or "")`, and for
    a single-project repository `project` is None -- so every typosquat,
    integrity and source finding carried an empty `artifactLocation.uri` in
    SARIF. GitHub code scanning cannot anchor an alert to an empty URI, so the
    whole dependency layer was invisible in the integration that is the
    product's main CI story."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "direct": self.direct,
            "depth": self.depth,
            "scope": str(self.scope),
        }
        for key in (
            "version",
            "resolved_from",
            "integrity",
            "declared_spec",
            "project",
            "declared_in",
        ):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.parents:
            out["parents"] = list(self.parents)
        return out


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    dependencies: int = 0
    rules_evaluated: int = 0
    duration_ms: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "dependencies": self.dependencies,
            "rules_evaluated": self.rules_evaluated,
            "duration_ms": self.duration_ms,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything a scan produced. The aggregate root of the domain.

    ``complete`` is the field a pipeline must be able to see. A scan that hit its
    timeout, or skipped files it could not read, is not a clean scan, and
    reporting it as one is a false negative dressed as a pass. Making
    completeness an explicit property with its own exit code lets a release
    pipeline demand a full scan while a pre-commit hook tolerates a partial one.

    ``rulepack_hash`` and ``config_hash`` make a result self-describing: months
    later it is still possible to say exactly which rules and which settings
    produced it, which is what auditability actually requires.
    """

    findings: tuple[Finding, ...] = ()
    repository: Repository | None = None
    dependencies: tuple[Dependency, ...] = ()
    stats: ScanStats = field(default_factory=ScanStats)
    complete: bool = True
    schema_version: int = 1
    engine_version: str = "0.0.0"
    rulepack_version: str = "0.0.0"
    rulepack_hash: str = ""
    config_hash: str = ""

    @property
    def active(self) -> tuple[Finding, ...]:
        """Findings that are not suppressed. What a policy gate evaluates."""
        return tuple(f for f in self.findings if not f.is_suppressed)

    @property
    def suppressed(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.is_suppressed)

    def by_severity(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.active:
            counts[finding.severity] += 1
        return counts

    def by_category(self) -> dict[Category, int]:
        counts = dict.fromkeys(Category, 0)
        for finding in self.active:
            counts[finding.category] += 1
        return counts

    def filter(
        self,
        *,
        min_severity: Severity | None = None,
        min_confidence: Confidence | None = None,
        categories: Sequence[Category] | None = None,
    ) -> ScanResult:
        selected = [
            f
            for f in self.findings
            if (min_severity is None or f.severity >= min_severity)
            and (min_confidence is None or f.confidence >= min_confidence)
            and (categories is None or f.category in categories)
        ]
        return replace(self, findings=tuple(selected))

    def sorted(self) -> ScanResult:
        return replace(self, findings=tuple(sorted(self.findings, key=Finding.sort_key)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "rulepack_version": self.rulepack_version,
            "rulepack_hash": self.rulepack_hash,
            "config_hash": self.config_hash,
            "complete": self.complete,
            "stats": self.stats.to_dict(),
            "repository": self.repository.to_dict() if self.repository else None,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "findings": [f.to_dict() for f in self.findings],
        }


__all__ = [
    "Capability",
    "Category",
    "Confidence",
    "Dependency",
    "Evidence",
    "EvidenceKind",
    "Explanation",
    "Finding",
    "Hook",
    "LanguageStat",
    "Location",
    "MatchKind",
    "Project",
    "RedactionMode",
    "Repository",
    "RiskFactor",
    "RiskScore",
    "Rule",
    "RuleProvenance",
    "RuleTests",
    "ScanResult",
    "ScanStats",
    "Scope",
    "Severity",
    "Suppression",
]
