"""Layered configuration with an enforced ceiling.

This module implements constraint C3, and it is a security control rather than a
convenience layer.

The problem it solves: an attacker who can commit to a repository can also commit
that repository's scanner configuration. If a repository's own config file can
add an exclusion, disable a detector, lower a threshold or register a permanent
suppression, then the first thing any competent payload ships with is a
configuration change, and every control underneath it is decorative.

So configuration is layered, and the organisation layer is a **ceiling** rather
than a set of defaults:

    CLI flags  >  organisation policy  >  repository config  >  built-in defaults
                        ^ clamps everything below it

The repository layer can describe the repository -- where its vendored code
lives, which paths are generated -- and can make the scan *stricter*. It cannot
make it weaker. Where it tries, the conflict is named and the run fails with a
configuration error rather than being silently clamped: an owner who believes a
setting is in force when it is not is in a worse position than one whose build
failed, because a control that reads as protective while doing nothing also
stops anybody from looking for the real gap.

Parsing is strict. Unknown keys are errors, never warnings. A silently ignored
`sevrity_threshold` typo means the operator thinks a threshold is set when the
default is in force, which is the same failure in a different costume.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon.core.errors import ConfigError, PolicyViolationError
from cordon.core.limits import DEFAULT_LIMITS, Limits
from cordon.core.models import Category, Confidence, RedactionMode, Severity, Suppression

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

CONFIG_VERSION = 1

CONFIG_FILENAMES = (
    "cordon.yaml",
    "cordon.yml",
    ".cordon.yaml",
    ".cordon.yml",
)

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

MIN_JUSTIFICATION_CHARS = 40
"""A suppression's justification must be long enough to contain a reason.

Not arbitrary: the failure being prevented is `justification: "false positive"`,
which records that somebody decided, not what they decided or why. A reviewer
reading it two years later learns nothing, so the suppression is never revisited
and becomes permanent by default.
"""

MAX_SUPPRESSION_DAYS = 365
"""Ceiling on suppression lifetime, lowerable by organisation policy.

Expiry is what converts a suppression from a permanent hole into a scheduled
question. It forces the decision to be re-examined while somebody still
remembers the context that justified it.
"""


# ---------------------------------------------------------------------------
# Layer identity, for `cordon config explain`
# ---------------------------------------------------------------------------


class Layer:
    """Where a setting came from. Every effective value records its origin."""

    DEFAULT = "default"
    REPO = "repo"
    ORG = "org"
    CLI = "cli"

    ORDER = (DEFAULT, REPO, ORG, CLI)


@dataclass(frozen=True, slots=True)
class Provenance:
    """One setting's final value and the layer that supplied it.

    Auditability requires that "why is this threshold medium?" be answerable
    without re-deriving the merge by hand.
    """

    key: str
    value: Any
    layer: str
    source: str = ""

    def __str__(self) -> str:
        where = f" ({self.source})" if self.source else ""
        return f"{self.key} = {self.value!r}  [{self.layer}{where}]"


# ---------------------------------------------------------------------------
# Organisation policy: the ceiling
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OrgConstraints:
    """What a repository is not permitted to do.

    Each field answers one question: can the repository layer weaken this?
    Defaults are permissive, because an organisation that has not deployed a
    policy should not have Cordon refusing its repositories' configurations.
    Once a policy is supplied, it binds.
    """

    detectors_required: frozenset[str] = frozenset()
    """Detectors a repository may not disable."""

    min_severity_threshold: Severity | None = None
    """The repository may not report *less* than this. A repository setting a
    stricter (lower) threshold is fine and is not a conflict."""

    min_confidence_threshold: Confidence | None = None

    allow_network: bool = True
    allow_plugins: bool = False
    allow_extra_rule_packs: bool = True
    allow_limit_increase: bool = False
    """Whether a repository may raise a resource limit. Denied by default: a
    repository able to raise its own limits can raise them until the protection
    stops applying."""

    max_suppression_days: int = MAX_SUPPRESSION_DAYS
    require_justification: bool = True
    require_approver: bool = False
    forbid_path_only_suppressions: bool = True
    forbid_suppressing: frozenset[Category] = frozenset({Category.MALICIOUS})
    """Categories a repository-level config may never suppress. Malicious by
    default: a repository that can silence a malware finding about itself is not
    being scanned."""

    max_total_timeout: float | None = None

    @classmethod
    def permissive(cls) -> OrgConstraints:
        """The no-policy default. Still forbids suppressing malware."""
        return cls()


@dataclass(frozen=True, slots=True)
class Policy:
    """Failure policy: what turns findings into a non-zero exit.

    Separate from reporting thresholds on purpose. Teams routinely want to *see*
    medium findings while only *failing* on high ones, and collapsing the two
    forces them to choose between blindness and a blocked pipeline. The pipeline
    wins that argument every time, so the tool ends up reporting nothing.
    """

    fail_on_severity: Severity | None = Severity.HIGH
    fail_on_categories: frozenset[Category] = frozenset({Category.MALICIOUS})
    fail_on_incomplete: bool = False
    min_confidence_to_fail: Confidence = Confidence.MEDIUM
    """A low-confidence heuristic should surface for review, not stop a release.
    Without this floor, the noisiest rule in the pack sets the gate."""

    @classmethod
    def default(cls) -> Policy:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on_severity": str(self.fail_on_severity) if self.fail_on_severity else None,
            "fail_on_categories": sorted(str(c) for c in self.fail_on_categories),
            "fail_on_incomplete": self.fail_on_incomplete,
            "min_confidence_to_fail": str(self.min_confidence_to_fail),
        }


# ---------------------------------------------------------------------------
# Effective configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """The effective configuration for one scan.

    Immutable and hashable, so it can be fingerprinted into the cache key and
    passed to worker processes without defensive copying. ``config_hash`` is what
    makes a cached result sound: any configuration change invalidates every entry,
    because a stale cached "clean" is a false negative and false negatives are the
    failure that matters.
    """

    version: int = CONFIG_VERSION

    severity_threshold: Severity = Severity.LOW
    confidence_threshold: Confidence = Confidence.LOW

    detectors: Mapping[str, bool] = field(default_factory=dict)
    exclude: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    minified: tuple[str, ...] = ()

    limits: Limits = DEFAULT_LIMITS
    explicit_limits: frozenset[str] = frozenset()
    """Which limits this layer actually wrote down.

    Load-bearing for ceiling enforcement. A limit the author never wrote is an
    inherited default, not a belief they hold, so clamping it silently is
    correct and raising a conflict about it is noise. A limit they *did* write
    and that exceeds the ceiling is a real disagreement and is named.
    """
    policy: Policy = field(default_factory=Policy.default)
    suppressions: tuple[Suppression, ...] = ()

    evidence: RedactionMode = RedactionMode.MASKED
    offline: bool = True
    allow_plugins: bool = False
    rule_packs: tuple[str, ...] = ("cordon-builtin",)
    extra_rule_paths: tuple[str, ...] = ()

    profile: str = "balanced"
    cache_dir: str | None = None
    use_cache: bool = True

    constraints: OrgConstraints = field(default_factory=OrgConstraints.permissive)
    provenance: tuple[Provenance, ...] = field(default=(), compare=False)

    from_untrusted_source: bool = field(default=False, compare=False)
    """Whether these settings were read from inside the scan target.

    The scan target is untrusted input, and its configuration file is part of
    it. Without an organisation policy there is no ceiling, so a repository
    could previously raise its own resource limits without bound and load its own
    rule packs. Marking the origin lets those two specific powers be withheld by
    default, while leaving every setting a repository legitimately needs.
    """

    clamped_settings: tuple[str, ...] = field(default=(), compare=False)
    """Settings that were reduced because they came from an untrusted source.

    Recorded rather than applied silently: a repository owner who believes a
    limit is in force when it is not is in a worse position than one who was
    told. The engine reports each of these as a POLICY finding.
    """

    # -- Construction ----------------------------------------------------

    @classmethod
    def default(cls) -> Config:
        return cls()

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        source: str = "<dict>",
        layer: str = Layer.REPO,
    ) -> Config:
        """Parse a configuration mapping strictly.

        Raises :class:`ConfigError` on any unknown key, malformed value, or
        invalid suppression. Nothing is coerced silently.
        """
        return _parse_config(data, source=source, layer=layer)

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(
                f"configuration file not found: {p}",
                hint="Run `cordon config validate` after creating it, or omit --config.",
            )
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read {p}: {exc}") from exc
        data = _load_yaml_subset(raw, source=str(p))
        return cls.from_dict(data, source=str(p), layer=Layer.REPO)

    @classmethod
    def from_untrusted_file(cls, path: str | Path) -> Config:
        """Load a configuration found inside the scan target.

        Identical parsing, with two powers withheld: the file may not raise a
        resource limit above the built-in default, and it may not add rule
        packs. Both are things a repository can otherwise use against the person
        scanning it -- an unbounded timeout is a denial of service on a shared
        runner, and a rule pack is engine input supplied by the code under
        examination.

        Neither is withheld from the operator. `--timeout` and `--rules` are
        typed by the person running the scan and remain trusted.
        """
        config = cls.from_file(path)
        return config._withhold_untrusted_powers()

    def _withhold_untrusted_powers(self) -> Config:
        clamped: list[str] = []

        limits = self.limits
        for name in sorted(self.explicit_limits):
            if name == "max_workers":
                continue
            mine = getattr(limits, name, None)
            default = getattr(DEFAULT_LIMITS, name, None)
            if mine is not None and default is not None and mine > default:
                limits = limits.merged(**{name: default})
                clamped.append(f"limits.{name}")

        extra = self.extra_rule_paths
        if extra:
            clamped.append("rules.extra")
            extra = ()

        return replace(
            self,
            limits=limits,
            extra_rule_paths=extra,
            from_untrusted_source=True,
            clamped_settings=tuple(clamped),
        )

    @classmethod
    def discover(cls, root: str | Path) -> Config:
        """Find and load a repository configuration, or return defaults.

        Absence of a configuration file is not an error. A tool that requires
        configuration before it will run is a tool most repositories never adopt.

        A configuration file that is a symbolic link pointing outside the scan
        root is refused. The rest of the engine never follows a link out of the
        tree, and config discovery must not either: a link is a way to have the
        scanner read settings from somewhere the reviewer of this repository
        never sees.
        """
        base = Path(root).resolve()
        for name in CONFIG_FILENAMES:
            candidate = base / name
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if not str(resolved).startswith(str(base)):
                raise ConfigError(
                    f"{candidate} is a link to {resolved}, outside the scan root",
                    hint=(
                        "Configuration must live in the tree being scanned, where it "
                        "is reviewed with it. Pass --config explicitly if the file "
                        "genuinely belongs elsewhere."
                    ),
                )
            return cls.from_file(candidate)
        return cls.default()

    # -- Layering --------------------------------------------------------

    def clamped_by(self, org: Config, constraints: OrgConstraints) -> Config:
        """Apply the organisation ceiling to this repository configuration.

        Returns the clamped configuration, or raises
        :class:`PolicyViolationError` naming the specific conflict.

        Conflicts are raised rather than silently resolved. Silent clamping
        leaves the repository owner believing a setting is in force when it is
        not, and there is then no signal anywhere that the two layers disagree.
        """
        violations: list[str] = []

        for detector in sorted(constraints.detectors_required):
            if self.detectors.get(detector) is False:
                violations.append(
                    f"detector {detector!r} is disabled here but required by organisation policy"
                )

        if (
            constraints.min_severity_threshold is not None
            and self.severity_threshold > constraints.min_severity_threshold
        ):
            violations.append(
                f"severity_threshold {self.severity_threshold} is less strict than the "
                f"organisation minimum {constraints.min_severity_threshold}"
            )

        if (
            constraints.min_confidence_threshold is not None
            and self.confidence_threshold > constraints.min_confidence_threshold
        ):
            violations.append(
                f"confidence_threshold {self.confidence_threshold} is less strict than the "
                f"organisation minimum {constraints.min_confidence_threshold}"
            )

        if not constraints.allow_network and not self.offline:
            violations.append("network access is enabled here but forbidden by organisation policy")

        if not constraints.allow_plugins and self.allow_plugins:
            violations.append("third-party plugins are enabled here but forbidden by policy")

        if not constraints.allow_extra_rule_packs and self.extra_rule_paths:
            violations.append("additional rule packs are configured here but forbidden by policy")

        if not constraints.allow_limit_increase:
            for name in sorted(self.explicit_limits):
                if name == "max_workers":
                    continue
                mine = getattr(self.limits, name)
                theirs = getattr(org.limits, name)
                if mine > theirs:
                    violations.append(
                        f"limit {name}={mine} exceeds the organisation ceiling of {theirs}"
                    )

        for suppression in self.suppressions:
            problem = _suppression_violation(suppression, constraints)
            if problem:
                violations.append(
                    f"suppression {suppression.rule} at {suppression.path}: {problem}"
                )

        if violations:
            listed = "\n  - ".join(violations)
            raise PolicyViolationError(
                f"repository configuration conflicts with organisation policy:\n  - {listed}",
                hint=(
                    "Organisation policy is a ceiling, not a default. Make the repository "
                    "configuration at least as strict, or request a policy change."
                ),
            )

        # No conflicts: take the stricter value of each pair.
        return replace(
            self,
            severity_threshold=min(self.severity_threshold, org.severity_threshold),
            confidence_threshold=min(self.confidence_threshold, org.confidence_threshold),
            limits=self.limits.stricter_of(org.limits),
            explicit_limits=self.explicit_limits | org.explicit_limits,
            offline=self.offline or org.offline,
            allow_plugins=self.allow_plugins and org.allow_plugins,
            policy=_stricter_policy(self.policy, org.policy),
            constraints=constraints,
        )

    def with_overrides(self, **overrides: Any) -> Config:
        """Apply CLI overrides, the highest-precedence layer."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean) if clean else self

    # -- Derived ---------------------------------------------------------

    def detector_enabled(self, detector_id: str) -> bool:
        """Detectors are opt-out, not opt-in.

        A detector absent from the configuration runs. The alternative means a
        new detector ships disabled everywhere and protects nobody until each
        repository is edited, which in practice is never.
        """
        return self.detectors.get(detector_id, True)

    def active_suppressions(self, today: date | None = None) -> tuple[Suppression, ...]:
        """Suppressions that have not expired.

        An expired suppression stops suppressing. The engine separately emits a
        POLICY finding for it, so expiry is loud rather than silent: the finding
        it was hiding reappears *and* the stale entry is named.
        """
        now = today or date.today()
        live: list[Suppression] = []
        for suppression in self.suppressions:
            try:
                if date.fromisoformat(suppression.expires) >= now:
                    live.append(suppression)
            except ValueError:
                continue  # validated at parse time; a malformed date suppresses nothing
        return tuple(live)

    def expired_suppressions(self, today: date | None = None) -> tuple[Suppression, ...]:
        now = today or date.today()
        expired: list[Suppression] = []
        for suppression in self.suppressions:
            try:
                if date.fromisoformat(suppression.expires) < now:
                    expired.append(suppression)
            except ValueError:
                expired.append(suppression)
        return tuple(expired)

    def fingerprint(self) -> str:
        """Stable hash of everything that can change a finding.

        Feeds the incremental cache key. Deliberately includes rule packs,
        thresholds, detectors and limits, and deliberately excludes presentation
        concerns such as evidence mode and cache location, which cannot change
        whether a finding exists.
        """
        payload = {
            "version": self.version,
            "severity_threshold": int(self.severity_threshold),
            "confidence_threshold": int(self.confidence_threshold),
            "detectors": dict(sorted(self.detectors.items())),
            "exclude": sorted(self.exclude),
            "include": sorted(self.include),
            "minified": sorted(self.minified),
            "limits": self.limits.to_dict(),
            "rule_packs": sorted(self.rule_packs),
            "extra_rule_paths": sorted(self.extra_rule_paths),
            "profile": self.profile,
            "offline": self.offline,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def explain(self) -> Iterator[str]:
        """Yield every effective setting with the layer that supplied it."""
        for entry in self.provenance:
            yield str(entry)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the canonical configuration schema.

        Deliberately the same shape ``from_dict`` accepts, so the round trip
        holds. It did not before, and the failure was silent: anything that
        serialised a config and read it back -- a worker pool, a saved run --
        produced something that could not be parsed, and the caller fell back
        without saying why.
        """
        return {
            "version": self.version,
            "evidence": str(self.evidence),
            "scan": {
                "severity_threshold": str(self.severity_threshold),
                "confidence_threshold": str(self.confidence_threshold),
                "detectors": dict(sorted(self.detectors.items())),
                "exclude": list(self.exclude),
                "include": list(self.include),
                "minified": list(self.minified),
                "limits": self.limits.to_dict(),
                "offline": self.offline,
                "allow_plugins": self.allow_plugins,
                "profile": self.profile,
            },
            "policy": {
                "fail_on": (
                    [str(self.policy.fail_on_severity)]
                    if self.policy.fail_on_severity is not None
                    else []
                )
                + [{"category": str(c)} for c in sorted(self.policy.fail_on_categories)],
                "fail_on_incomplete": self.policy.fail_on_incomplete,
                "min_confidence_to_fail": str(self.policy.min_confidence_to_fail),
            },
            "suppressions": [s.to_dict() for s in self.suppressions],
            "rules": {
                "packs": list(self.rule_packs),
                "extra": list(self.extra_rule_paths),
            },
        }

    def summary(self) -> dict[str, Any]:
        """A flat view for display. Not a serialisation format."""
        return {
            "severity_threshold": str(self.severity_threshold),
            "confidence_threshold": str(self.confidence_threshold),
            "evidence": str(self.evidence),
            "offline": self.offline,
            "detectors": dict(sorted(self.detectors.items())),
            "exclude": list(self.exclude),
            "suppressions": len(self.suppressions),
            "config_hash": self.fingerprint(),
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_TOP_LEVEL_KEYS = frozenset({"version", "scan", "policy", "evidence", "suppressions", "rules"})
_SCAN_KEYS = frozenset(
    {
        "severity_threshold",
        "confidence_threshold",
        "detectors",
        "exclude",
        "include",
        "minified",
        "limits",
        "offline",
        "allow_plugins",
        "profile",
    }
)
_POLICY_KEYS = frozenset({"fail_on", "fail_on_incomplete", "min_confidence_to_fail"})
_RULES_KEYS = frozenset({"packs", "extra"})
_SUPPRESSION_KEYS = frozenset({"rule", "path", "justification", "expires", "approved_by"})


def _reject_unknown(data: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    """Strict key checking.

    A configuration parser that ignores what it does not understand is a
    scanner-blinding primitive: `detectors:` misspelled as `detector:` silently
    means "use every default", and nothing anywhere reports that the setting was
    discarded.
    """
    unknown = set(data) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        near = _suggest(next(iter(sorted(unknown))), allowed)
        hint = f"Did you mean {near!r}?" if near else None
        raise ConfigError(f"unknown key(s) in {where}: {names}", hint=hint)


def _suggest(word: str, options: frozenset[str]) -> str | None:
    """Cheapest useful typo suggestion: shared-prefix, then edit distance 1-2."""
    best: tuple[int, str] | None = None
    for option in options:
        distance = _edit_distance(word, option)
        if distance <= 2 and (best is None or distance < best[0]):
            best = (distance, option)
    return best[1] if best else None


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _as_str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise ConfigError(
            f"{where} must be a list, not a string",
            hint=f"Write:\n  {where}:\n    - {value}",
        )
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(value)


def _parse_config(data: Mapping[str, Any], *, source: str, layer: str) -> Config:
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: top level must be a mapping")

    _reject_unknown(data, _TOP_LEVEL_KEYS, source)

    version = data.get("version", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        raise ConfigError(
            f"{source}: unsupported config version {version!r}",
            hint=f"This build understands version {CONFIG_VERSION}.",
        )

    provenance: list[Provenance] = []

    def record(key: str, value: Any) -> Any:
        provenance.append(Provenance(key, value, layer, source))
        return value

    scan = data.get("scan") or {}
    if not isinstance(scan, dict):
        raise ConfigError(f"{source}: `scan` must be a mapping")
    _reject_unknown(scan, _SCAN_KEYS, f"{source}: scan")

    try:
        severity = Severity.parse(scan.get("severity_threshold", "low"))
        confidence = Confidence.parse(scan.get("confidence_threshold", "low"))
    except ValueError as exc:
        raise ConfigError(f"{source}: {exc}") from exc

    detectors_raw = scan.get("detectors") or {}
    if not isinstance(detectors_raw, dict) or not all(
        isinstance(v, bool) for v in detectors_raw.values()
    ):
        raise ConfigError(f"{source}: scan.detectors must map detector ids to booleans")

    limits_raw = scan.get("limits") or {}
    if not isinstance(limits_raw, dict):
        raise ConfigError(f"{source}: scan.limits must be a mapping")
    explicit_limits = frozenset(limits_raw)
    try:
        limits = DEFAULT_LIMITS.merged(**limits_raw) if limits_raw else DEFAULT_LIMITS
        Limits.from_dict({**DEFAULT_LIMITS.to_dict(), **limits_raw})  # key validation
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{source}: scan.limits: {exc}") from exc

    evidence_raw = data.get("evidence", "masked")
    try:
        evidence = RedactionMode(evidence_raw)
    except ValueError:
        valid = ", ".join(m.value for m in RedactionMode)
        raise ConfigError(
            f"{source}: evidence must be one of: {valid}", hint=f"got {evidence_raw!r}"
        ) from None

    policy = _parse_policy(data.get("policy") or {}, source=source)
    suppressions = _parse_suppressions(data.get("suppressions") or [], source=source)

    rules = data.get("rules") or {}
    if not isinstance(rules, dict):
        raise ConfigError(f"{source}: `rules` must be a mapping")
    _reject_unknown(rules, _RULES_KEYS, f"{source}: rules")
    packs = _as_str_tuple(rules.get("packs"), f"{source}: rules.packs") or ("cordon-builtin",)
    extra = _as_str_tuple(rules.get("extra"), f"{source}: rules.extra")

    record("scan.severity_threshold", str(severity))
    record("scan.confidence_threshold", str(confidence))
    record("evidence", str(evidence))
    record("scan.offline", bool(scan.get("offline", True)))

    return Config(
        version=CONFIG_VERSION,
        severity_threshold=severity,
        confidence_threshold=confidence,
        detectors=dict(detectors_raw),
        exclude=_as_str_tuple(scan.get("exclude"), f"{source}: scan.exclude"),
        include=_as_str_tuple(scan.get("include"), f"{source}: scan.include"),
        minified=_as_str_tuple(scan.get("minified"), f"{source}: scan.minified"),
        limits=limits,
        explicit_limits=explicit_limits,
        policy=policy,
        suppressions=suppressions,
        evidence=evidence,
        offline=bool(scan.get("offline", True)),
        allow_plugins=bool(scan.get("allow_plugins", False)),
        rule_packs=packs,
        extra_rule_paths=extra,
        profile=str(scan.get("profile", "balanced")),
        provenance=tuple(provenance),
    )


def _parse_policy(raw: Any, *, source: str) -> Policy:
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: `policy` must be a mapping")
    _reject_unknown(raw, _POLICY_KEYS, f"{source}: policy")

    fail_on = raw.get("fail_on")
    severity: Severity | None = Severity.HIGH
    categories: set[Category] = {Category.MALICIOUS}

    if fail_on is not None:
        if not isinstance(fail_on, list):
            raise ConfigError(f"{source}: policy.fail_on must be a list")
        severity = None
        categories = set()
        for entry in fail_on:
            if isinstance(entry, str):
                try:
                    level = Severity.parse(entry)
                except ValueError as exc:
                    raise ConfigError(f"{source}: policy.fail_on: {exc}") from exc
                severity = level if severity is None else min(severity, level)
            elif isinstance(entry, dict) and set(entry) == {"category"}:
                try:
                    categories.add(Category(entry["category"]))
                except ValueError:
                    valid = ", ".join(c.value for c in Category)
                    raise ConfigError(
                        f"{source}: policy.fail_on: unknown category {entry['category']!r}; "
                        f"expected one of: {valid}"
                    ) from None
            else:
                raise ConfigError(
                    f"{source}: policy.fail_on entries must be a severity name "
                    f"or {{category: <name>}}, got {entry!r}"
                )

    min_conf = Confidence.MEDIUM
    if "min_confidence_to_fail" in raw:
        try:
            min_conf = Confidence.parse(raw["min_confidence_to_fail"])
        except ValueError as exc:
            raise ConfigError(f"{source}: policy: {exc}") from exc

    return Policy(
        fail_on_severity=severity,
        fail_on_categories=frozenset(categories),
        fail_on_incomplete=bool(raw.get("fail_on_incomplete", False)),
        min_confidence_to_fail=min_conf,
    )


def _parse_suppressions(raw: Any, *, source: str) -> tuple[Suppression, ...]:
    """Parse and validate suppressions.

    Validation is strict here rather than at apply time, so a malformed
    suppression fails the configuration instead of silently suppressing nothing
    (or, worse, silently suppressing everything).
    """
    if not isinstance(raw, list):
        raise ConfigError(f"{source}: `suppressions` must be a list")

    out: list[Suppression] = []
    for index, entry in enumerate(raw):
        where = f"{source}: suppressions[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a mapping")
        _reject_unknown(entry, _SUPPRESSION_KEYS, where)

        for required in ("rule", "path", "justification", "expires"):
            if not entry.get(required):
                raise ConfigError(
                    f"{where}: `{required}` is required",
                    hint=(
                        "Every suppression must name a rule AND a path, and must carry a "
                        "justification and an expiry date. A suppression naming only one of "
                        "rule or path disables far more than intended, and one that never "
                        "expires outlives everyone who understood it."
                    ),
                )

        justification = str(entry["justification"]).strip()
        if len(justification) < MIN_JUSTIFICATION_CHARS:
            raise ConfigError(
                f"{where}: justification must be at least {MIN_JUSTIFICATION_CHARS} characters",
                hint="Record why this is safe here, not that somebody decided it was.",
            )

        expires = str(entry["expires"])
        if not _ISO_DATE.match(expires):
            raise ConfigError(f"{where}: expires must be an ISO date (YYYY-MM-DD)")
        try:
            date.fromisoformat(expires)
        except ValueError as exc:
            raise ConfigError(f"{where}: invalid date {expires!r}") from exc

        out.append(
            Suppression(
                rule=str(entry["rule"]),
                path=str(entry["path"]),
                justification=justification,
                expires=expires,
                approved_by=str(entry["approved_by"]) if entry.get("approved_by") else None,
            )
        )
    return tuple(out)


def _suppression_violation(s: Suppression, c: OrgConstraints) -> str | None:
    """Check one suppression against the organisation ceiling."""
    if c.require_justification and len(s.justification.strip()) < MIN_JUSTIFICATION_CHARS:
        return "justification is too short"
    if c.require_approver and not s.approved_by:
        return "organisation policy requires an approver"
    if c.forbid_path_only_suppressions and (not s.rule or s.rule == "*"):
        return "wildcard rule suppressions are forbidden; name the specific rule"
    try:
        expires = date.fromisoformat(s.expires)
    except ValueError:
        return "expiry is not a valid date"
    horizon = (expires - date.today()).days
    if horizon > c.max_suppression_days:
        return f"expiry is {horizon} days away, exceeding the maximum of {c.max_suppression_days}"
    return None


def _stricter_policy(a: Policy, b: Policy) -> Policy:
    """Merge two failure policies, keeping the stricter of each field."""
    if a.fail_on_severity is None:
        severity = b.fail_on_severity
    elif b.fail_on_severity is None:
        severity = a.fail_on_severity
    else:
        severity = min(a.fail_on_severity, b.fail_on_severity)
    return Policy(
        fail_on_severity=severity,
        fail_on_categories=a.fail_on_categories | b.fail_on_categories,
        fail_on_incomplete=a.fail_on_incomplete or b.fail_on_incomplete,
        min_confidence_to_fail=min(a.min_confidence_to_fail, b.min_confidence_to_fail),
    )


# ---------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------
#
# Constraint C1 forbids a third-party runtime dependency, so PyYAML is not
# available and this parses the subset of YAML that configuration files need:
# nested mappings, block sequences, scalars, quoted strings, block scalars,
# comments and inline flow collections.
#
# Restricting the grammar is a feature rather than a compromise. Full YAML
# carries genuinely dangerous constructs -- type tags that instantiate arbitrary
# objects, anchors and aliases that can be expanded into a billion-node document,
# merge keys with quadratic resolution behaviour. A security tool parsing
# untrusted configuration wants none of them, and the safest way to not
# implement a hazard is to not implement it.
#
# Anything outside the subset raises a ConfigError naming the line, so an
# unsupported construct is a clear error rather than a silent misparse.


class _YamlError(ConfigError):
    pass


def _load_yaml_subset(text: str, *, source: str) -> dict[str, Any]:
    lines = _tokenize(text, source=source)
    if not lines:
        return {}
    value, index = _parse_block(lines, 0, lines[0][0], source=source)
    if index != len(lines):
        raise _YamlError(f"{source}:{lines[index][2]}: unexpected indentation")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _YamlError(f"{source}: top level must be a mapping")
    return value


def _tokenize(text: str, *, source: str) -> list[tuple[int, str, int]]:
    """Return (indent, content, line_number) for each significant line."""
    out: list[tuple[int, str, int]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise _YamlError(
                f"{source}:{number}: tab in indentation",
                hint="YAML indentation must use spaces.",
            )
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"---", "..."}:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out.append((indent, stripped, number))
    return out


def _parse_block(
    lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str
) -> tuple[Any, int]:
    if start >= len(lines):
        return None, start
    if lines[start][1].startswith("- "):
        return _parse_sequence(lines, start, indent, source=source)
    return _parse_mapping(lines, start, indent, source=source)


def _parse_mapping(
    lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    index = start
    while index < len(lines):
        line_indent, content, number = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise _YamlError(f"{source}:{number}: unexpected indentation")
        if content.startswith("- "):
            break

        key, _, rest = content.partition(":")
        if not _:
            raise _YamlError(f"{source}:{number}: expected 'key: value'")
        key = _unquote(key.strip())
        rest = rest.strip()

        if rest.startswith("#"):
            rest = ""
        if rest in {"|", ">", "|-", ">-"}:
            value, index = _parse_block_scalar(lines, index + 1, indent, rest, source=source)
            result[key] = value
            continue
        if rest:
            result[key] = _scalar(rest, number=number, source=source)
            index += 1
            continue

        # Nested block: whatever is indented further than this key.
        index += 1
        if index < len(lines) and lines[index][0] > indent:
            child_indent = lines[index][0]
            value, index = _parse_block(lines, index, child_indent, source=source)
            result[key] = value
        elif index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            # A sequence at the same indentation as its key. Common and legal.
            value, index = _parse_sequence(lines, index, indent, source=source)
            result[key] = value
        else:
            result[key] = None
    return result, index


def _parse_sequence(
    lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str
) -> tuple[list[Any], int]:
    result: list[Any] = []
    index = start
    while index < len(lines):
        line_indent, content, number = lines[index]
        if line_indent < indent or not content.startswith("- "):
            break
        if line_indent > indent:
            raise _YamlError(f"{source}:{number}: unexpected indentation in sequence")

        item = content[2:].strip()
        if ":" in item and not item.startswith(("'", '"')):
            # An inline mapping opening a sequence item. Re-parse the item and
            # any following lines indented past the dash as one mapping.
            synthetic: list[tuple[int, str, int]] = [(indent + 2, item, number)]
            index += 1
            while index < len(lines) and lines[index][0] > indent:
                synthetic.append(lines[index])
                index += 1
            value, consumed = _parse_mapping(synthetic, 0, indent + 2, source=source)
            if consumed != len(synthetic):
                raise _YamlError(f"{source}:{number}: could not parse sequence item")
            result.append(value)
            continue

        result.append(_scalar(item, number=number, source=source))
        index += 1
    return result, index


def _parse_block_scalar(
    lines: list[tuple[int, str, int]], start: int, indent: int, style: str, *, source: str
) -> tuple[str, int]:
    """Parse a literal (``|``) or folded (``>``) block scalar.

    Both chomping indicators are honoured, because they are not equivalent:
    ``|`` clips to a single trailing newline while ``|-`` strips it entirely.
    Collapsing them means a value silently differs from what the author wrote,
    which for a security configuration is exactly the class of surprise this
    parser exists to avoid.
    """
    parts: list[str] = []
    index = start
    while index < len(lines) and lines[index][0] > indent:
        parts.append(lines[index][1])
        index += 1

    # Literal keeps line breaks; folded joins lines with a single space.
    text = "\n".join(parts) if style.startswith("|") else " ".join(parts)

    # Chomping: "-" strips the trailing newline, the default clips to one.
    if style.endswith("-") or not text:
        return text, index
    return text + "\n", index


def _scalar(text: str, *, number: int, source: str) -> Any:
    text = text.strip()

    # Strip a trailing comment, but not one inside quotes.
    if text and text[0] not in {"'", '"'}:
        hash_at = text.find(" #")
        if hash_at != -1:
            text = text[:hash_at].strip()

    if not text:
        return None
    if text.startswith(("'", '"')):
        return _unquote(text)
    if text.startswith("["):
        if not text.endswith("]"):
            raise _YamlError(f"{source}:{number}: unterminated flow sequence")
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p, number=number, source=source) for p in _split_flow(inner)]
    if text.startswith("{"):
        if not text.endswith("}"):
            raise _YamlError(f"{source}:{number}: unterminated flow mapping")
        inner = text[1:-1].strip()
        if not inner:
            return {}
        mapping: dict[str, Any] = {}
        for pair in _split_flow(inner):
            k, sep, v = pair.partition(":")
            if not sep:
                raise _YamlError(f"{source}:{number}: expected 'key: value' in flow mapping")
            mapping[_unquote(k.strip())] = _scalar(v.strip(), number=number, source=source)
        return mapping

    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "~"}:
        return None
    # NOTE: "none" is deliberately NOT a null literal. The YAML 1.2 core schema
    # does not treat it as one, and `evidence: none` is a legitimate enum value
    # in this configuration -- mapping it to null makes that setting unreachable
    # while appearing to work.

    # Anchors, aliases and type tags are deliberately unsupported. Each is a
    # documented hazard in untrusted YAML, and a clear error beats a silent
    # misparse of something a user believed was in effect.
    if text[0] in {"&", "*", "!"}:
        raise _YamlError(
            f"{source}:{number}: YAML anchors, aliases and tags are not supported",
            hint="Cordon parses a restricted YAML subset deliberately. Write the value inline.",
        )

    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_flow(text: str) -> list[str]:
    """Split a flow collection on commas that are not inside quotes or brackets."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
        elif ch in "[{":
            depth += 1
            current.append(ch)
        elif ch in "]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        body = text[1:-1]
        if text[0] == '"':
            return body.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        return body.replace("''", "'")
    return text


# ---------------------------------------------------------------------------
# Organisation policy loading
# ---------------------------------------------------------------------------

_ORG_TOP_KEYS = frozenset(
    {
        "version",
        "name",
        "issued",
        "issuer",
        "enforce",
        "suppressions",
        "scoring",
        "fail_on",
        "scan",
        "evidence",
        "rules",
        "policy",
    }
)
_ENFORCE_KEYS = frozenset(
    {
        "detectors_required",
        "min_severity_threshold",
        "min_confidence_threshold",
        "allow_network",
        "allow_plugins",
        "allow_extra_rule_packs",
        "allow_limit_increase",
        "max_total_timeout",
    }
)
_ORG_SUPPRESSION_KEYS = frozenset(
    {
        "max_duration_days",
        "require_justification",
        "require_approver",
        "forbid_categories",
        "forbid_path_only",
    }
)


def load_org_policy(path: str | Path) -> tuple[Config, OrgConstraints]:
    """Load an organisation policy: its settings and its constraints.

    Returns the policy's own configuration (used as the upper layer in the merge)
    and the constraints it imposes on repository configurations.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"organisation policy not found: {p}")
    data = _load_yaml_subset(p.read_text(encoding="utf-8"), source=str(p))
    _reject_unknown(data, _ORG_TOP_KEYS, str(p))

    enforce = data.get("enforce") or {}
    if not isinstance(enforce, dict):
        raise ConfigError(f"{p}: `enforce` must be a mapping")
    _reject_unknown(enforce, _ENFORCE_KEYS, f"{p}: enforce")

    sup = data.get("suppressions") or {}
    if not isinstance(sup, dict):
        raise ConfigError(
            f"{p}: in an organisation policy, `suppressions` is a mapping of constraints, "
            "not a list of suppressions"
        )
    _reject_unknown(sup, _ORG_SUPPRESSION_KEYS, f"{p}: suppressions")

    forbid_raw = sup.get("forbid_categories", ["malicious"])
    try:
        forbid = frozenset(Category(c) for c in forbid_raw)
    except ValueError as exc:
        raise ConfigError(f"{p}: suppressions.forbid_categories: {exc}") from exc

    constraints = OrgConstraints(
        detectors_required=frozenset(
            _as_str_tuple(enforce.get("detectors_required"), f"{p}: enforce.detectors_required")
        ),
        min_severity_threshold=(
            Severity.parse(enforce["min_severity_threshold"])
            if "min_severity_threshold" in enforce
            else None
        ),
        min_confidence_threshold=(
            Confidence.parse(enforce["min_confidence_threshold"])
            if "min_confidence_threshold" in enforce
            else None
        ),
        allow_network=bool(enforce.get("allow_network", True)),
        allow_plugins=bool(enforce.get("allow_plugins", False)),
        allow_extra_rule_packs=bool(enforce.get("allow_extra_rule_packs", True)),
        allow_limit_increase=bool(enforce.get("allow_limit_increase", False)),
        max_suppression_days=int(sup.get("max_duration_days", MAX_SUPPRESSION_DAYS)),
        require_justification=bool(sup.get("require_justification", True)),
        require_approver=bool(sup.get("require_approver", False)),
        forbid_path_only_suppressions=bool(sup.get("forbid_path_only", True)),
        forbid_suppressing=forbid,
    )

    # The policy's own scan settings form the upper configuration layer.
    body = {k: v for k, v in data.items() if k in _TOP_LEVEL_KEYS and k != "suppressions"}
    body.setdefault("version", CONFIG_VERSION)
    org_config = _parse_config(body, source=str(p), layer=Layer.ORG)

    if constraints.max_total_timeout is not None:
        org_config = replace(
            org_config,
            limits=org_config.limits.merged(total_timeout=constraints.max_total_timeout),
        )

    return org_config, constraints


def resolve(
    *,
    root: str | Path = ".",
    config_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    **cli_overrides: Any,
) -> Config:
    """Build the effective configuration from all four layers.

    This is the only supported way to assemble a Config for a scan. Constructing
    one directly skips the ceiling enforcement, which is why the CLI and the SDK
    both route through here.
    """
    # An explicitly passed --config is operator input and is trusted. A config
    # discovered inside the scan target is not: it is part of the untrusted
    # input, and two of its powers are withheld accordingly.
    if config_path:
        repo = Config.from_file(config_path)
    else:
        repo = Config.discover(root)
        if repo != Config.default():
            repo = repo._withhold_untrusted_powers()

    policy_source = policy_path or os.environ.get("CORDON_POLICY")
    if policy_source:
        org_config, constraints = load_org_policy(policy_source)
        repo = repo.clamped_by(org_config, constraints)

    return repo.with_overrides(**cli_overrides)


__all__ = [
    "CONFIG_FILENAMES",
    "CONFIG_VERSION",
    "Config",
    "Layer",
    "OrgConstraints",
    "Policy",
    "Provenance",
    "load_org_policy",
    "resolve",
]
