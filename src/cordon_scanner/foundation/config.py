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
from dataclasses import dataclass, field, replace
from dataclasses import fields as dataclass_fields
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError, PolicyViolationError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS, Limits
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    RedactionMode,
    Severity,
    Suppression,
)
from cordon_scanner.foundation.taxonomy import ThreatDomain
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

CONFIG_VERSION = 1

CONFIG_FILENAMES = (
    "cordon.yaml",
    "cordon.yml",
    ".cordon.yaml",
    ".cordon.yml",
)


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


DEFAULT_MAX_MAJOR_DRIFT = 2
"""See `Policy.max_major_drift`. Named here because a `slots=True` dataclass
has no readable class attribute to take the default from."""


DEFAULT_ADVISORY_DOMAINS = frozenset(
    {ThreatDomain.INFRASTRUCTURE, ThreatDomain.CONTAINER, ThreatDomain.CICD}
)
"""See `Policy.advisory_domains`. Named here because a `slots=True` dataclass has
no readable class attribute for the parser to fall back to."""


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

    advisory_domains: frozenset[ThreatDomain] = DEFAULT_ADVISORY_DOMAINS
    """Domains that are REPORTED in full and do not fail the build by default.

    These three describe how a project configured its own infrastructure and
    pipelines: a security group open to the internet, `privileged: true`, a
    workflow that installs a tool with `curl | sh`. Every one of those is worth
    knowing and none of them is evidence that the code is compromised or is
    leaking anything -- they are choices the project already made, about itself,
    deliberately.

    Measured on 1,427 real repositories, they were most of the gate: with them
    failing the build, 76.2% of ordinary open-source projects went red, and
    infrastructure alone was 354 findings and the sole cause in 39 repositories.
    Triage of the largest classes found them overwhelmingly CORRECT --
    `SUSPECT.CI.FETCH_EXEC.001` was right in every sample examined, and
    `SUSPECT.DROPPER.001` in about nine of ten. They are not noise and deleting
    them would be wrong; they are simply not a reason to stop a release.

    A scanner that fails a build on the first day over a Dockerfile that runs
    `curl | sh` gets switched off, and a switched-off scanner catches nothing at
    all. That argument is written into half the rules in this pack; this is the
    same argument applied to the gate rather than to a pattern.

    What still fails, unchanged: malware, leaked credentials, obfuscation,
    exfiltration, and anything in the MALICIOUS category -- including
    `MALWARE.CI.SECRET_EXFIL.001`, which lives in `cicd` and is exempt from this
    carve-out because its category is the stronger claim.

    Set it empty to fail on everything, which is the pre-0.3 behaviour:

        policy:
          advisory_domains: []
    """

    hardening: bool = False
    """Report the hardening tier at its own severity.

    The advisory domains (`advisory_domains`) describe how a project configured its pipelines,
    containers and infrastructure: `curl | sh` in a workflow, a release job restoring a cache, a
    privileged pod. Those findings are correct and are not evidence that anything is attacking
    the project, and on the long-tail corpus they were most of what stopped repositories reading
    as quiet (review 98: Actions repositories 55% quiet with them, the infrastructure-heavy
    repository snapshots under 75%). So by default they form a hardening tier: every one is
    still in the report, recorded at LOW and labelled, and none is a warning. `--hardening`, or

        policy:
          hardening: true

    reports them at their own severity, for a team doing a hardening pass. Anything in the
    MALICIOUS category in those domains (`MALWARE.CI.SECRET_EXFIL.001`) is never in the tier.
    """

    max_major_drift: int = DEFAULT_MAX_MAJOR_DRIFT
    """How many major versions behind the current release a pin may sit before
    `POLICY.DEPENDENCY.DOWNGRADE.001` reports it.

    Two by default, and the default is a noise decision rather than a security
    one: a single major behind is the ordinary state of most dependencies in
    most projects, and a rule that fires on it fires on nearly everything.

    Configurable because "ordinary" is a property of the project rather than of
    the tool. A team that upgrades on a schedule wants 1; a codebase pinned to a
    long-term-support line wants 3 or more:

        policy:
          max_major_drift: 1
    """

    package_deny: tuple[str, ...] = ()
    """Packages that must not be used: `npm:event-stream`, `pypi:*-internal-*`,
    `pkg:npm/lodash@4.17.20`. Each match is `POLICY.PACKAGE.DENIED.001`.

        policy:
          packages:
            deny: ["npm:event-stream", "pypi:pycrypto"]
    """

    package_allow: tuple[str, ...] = ()
    """When set, the only packages that may be used; any other is `POLICY.PACKAGE.NOT_ALLOWED.001`."""

    license_deny: tuple[str, ...] = ()
    """Licences that must not be used: SPDX identifiers (`AGPL-3.0-only`) or categories
    (`network_copyleft`, `copyleft`, `weak_copyleft`, `permissive`, `unknown`)."""

    license_allow: tuple[str, ...] = ()
    """When set, the only licences that may be used. An expression is allowed when one of its
    `OR` branches is wholly allowed (`MIT OR GPL-3.0`); every part of an `AND` must be."""

    license_unknown: str = "allow"
    """What a dependency with no licence data, or one that cannot be classified, is: `allow`
    (not reported), `report` (`POLICY.LICENSE.UNKNOWN.001`, low) or `deny` (the same, high). With an
    allow list set, unknown is never approved: `allow` is read as `report`."""

    accept_no_feed: frozenset[str] | None = None
    """Ecosystems whose lack of any advisory source this project accepts. Their dependencies are
    still reported unchecked (`OPERATIONAL.ADVISORY.NO_FEED.001`, naming them), but no longer
    make the scan incomplete: an ecosystem no source covers can never be checked, and a gate that
    can never pass teaches a team to switch `fail_on_incomplete` off, which hides real gaps.

    Strict by default, and a choice made where reviewers see it. `None` is "not said", which a
    merge with an organisation policy that does say leaves to that policy; two that both say keep
    only what both accept."""

    @classmethod
    def default(cls) -> Policy:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on_severity": str(self.fail_on_severity) if self.fail_on_severity else None,
            "fail_on_categories": sorted(str(c) for c in self.fail_on_categories),
            "fail_on_incomplete": self.fail_on_incomplete,
            "min_confidence_to_fail": str(self.min_confidence_to_fail),
            "advisory_domains": sorted(str(d) for d in self.advisory_domains),
            "hardening": self.hardening,
            "max_major_drift": self.max_major_drift,
            "packages": {"deny": list(self.package_deny), "allow": list(self.package_allow)},
            "accept_no_feed": sorted(self.accept_no_feed)
            if self.accept_no_feed is not None
            else None,
            "licenses": {
                "deny": list(self.license_deny),
                "allow": list(self.license_allow),
                "unknown": self.license_unknown,
            },
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
    reachability: bool = False
    """Annotate vulnerability findings with import reachability.

    Off by default because it reads every source file to collect imports, which
    a large scan should not pay for unasked. When on, a vulnerability in a
    transitive dependency that first-party code does not import is lowered and
    tagged -- never removed. See `detect/reachability`."""
    intel_feed: bool = True
    """Refresh intel from Cordon's signed public feed before scanning.

    The scan itself never uses the network for this: the feed is static, identical files for
    everyone, so fetching it reveals nothing about what is being scanned. Off with `--offline`
    or `CORDON_OFFLINE=1`, which makes no network attempt at all. A build with no pinned feed
    root never makes a request whatever this says. See `intel/feed`."""
    clamav: str | None = None
    """A local clamd to hand file bytes to (`--clamav`): a Unix socket path, or `tcp://` on a
    loopback address. Set only by the operator: never read from a repository's configuration,
    because the scan target must not choose where its own bytes are sent. See `detect/clamav`."""
    private_registries: tuple[tuple[str, str], ...] = ()
    """`(registry URL, environment variable)` for each registry the organisation runs: under
    `--online`, a dependency resolved from one is asked about there, with the token in that
    variable (`--registry-token URL=VAR`, `CORDON_REGISTRY_TOKENS`). Set only by the operator,
    never from any configuration file: a repository naming one could send a credential to a host
    it chose. See `intel/private_registries`."""
    rule_file: str | None = None
    """A cordon-rule rule file to match every file against (`--rule-file`). Set only by the
    operator, for the reason `clamav` is: a repository that chose the rules run against it would
    choose rules that never match. See `detect/binary/rule_files`."""
    keyrings: tuple[str, ...] = ()
    """OpenPGP keyrings whose keys a Helm chart's provenance file may be signed by (`--keyring`,
    `CORDON_KEYRINGS`), as `helm verify --keyring` takes them. Set only by the operator, never
    from any configuration file: a repository that chose the keys it is verified against would
    bring its own. See `intel/openpgp`."""
    judge: str | None = None
    """A language model to judge agent-facing text (`--judge`): `ollama:<model>`,
    `openai:<model>`, `anthropic[:<model>]` or `cordon-cloud`. Set only by the operator, for the
    reason `clamav` is: the scan target must not choose where its own text is sent. See
    `detect/agent_judge`."""
    judge_blocks: bool = False
    """Whether a malicious verdict from the judge is HIGH, inside the default gate (`--judge-blocks`).
    Off, it warns: a model's reading is weaker evidence than a rule's match."""
    judge_max_calls: int = 200
    """The most model calls one scan may make; text past the budget is reported unjudged."""
    max_intel_age: int | None = None
    """Seconds after which the intel behind a scan is reported stale (`OPERATIONAL.INTEL.STALE`),
    which marks the scan incomplete. `None` means 24 hours when this build has a feed, and no
    check when it does not; 0 turns the check off."""
    expand_archives: bool = True
    """Open archives found inside a directory scan and scan their members.

    On by default because a vendored `.whl`, `.jar` or `.tgz` is part of what a
    repository ships, and one left unopened passed the default gate with its
    payload unread. Turning it off (`--no-expand`) is for speed only: an archive
    that was not opened marks the scan incomplete rather than looking clean."""
    allow_plugins: bool = False
    rule_packs: tuple[str, ...] = ("cordon-builtin",)
    extra_rule_paths: tuple[str, ...] = ()

    disabled_rules: frozenset[str] = frozenset()

    allowed_action_owners: tuple[str, ...] = ()
    """Owners whose CI actions this project accepts.

    A third-party action runs with the job's token and secrets, so `uses:`
    is an execution decision, not a dependency declaration. Which owners are
    acceptable is a policy question with no universal answer -- a shop that
    only permits `actions/` and its own org is being sensible, and so is one
    that permits a long reviewed list -- so this stays off until an answer is
    supplied rather than guessing one.

    Like `internal_namespaces`, safe to read from an untrusted repository
    config: setting it can only add findings."""

    internal_namespaces: tuple[str, ...] = ()
    """Name prefixes that belong to this organisation.

    Dependency confusion needs one fact no scanner can derive: which names are
    supposed to come from somewhere private. `@acme/utils` on the public
    registry is an attack if Acme publishes it internally and ordinary if they
    publish it publicly, and nothing in the repository distinguishes those.

    Safe to accept from an untrusted repository config, unusually for this
    file. Declaring a namespace can only *add* findings -- the worst an
    attacker achieves by setting it is noise in the scan of their own package
    -- so it needs no clamping, and the default of none means the check is off
    until somebody supplies the fact."""
    """Rule ids that must not produce findings.

    Applies to pack rules and to rules declared by a detector alike. Without it
    the second kind could only be turned off by patching the installed package,
    which meant an organisation could not tune the secret, container, CI and IaC
    rules -- the ones that fire most often in practice.

    Disabling is reported, like every other reduction in coverage, so a rule
    that was turned off and a rule that found nothing do not look the same.
    """

    profile: str = "balanced"
    cache_dir: str | None = None
    use_cache: bool = True

    constraints: OrgConstraints = field(default_factory=OrgConstraints.permissive)

    org_limits: Limits | None = field(default=None, compare=False)
    """The organisation's own limits, retained for the re-check.

    `recheck_constraints` exists because command-line overrides applied after
    `clamped_by` escaped the ceiling. It called `_check_against(constraints)`
    with `org=None`, and the limit comparison inside is guarded by
    `if not constraints.allow_limit_increase and org is not None` -- so the
    re-check never compared a single limit. `--timeout` and `--jobs` still went
    straight past the ceiling the method was written to enforce.

    The organisation's `Config` was not kept anywhere, which is why `org` was
    `None`. Its limits are kept here instead: they are the only part the
    re-check needs.
    """

    provenance: tuple[Provenance, ...] = field(default=(), compare=False)

    untrusted_exclusions: tuple[str, ...] = field(default=(), compare=False)
    """Exclude and include patterns that came from inside the scan target.

    Recorded separately from `exclude`/`include` so a reduction the *target*
    chose can be told apart from one the operator chose. They are not the same
    event: an operator excluding `vendor/**` is tuning their own scan, and a
    repository excluding `package.json` is hiding from it.

    `_withhold_untrusted_powers` refused two of the levers a discovered config
    can pull -- raising limits, adding rule packs -- and left this one alone, so
    a single line

        scan:
          exclude: ["package.json"]

    removed the file carrying a critical finding and produced output identical
    to a clean scan. The broad-exclusion check did not fire because one file out
    of sixty-one is nowhere near its threshold, and the unmatched-exclusion
    check did not fire because the pattern matched.
    """

    reduced_limits: tuple[str, ...] = field(default=(), compare=False)
    """Limits the scan target lowered below the built-in default.

    Lowering a limit is not refused -- a repository can have a real reason to
    cap its own scan cost -- but it narrows what the scan reaches just as surely
    as an exclusion does, and `max_files: 5` is an exclusion written in a way
    that produces no exclusion patterns to report. Recorded so the engine can
    say so.
    """

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
        from cordon_scanner.foundation.config_parser import ConfigParser

        return ConfigParser._parse_config(data, source=source, layer=layer)

    MAX_CONFIG_BYTES = 1024 * 1024
    """Ceiling on a configuration file.

    The file lives inside the scan target, which is untrusted input, and
    `read_text()` had no bound at all -- so a 2 GB `.cordon.yml` exhausted memory
    before scanning started."""

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser

        p = Path(path)
        if not p.is_file():
            raise ConfigError(
                f"configuration file not found: {p}",
                hint=f"Run `{PROGRAM} config validate` after creating it, or omit --config.",
            )
        raw = cls.read_bounded(p)
        data = RestrictedYamlParser._load_yaml_subset(raw, source=str(p))
        return cls.from_dict(data, source=str(p), layer=Layer.REPO)

    @classmethod
    def read_bounded(cls, p: Path) -> str:
        """Read a YAML document with a size ceiling and real error handling.

        Extracted because the organisation policy loader did none of it: no size
        check, no `OSError` handling, no `UnicodeDecodeError` handling. Since
        `CORDON_POLICY` can be aimed at any path, pointing it at a large or
        binary file produced an unhandled exception and exit 2 -- "the scanner
        broke" rather than "your policy is wrong", which is the reading that
        gets a pipeline to skip the step.
        """
        try:
            size = p.stat().st_size
            if size > cls.MAX_CONFIG_BYTES:
                raise ConfigError(
                    f"{p} is {size} bytes, over the {cls.MAX_CONFIG_BYTES} byte limit",
                    hint=(
                        "A configuration file this large is not a configuration file. "
                        "It lives inside the scan target, which is untrusted input."
                    ),
                )
            return p.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError(
                f"{p} is not UTF-8 text: {exc}",
                hint="A policy or configuration file has to be readable YAML.",
            ) from exc
        except OSError as exc:
            raise ConfigError(f"cannot read {p}: {exc}") from exc

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
        from cordon_scanner.foundation.config_parser import ConfigParser

        clamped: list[str] = []
        reduced: list[str] = []

        limits = self.limits
        limits = self._withheld_limits(limits, clamped, reduced)

        extra = self.extra_rule_paths
        if extra:
            clamped.append("rules.extra")
            extra = ()

        # The failure gate. A discovered config may make it stricter and never
        # weaker, which is the same rule limits already follow and for a sharper
        # reason: `policy: {fail_on: []}` disarms the gate for every finding
        # including MALICIOUS at CRITICAL, and it did so silently.
        #
        # Worse, it disarmed the fix for a different bug. `filter_for_reporting`
        # keeps any finding that trips the gate regardless of a reporting
        # threshold, precisely so a repository cannot hide a critical finding
        # behind `confidence_threshold: confirmed`. That protection is
        # conditioned on the gate being non-empty, and the same untrusted file
        # controlled both -- so five lines re-opened the bug the fix was written
        # against, in the file the fix lives in.
        policy = ConfigParser._stricter_policy(self.policy, Policy.default())
        if policy != self.policy:
            clamped.append("policy.fail_on")

        offline, allow_plugins, expand_archives, intel_feed, max_intel_age, minified = (
            self._withheld_switches(clamped)
        )

        return replace(
            self,
            limits=limits,
            extra_rule_paths=extra,
            policy=policy,
            offline=offline,
            allow_plugins=allow_plugins,
            expand_archives=expand_archives,
            intel_feed=intel_feed,
            max_intel_age=max_intel_age,
            minified=minified,
            from_untrusted_source=True,
            clamped_settings=tuple(clamped),
            reduced_limits=tuple(reduced),
            untrusted_exclusions=(*self.exclude, *self.include, *minified),
        )

    def _withheld_limits(self, limits: Limits, clamped: list[str], reduced: list[str]) -> Limits:
        """Limits an untrusted layer raised, held at the default; ones it lowered, kept and recorded."""
        for name in sorted(self.explicit_limits):
            if name == "max_workers":
                continue
            mine = getattr(limits, name, None)
            default = getattr(DEFAULT_LIMITS, name, None)
            if mine is None or default is None:
                continue
            if mine > default:
                # Raising is refused. A repository that sets a multi-hour
                # timeout and a gigabyte file ceiling makes any scan target a
                # denial of service against the machine running the scan.
                limits = limits.merged(**{name: default})
                clamped.append(f"limits.{name}")
            elif mine < default:
                # Lowering is *allowed and reported*. It is the same attack from
                # the other direction: `max_files: 5` stops the traversal before
                # it reaches the payload, and the result is an incomplete scan
                # that exits zero. It is not refused, because a repository can
                # have a real reason to cap its own scan cost -- but it is never
                # silent, because the reason might equally be that the fifth
                # file is where the interesting one starts.
                reduced.append(f"limits.{name}")
        return limits

    def _withheld_switches(
        self, clamped: list[str]
    ) -> tuple[bool, bool, bool, bool, int | None, tuple[str, ...]]:
        """The switches an untrusted layer may only turn towards safety: offline, plugins, archives, the intel feed, its age, minified paths."""
        from cordon_scanner.foundation.config_parser import ConfigParser

        # Going online is an operator's decision, never the scan target's.
        #
        # `offline` defaults to true and every network-requiring detector is
        # disabled while it holds. Nothing withheld it here, so five characters
        # in a repository's own `cordon.yaml`
        #
        #     scan:
        #       offline: false
        #
        # turned the scanner's network on for the scan of that same repository
        # -- and silently, because no clamp was recorded either. What that
        # reaches is the registry detector, which then sends this repository's
        # package names to a host, from the machine running the scan, on the
        # say-so of the thing being scanned.
        #
        # The same rule the gate and the limits already follow: a discovered
        # config may make a scan stricter and never weaker.
        offline = self.offline
        if not offline:
            offline = True
            clamped.append("scan.offline")

        # Settings that switch detection off, by any other name. Each is an operator's decision and
        # is withheld from the scan target, reported at HIGH: `allow_plugins` loads third-party code
        # into the scanner itself (code execution in the scan step, and a plugin can rewrite the
        # verdict); `minified: ["**"]` silenced the long-line obfuscation rule everywhere;
        # `expand_archives: false` left every archive unread; `intel_feed: false` and
        # `max_intel_age: 0` turned the staleness check off.
        allow_plugins = self.allow_plugins
        if allow_plugins:
            allow_plugins = False
            clamped.append("scan.allow_plugins")
        expand_archives = self.expand_archives
        if not expand_archives:
            expand_archives = True
            clamped.append("scan.expand_archives")
        intel_feed = self.intel_feed
        if not intel_feed:
            intel_feed = True
            clamped.append("scan.intel_feed")
        max_intel_age = self.max_intel_age
        if max_intel_age == 0:
            max_intel_age = None
            clamped.append("scan.max_intel_age")
        # A pattern that names a place is kept and reported like an exclusion; one that spans the
        # tree (`**`, or a bare `*.js` that matches every directory) is a rule switched off.
        minified = tuple(p for p in self.minified if not ConfigParser._spans_tree(p))
        if len(minified) != len(self.minified):
            clamped.append("scan.minified")
        return offline, allow_plugins, expand_archives, intel_feed, max_intel_age, minified

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
            # `is_relative_to`, not a string prefix. `/home/u/repo` is a prefix
            # of `/home/u/repo-evil`, so a config symlinked to
            # `../repo-evil/cordon.yml` passed a check written to stop exactly
            # that.
            if not resolved.is_relative_to(base):
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

    def _check_suppressions(self, constraints: OrgConstraints) -> None:
        """Validate suppressions alone, with no organisation policy present.

        Split out because the suppression ceiling is the one part of
        OrgConstraints that means something without an organisation: an expiry
        and a justification are demanded of the repository by the tool, not by
        anybody's policy.
        """
        from cordon_scanner.foundation.config_parser import ConfigParser

        violations = [
            f"suppression {s.rule} at {s.path}: {problem}"
            for s in self.suppressions
            if (problem := ConfigParser._suppression_violation(s, constraints))
        ]
        if violations:
            listed = "\n  - ".join(violations)
            raise PolicyViolationError(
                f"suppressions in this configuration are not acceptable:\n  - {listed}",
                hint=(
                    "A suppression must name one rule and one path, carry a "
                    "justification, and expire. These are the tool's own requirements "
                    "and apply whether or not an organisation policy is configured."
                ),
            )

    _rechecking: bool = field(default=False, compare=False, repr=False)
    """Whether `_check_against` is running the post-override pass.

    Set only for the duration of `recheck_constraints`, because the two passes
    ask different questions: the first asks what the repository *declared*, and
    this one asks what the scan will actually run with."""

    def recheck_constraints(self) -> None:
        """Re-validate against the organisation ceiling already attached here.

        `clamped_by` runs during `resolve()`. Anything that edits a Config
        afterwards escapes it, and the command line did exactly that:

            config = ConfigResolver.resolve(..., policy_path=...)   # ceiling applied
            if args.no_detector:
                config = config.with_overrides(detectors=...)        # ceiling gone

        so `--no-detector capability` turned a failing build into a passing one
        against a policy whose whole purpose was to require that detector. The
        flag's own help text said "(organisation policy may forbid this)".
        Nothing did.

        Called after every command-line override, so the ceiling is checked
        against the configuration the scan actually runs with rather than an
        intermediate one.
        """
        checking = replace(self, _rechecking=True)
        checking._check_against(
            self.constraints,
            org=replace(Config.default(), limits=self.org_limits)
            if self.org_limits is not None
            else None,
        )

    def clamped_by(self, org: Config, constraints: OrgConstraints) -> Config:
        """Apply the organisation ceiling to this repository configuration.

        Returns the clamped configuration, or raises
        :class:`PolicyViolationError` naming the specific conflict.

        Conflicts are raised rather than silently resolved. Silent clamping
        leaves the repository owner believing a setting is in force when it is
        not, and there is then no signal anywhere that the two layers disagree.
        """
        self._check_against(constraints, org=org)
        return self._merged_under(org, constraints)

    def _check_against(self, constraints: OrgConstraints, *, org: Config | None = None) -> None:
        """Collect every conflict with a ceiling and raise once, naming all of them.

        One error listing every conflict, rather than one per run: an operator
        fixing these is otherwise made to rediscover them one at a time.
        """
        from cordon_scanner.foundation.config_parser import ConfigParser

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

        if not constraints.allow_limit_increase and org is not None:
            # Every limit, not only the explicitly declared ones.
            #
            # `--timeout` reaches the config through `limits.merged(...)`, which
            # does not add to `explicit_limits`, so a re-check that iterated
            # only those compared nothing at all and the ceiling was bypassed by
            # the exact flag it was meant to catch. On the first pass the
            # distinction matters -- an unset limit is the default, not a
            # request -- but by the re-check the merge has already happened and
            # what is on the config is what the scan will run with.
            names = (
                {field.name for field in dataclass_fields(self.limits)}
                if self._rechecking
                else set(self.explicit_limits)
            )
            for name in sorted(names):
                if name == "max_workers":
                    continue
                mine = getattr(self.limits, name)
                theirs = getattr(org.limits, name)
                if mine > theirs:
                    violations.append(
                        f"limit {name}={mine} exceeds the organisation ceiling of {theirs}"
                    )

        for suppression in self.suppressions:
            problem = ConfigParser._suppression_violation(suppression, constraints)
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

    def _merged_under(self, org: Config, constraints: OrgConstraints) -> Config:
        """Take the stricter value of each pair. Called only after checking."""
        from cordon_scanner.foundation.config_parser import ConfigParser

        return replace(
            self,
            severity_threshold=min(self.severity_threshold, org.severity_threshold),
            confidence_threshold=min(self.confidence_threshold, org.confidence_threshold),
            limits=self.limits.stricter_of(org.limits),
            explicit_limits=self.explicit_limits | org.explicit_limits,
            offline=self.offline or org.offline,
            # Expansion is coverage, so the stricter value is "on": a repository
            # cannot switch off what its organisation requires to be opened.
            expand_archives=self.expand_archives or org.expand_archives,
            # The organisation may forbid the network entirely (an air-gapped estate) and may
            # demand fresher intel; a repository can do neither the other way.
            intel_feed=self.intel_feed and org.intel_feed,
            clamav=self.clamav or org.clamav,
            rule_file=self.rule_file or org.rule_file,
            keyrings=self.keyrings or org.keyrings,
            judge=self.judge or org.judge,
            judge_blocks=self.judge_blocks or org.judge_blocks,
            judge_max_calls=min(self.judge_max_calls, org.judge_max_calls),
            max_intel_age=IntelAge._shorter_age(self.max_intel_age, org.max_intel_age),
            allow_plugins=self.allow_plugins and org.allow_plugins,
            policy=ConfigParser._stricter_policy(self.policy, org.policy),
            constraints=constraints,
            # Kept so `recheck_constraints` has something to compare against
            # after the command line has had its turn.
            org_limits=org.limits,
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

        Feeds the incremental cache key. Includes rule packs, thresholds,
        detectors, limits -- and the evidence mode.

        The evidence mode looks like a presentation concern, and an earlier
        version excluded it on the grounds that it "cannot change whether a
        finding exists". That is true and beside the point: redaction is applied
        when the evidence is *constructed*, not when it is rendered, so the
        redacted snippet is baked into the cached finding. With the mode outside
        the key, a warm cache served snippets built under the previous mode, and
        `--evidence hash_only` silently returned masked content -- the exact flag
        an operator sets when the report is going somewhere widely readable.

        Cache location stays out. It changes where a finding is stored, not what
        it says.
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
            "disabled_rules": sorted(self.disabled_rules),
            "internal_namespaces": sorted(self.internal_namespaces),
            "allowed_action_owners": sorted(self.allowed_action_owners),
            "profile": self.profile,
            "offline": self.offline,
            "reachability": self.reachability,
            "expand_archives": self.expand_archives,
            "intel_feed": self.intel_feed,
            "max_intel_age": self.max_intel_age,
            "clamav": bool(self.clamav),
            "rule_file": bool(self.rule_file),
            "keyrings": bool(self.keyrings),
            "judge": bool(self.judge),
            "evidence": str(self.evidence),
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
                "reachability": self.reachability,
                "expand_archives": self.expand_archives,
                "intel_feed": self.intel_feed,
                "max_intel_age": self.max_intel_age,
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
                "advisory_domains": sorted(str(d) for d in self.policy.advisory_domains),
                "hardening": self.policy.hardening,
                "max_major_drift": self.policy.max_major_drift,
                **(
                    {"accept_no_feed": sorted(self.policy.accept_no_feed)}
                    if self.policy.accept_no_feed is not None
                    else {}
                ),
                "packages": {
                    "deny": list(self.policy.package_deny),
                    "allow": list(self.policy.package_allow),
                },
                "licenses": {
                    "deny": list(self.policy.license_deny),
                    "allow": list(self.policy.license_allow),
                    "unknown": self.policy.license_unknown,
                },
            },
            "suppressions": [s.to_dict() for s in self.suppressions],
            "rules": {
                "packs": list(self.rule_packs),
                "extra": list(self.extra_rule_paths),
                "disabled": sorted(self.disabled_rules),
            },
        }

    def summary(self) -> dict[str, Any]:
        """A flat view for display. Not a serialisation format."""
        return {
            "severity_threshold": str(self.severity_threshold),
            "confidence_threshold": str(self.confidence_threshold),
            "evidence": str(self.evidence),
            "offline": self.offline,
            "reachability": self.reachability,
            "expand_archives": self.expand_archives,
            "intel_feed": self.intel_feed,
            "max_intel_age": self.max_intel_age,
            "clamav": bool(self.clamav),
            "rule_file": bool(self.rule_file),
            "keyrings": bool(self.keyrings),
            "judge": bool(self.judge),
            "detectors": dict(sorted(self.detectors.items())),
            "exclude": list(self.exclude),
            "suppressions": len(self.suppressions),
            "config_hash": self.fingerprint(),
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

TOP_LEVEL_KEYS = frozenset({"version", "scan", "policy", "evidence", "suppressions", "rules"})
LICENSE_UNKNOWN_ORDER = ("allow", "report", "deny")


class IntelAge:
    """Limits on how old the intel behind a scan may be."""

    @staticmethod
    def _shorter_age(ours: int | None, theirs: int | None) -> int | None:
        """The stricter of two intel-age limits. `None` is the default and 0 means no limit."""
        if theirs is None:
            return ours
        if ours is None or ours == 0:
            return theirs
        return ours if theirs == 0 else min(ours, theirs)

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


__all__ = [
    "CONFIG_FILENAMES",
    "CONFIG_VERSION",
    "Config",
    "Layer",
    "OrgConstraints",
    "Policy",
    "Provenance",
]
