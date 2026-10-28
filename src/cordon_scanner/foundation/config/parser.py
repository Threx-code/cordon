"""Reading a configuration document into a Config: every key checked against the ones the schema
knows (an unknown key is an error, never ignored), every value against its type and range, and the
policy, rule, suppression and licence sections each validated in full before anything is applied.
"""

from __future__ import annotations

import re
from datetime import date
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS, Limits
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    RedactionMode,
    Severity,
    Suppression,
)
from cordon_scanner.foundation.renames import Renamed
from cordon_scanner.foundation.taxonomy import ThreatDomain

if TYPE_CHECKING:
    from collections.abc import Mapping

from cordon_scanner.foundation.config.policy import (
    DEFAULT_ADVISORY_DOMAINS,
    DEFAULT_MAX_MAJOR_DRIFT,
    OrgConstraints,
    Policy,
)
from cordon_scanner.foundation.config.settings import (
    CONFIG_VERSION,
    LICENSE_UNKNOWN_ORDER,
    MIN_JUSTIFICATION_CHARS,
    TOP_LEVEL_KEYS,
    Config,
    Provenance,
)

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
        "reachability",
        "expand_archives",
        "intel_feed",
        "max_intel_age",
        "allow_plugins",
        "profile",
        "internal_namespaces",
        "allowed_action_owners",
    }
)


_POLICY_KEYS = frozenset(
    {
        "fail_on",
        "fail_on_incomplete",
        "min_confidence_to_fail",
        "advisory_domains",
        "hardening",
        "max_major_drift",
        "packages",
        "licenses",
        "accept_no_feed",
    }
)


_PACKAGE_LIST_KEYS = frozenset({"deny", "allow"})


_LICENSE_LIST_KEYS = frozenset({"deny", "allow", "unknown"})


_RULES_KEYS = frozenset({"packs", "extra", "disabled"})


_SUPPRESSION_KEYS = frozenset({"rule", "path", "justification", "expires", "approved_by"})


class ConfigParser:
    """Reads a configuration mapping into domain objects, strictly.

    Strictness is the whole point, and it is a security property rather than
    pedantry. A parser that ignores what it does not understand is a
    scanner-blinding primitive: `detectors:` misspelled as `detector:` silently
    means "use every default", the author believes they turned something on,
    and nothing anywhere says otherwise. Every unknown key is an error, and
    every error carries a suggestion, because an error without a suggestion is
    one people work around by deleting the setting.
    """

    @staticmethod
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
            near = ConfigParser._suggest(next(iter(sorted(unknown))), allowed)
            hint = f"Did you mean {near!r}?" if near else None
            raise ConfigError(f"unknown key(s) in {where}: {names}", hint=hint)

    @staticmethod
    def _suggest(word: str, options: frozenset[str]) -> str | None:
        """Cheapest useful typo suggestion: shared-prefix, then edit distance 1-2."""
        best: tuple[int, str] | None = None
        for option in options:
            distance = ConfigParser._edit_distance(word, option)
            if distance <= 2 and (best is None or distance < best[0]):
                best = (distance, option)
        return best[1] if best else None

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        if abs(len(a) - len(b)) > 2:
            return 99
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            current = [i]
            for j, cb in enumerate(b, 1):
                current.append(
                    min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
                )
            previous = current
        return previous[-1]

    @staticmethod
    def _spans_tree(pattern: str) -> bool:
        """Whether a path pattern reaches across the whole tree rather than naming a place."""
        stripped = pattern.strip().lstrip("./")
        if not stripped or "**" in stripped:
            return True
        first = stripped.split("/", 1)[0]
        return "*" in first or "?" in first

    @staticmethod
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

    @staticmethod
    def _parse_config(data: Mapping[str, Any], *, source: str, layer: str) -> Config:
        if not isinstance(data, dict):
            raise ConfigError(f"{source}: top level must be a mapping")

        ConfigParser._reject_unknown(data, TOP_LEVEL_KEYS, source)

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
        ConfigParser._reject_unknown(scan, _SCAN_KEYS, f"{source}: scan")

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
        # a detector named by the ID it had before a rename is the detector it became
        detectors_raw = {Renamed.detector(k): v for k, v in detectors_raw.items()}

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

        policy = ConfigParser._parse_policy(data.get("policy") or {}, source=source)
        suppressions = ConfigParser._parse_suppressions(
            data.get("suppressions") or [], source=source
        )

        rules = data.get("rules") or {}
        if not isinstance(rules, dict):
            raise ConfigError(f"{source}: `rules` must be a mapping")
        ConfigParser._reject_unknown(rules, _RULES_KEYS, f"{source}: rules")
        packs = ConfigParser._as_str_tuple(rules.get("packs"), f"{source}: rules.packs") or (
            "cordon-builtin",
        )
        extra = ConfigParser._as_str_tuple(rules.get("extra"), f"{source}: rules.extra")
        disabled = ConfigParser._as_str_tuple(rules.get("disabled"), f"{source}: rules.disabled")

        record("scan.severity_threshold", str(severity))
        record("scan.confidence_threshold", str(confidence))
        record("evidence", str(evidence))
        record("scan.offline", bool(scan.get("offline", True)))

        return Config(
            version=CONFIG_VERSION,
            severity_threshold=severity,
            confidence_threshold=confidence,
            detectors=dict(detectors_raw),
            exclude=ConfigParser._as_str_tuple(scan.get("exclude"), f"{source}: scan.exclude"),
            include=ConfigParser._as_str_tuple(scan.get("include"), f"{source}: scan.include"),
            minified=ConfigParser._as_str_tuple(scan.get("minified"), f"{source}: scan.minified"),
            limits=limits,
            explicit_limits=explicit_limits,
            policy=policy,
            suppressions=suppressions,
            evidence=evidence,
            offline=bool(scan.get("offline", True)),
            reachability=bool(scan.get("reachability", False)),
            expand_archives=bool(scan.get("expand_archives", True)),
            intel_feed=bool(scan.get("intel_feed", True)),
            max_intel_age=ConfigParser._max_intel_age(scan.get("max_intel_age"), source),
            allow_plugins=bool(scan.get("allow_plugins", False)),
            rule_packs=packs,
            extra_rule_paths=extra,
            disabled_rules=frozenset(disabled),
            internal_namespaces=ConfigParser._as_str_tuple(
                scan.get("internal_namespaces"), f"{source}: scan.internal_namespaces"
            ),
            allowed_action_owners=ConfigParser._as_str_tuple(
                scan.get("allowed_action_owners"), f"{source}: scan.allowed_action_owners"
            ),
            profile=str(scan.get("profile", "balanced")),
            provenance=tuple(provenance),
        )

    @staticmethod
    def _max_intel_age(raw: Any, source: str) -> int | None:
        if raw is None:
            return None
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ConfigError(
                f"{source}: scan.max_intel_age must be a whole number of seconds >= 0"
            )
        return raw

    @staticmethod
    def _parse_policy(raw: Any, *, source: str) -> Policy:
        if not isinstance(raw, dict):
            raise ConfigError(f"{source}: `policy` must be a mapping")
        ConfigParser._reject_unknown(raw, _POLICY_KEYS, f"{source}: policy")

        fail_on = raw.get("fail_on")
        severity: Severity | None = Severity.HIGH
        categories: set[Category] = {Category.MALICIOUS}

        if fail_on is not None:
            if not isinstance(fail_on, list):
                raise ConfigError(f"{source}: policy.fail_on must be a list")
            if not fail_on:
                # Refused from every layer, operator input included. "Fail on
                # nothing" is not a setting anybody means: it produces a scan
                # that reports findings and exits 0, which is a scan whose
                # verdict has been deleted while its output still looks like a
                # verdict. Somebody who wants that writes `--fail-on` never, or
                # ignores the exit code; they do not write an empty list.
                raise ConfigError(
                    f"{source}: policy.fail_on is empty, which would fail on nothing",
                    hint=(
                        "Omit the key to keep the default gate, or list the severities "
                        "and categories that should fail the build."
                    ),
                )
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

        advisory = DEFAULT_ADVISORY_DOMAINS
        if "advisory_domains" in raw:
            entries = raw["advisory_domains"]
            if not isinstance(entries, list):
                raise ConfigError(f"{source}: policy.advisory_domains must be a list")
            names = []
            for entry in entries:
                try:
                    names.append(ThreatDomain(str(entry)))
                except ValueError:
                    valid = ", ".join(sorted(str(d) for d in ThreatDomain))
                    raise ConfigError(
                        f"{source}: policy.advisory_domains: unknown domain {entry!r}; "
                        f"expected one of: {valid}"
                    ) from None
            advisory = frozenset(names)

        drift = DEFAULT_MAX_MAJOR_DRIFT
        if "max_major_drift" in raw:
            value = raw["max_major_drift"]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ConfigError(
                    f"{source}: policy.max_major_drift must be an integer of 1 or more"
                )
            drift = value

        packages = raw.get("packages") or {}
        if not isinstance(packages, dict):
            raise ConfigError(f"{source}: policy.packages must be a mapping")
        ConfigParser._reject_unknown(packages, _PACKAGE_LIST_KEYS, f"{source}: policy.packages")
        licenses = raw.get("licenses") or {}
        if not isinstance(licenses, dict):
            raise ConfigError(f"{source}: policy.licenses must be a mapping")
        ConfigParser._reject_unknown(licenses, _LICENSE_LIST_KEYS, f"{source}: policy.licenses")
        unknown = str(licenses.get("unknown", "allow"))
        if unknown not in LICENSE_UNKNOWN_ORDER:
            raise ConfigError(
                f"{source}: policy.licenses.unknown must be one of: {', '.join(LICENSE_UNKNOWN_ORDER)}",
                hint=f"got {unknown!r}",
            )

        accepted: frozenset[str] | None = None
        if "accept_no_feed" in raw:
            from cordon_scanner.foundation.dependencies import ECOSYSTEM_IDS

            ecosystems = ConfigParser._as_str_tuple(
                raw["accept_no_feed"], f"{source}: policy.accept_no_feed"
            )
            known = ECOSYSTEM_IDS
            unknown_names = [n for n in ecosystems if n not in known]
            if unknown_names:
                raise ConfigError(
                    f"{source}: policy.accept_no_feed names no ecosystem Cordon reads: "
                    f"{', '.join(unknown_names)}",
                    hint=f"one of: {', '.join(sorted(known))}",
                )
            accepted = frozenset(ecosystems)
        return Policy(
            fail_on_severity=severity,
            fail_on_categories=frozenset(categories),
            fail_on_incomplete=bool(raw.get("fail_on_incomplete", False)),
            min_confidence_to_fail=min_conf,
            advisory_domains=advisory,
            hardening=bool(raw.get("hardening", False)),
            max_major_drift=drift,
            accept_no_feed=accepted,
            package_deny=ConfigParser._as_str_tuple(
                packages.get("deny"), f"{source}: policy.packages.deny"
            ),
            package_allow=ConfigParser._as_str_tuple(
                packages.get("allow"), f"{source}: policy.packages.allow"
            ),
            license_deny=ConfigParser._as_str_tuple(
                licenses.get("deny"), f"{source}: policy.licenses.deny"
            ),
            license_allow=ConfigParser._as_str_tuple(
                licenses.get("allow"), f"{source}: policy.licenses.allow"
            ),
            license_unknown=unknown,
        )

    @staticmethod
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
            ConfigParser._reject_unknown(entry, _SUPPRESSION_KEYS, where)

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

    @staticmethod
    def _suppression_violation(s: Suppression, c: OrgConstraints) -> str | None:
        """Check one suppression against the organisation ceiling."""
        if c.require_justification and len(s.justification.strip()) < MIN_JUSTIFICATION_CHARS:
            return "justification is too short"
        if c.require_approver and not s.approved_by:
            return "organisation policy requires an approver"
        if c.forbid_path_only_suppressions and (not s.rule or s.rule == "*"):
            return "wildcard rule suppressions are forbidden; name the specific rule"
        if c.forbid_path_only_suppressions:
            # The check tested only the rule half. `{rule: SUSPECT.PERSIST.001,
            # path: "*"}` therefore disabled that rule across the whole
            # repository -- and suppression path matching used fnmatchcase,
            # whose `*` crosses `/`, so a single character did it. That is
            # precisely the failure the rule-and-path pair exists to prevent.
            #
            # Listing the exact strings was not enough either: `*.js` reads as
            # specific and, under fnmatch, was not. Matching is now
            # path-aware, and any pattern that can still reach arbitrary depth
            # is refused, because a suppression that spans directories is a
            # rule-level exception wearing a path.
            stripped = s.path.strip()
            if not stripped or stripped in {"*", "**", "**/*", "/"}:
                return "wildcard path suppressions are forbidden; name the specific path"
            if "**" in stripped:
                return (
                    "a suppression path may not use `**`; it spans directories, which "
                    "makes the exception rule-wide rather than path-specific"
                )
        try:
            expires = date.fromisoformat(s.expires)
        except ValueError:
            return "expiry is not a valid date"
        horizon = (expires - date.today()).days
        if horizon > c.max_suppression_days:
            return (
                f"expiry is {horizon} days away, exceeding the maximum of {c.max_suppression_days}"
            )
        return None

    @staticmethod
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
            # Intersection, because merging two policies must never end weaker
            # than either. A domain is advisory only if BOTH sides say so; an
            # organisation policy that blocks on infrastructure is not undone by
            # a repository's own file leaving the default in place.
            advisory_domains=a.advisory_domains & b.advisory_domains,
            # Either side asking for the hardening tier at full severity gets it: reporting more
            # is the stricter choice.
            hardening=a.hardening or b.hardening,
            # The tighter of the two, for the same reason: merging must never
            # end weaker than either side asked for.
            max_major_drift=min(a.max_major_drift, b.max_major_drift),
            # Unsaid on one side, the other side's; said on both, only what both accept.
            accept_no_feed=(
                b.accept_no_feed
                if a.accept_no_feed is None
                else a.accept_no_feed
                if b.accept_no_feed is None
                else a.accept_no_feed & b.accept_no_feed
            ),
            # Deny lists add up; allow lists narrow (an empty one allows everything, so the other
            # side's applies); unknown licences take the stricter handling. A repository's own file
            # cannot loosen what the organisation set.
            package_deny=tuple(dict.fromkeys((*a.package_deny, *b.package_deny))),
            package_allow=ConfigParser._narrower(a.package_allow, b.package_allow),
            license_deny=tuple(dict.fromkeys((*a.license_deny, *b.license_deny))),
            license_allow=ConfigParser._narrower(a.license_allow, b.license_allow),
            license_unknown=max(
                a.license_unknown, b.license_unknown, key=LICENSE_UNKNOWN_ORDER.index
            ),
        )

    @staticmethod
    def _narrower(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
        if not a:
            return b
        if not b:
            return a
        return tuple(x for x in a if x in set(b))


__all__ = ["ConfigParser"]
