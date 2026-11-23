"""A policy bundle that loosens the policy needs a current, signed loosening.

Remote content may tighten policy at any time. Loosening needs a separately signed, logged, expiring action. A client that holds a bundle
compares the next one with it:

```
  held bundle  ──►  offered bundle
        differences: what the offer lets through that the held one did not
        │
        ▼ a tightening (a rule added that blocks, an outcome raised, a deny list that grew, a default made stricter)  ─► nothing needed
        ▼ a lowering, or a change the client cannot prove is none (a rule's condition edited, an unknown list changed, a scope widened)
              each needs ONE loosening of the offer's own `loosenings` that
                 * is a DSSE envelope signed by a policy role key the pinned root delegated (the keys valid now),
                 * is for this tenant and this scope, and relaxes FROM the version held (`from_version`),
                 * names the difference in `relaxes`,
                 * was issued at most five minutes ahead of the client's clock, has not expired, and lasted at most 30 days,
                 * carries the id of the platform's decision-log entry (`log_id`), kept for an auditor and not checked online.
              any difference left uncovered: `BundleRefused("bundle_loosened")`, and the held bundle is as it was.
```

A difference is named like this: `rule:<id>`, `rules:order`, `default:<field>` (`default:on_incomplete.<environment>`), `list:bundle.<name>` for the
bundle's own lists and `list:policy.<name>` for the policy's, `mandatory`, `locked_by`, `scope`. A list is read by its name: one that holds allowed or
trusted things loosens when it grows, one that holds denied things loosens when it shrinks, any other when it changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.cloud.bundle_chain import BundleError, BundleRefused, Dsse
from cordon_scanner.decide.decision.records import DecisionError
from cordon_scanner.decide.decision.table import CompiledPolicy

if TYPE_CHECKING:
    from collections.abc import Mapping

LOOSENING_TYPE: Final = "application/vnd.cordon.loosening+json"
LOOSENING_SCHEMA: Final = "cordon.loosening/v1"
#: The longest a loosening may last, from `issued_at` to `expires_at`.
MAX_LIFETIME: Final = timedelta(days=30)
#: How far ahead of the client's clock a loosening's `issued_at` may be: the client's clock may be slow.
SKEW: Final = timedelta(minutes=5)
MAX_RELAXES: Final = 500


@dataclass(frozen=True, slots=True)
class Granted:
    """A loosening that counted: what it relaxed and the decision-log entry an auditor can find."""

    log_id: str
    relaxes: tuple[str, ...]
    issued_at: str
    expires_at: str


class Loosening:
    #: A word in a list's name that says what the list holds.
    PERMISSIVE: ClassVar[tuple[str, ...]] = (
        "allow",
        "exempt",
        "trust",
        "accept",
        "approved",
        "ignore",
        "waive",
    )
    RESTRICTIVE: ClassVar[tuple[str, ...]] = (
        "deny",
        "block",
        "ban",
        "forbid",
        "revoke",
        "malicious",
        "quarantine",
    )
    #: How strict a rule's outcome is: a larger number is stricter.
    OUTCOME: ClassVar[dict[str, int]] = {
        "allow": 0,
        "allow_with_conditions": 1,
        "warn": 1,
        "review": 2,
        "block": 3,
    }

    # -- what differs -------------------------------------------------------------------------------------------
    @classmethod
    def differences(cls, held: Mapping[str, Any], offered: Mapping[str, Any]) -> set[str]:
        """The names of what `offered` loosens against `held`; empty when it only tightens or changes nothing that matters."""
        found = cls._lists(held.get("lists"), offered.get("lists"), "bundle")
        before, after = cls._policy(held), cls._policy(offered)
        if before is None or after is None:
            return found
        found |= cls._defaults(before, after)
        found |= cls._rules(before, after)
        found |= cls._lists(before.lists, after.lists, "policy")
        if before.mandatory and not after.mandatory:
            found.add("mandatory")
        if set(before.locked_by) - set(after.locked_by):
            found.add("locked_by")
        if before.scope != after.scope:
            found.add("scope")
        return found

    @staticmethod
    def _policy(bundle: Mapping[str, Any]) -> CompiledPolicy | None:
        document = bundle.get("compiled_table")
        if not isinstance(document, dict):
            return None
        try:
            return CompiledPolicy.from_json(document)
        except (DecisionError, KeyError, TypeError, ValueError):
            return None

    @classmethod
    def _lists(cls, held: object, offered: object, owner: str) -> set[str]:
        before = held if isinstance(held, dict) else {}
        after = offered if isinstance(offered, dict) else {}
        out: set[str] = set()
        for name in sorted(set(before) | set(after)):
            old, new = cls._items(before.get(name)), cls._items(after.get(name))
            lowered = name.lower()
            if any(word in lowered for word in cls.PERMISSIVE):
                loosens = bool(new - old)
            elif any(word in lowered for word in cls.RESTRICTIVE):
                loosens = bool(old - new)
            else:
                loosens = old != new
            if loosens:
                out.add(f"list:{owner}.{name}")
        return out

    @staticmethod
    def _items(value: object) -> set[str]:
        if isinstance(value, (list, tuple, set)):
            return {json.dumps(item, sort_keys=True) for item in value}
        return set() if value is None else {json.dumps(value, sort_keys=True)}

    @classmethod
    def _defaults(cls, before: CompiledPolicy, after: CompiledPolicy) -> set[str]:
        old, new = before.defaults, after.defaults
        out: set[str] = set()
        strict = old.STRICTNESS
        for environment in sorted(set(old.on_incomplete) | set(new.on_incomplete)):
            if cls._rank(strict, new.incomplete_for(environment)) < cls._rank(
                strict, old.incomplete_for(environment)
            ):
                out.add(f"default:on_incomplete.{environment}")
        for field, order in (
            ("unresolved", strict),
            ("on_gaps", strict),
            ("exceptions", old.EXCEPTIONS),
            ("default", old.OUTCOMES),
        ):
            if cls._rank(order, getattr(new, field)) < cls._rank(order, getattr(old, field)):
                out.add(f"default:{field}")
        for field in ("max_intel_age_s", "bundle_max_age_s"):
            if cls._longer(getattr(old, field), getattr(new, field)):
                out.add(f"default:{field.removesuffix('_s')}")
        if set(new.warn_until_measured) - set(old.warn_until_measured):
            out.add("default:warn_until_measured")
        if new.serve_last_allow_seconds() > old.serve_last_allow_seconds():
            out.add("default:serve_last_allow")
        return out

    @staticmethod
    def _rank(order: tuple[str, ...], value: str) -> int:
        return order.index(value) if value in order else -1

    @staticmethod
    def _longer(old: int | None, new: int | None) -> bool:
        """Whether a limit grew: no limit is the longest."""
        if old is None:
            return False
        return new is None or new > old

    @classmethod
    def _rules(cls, before: CompiledPolicy, after: CompiledPolicy) -> set[str]:
        old = {rule.id: rule for rule in before.rules}
        new = {rule.id: rule for rule in after.rules}
        out: set[str] = set()
        for rule_id, rule in old.items():
            kept = new.get(rule_id)
            if kept is None:
                if cls.OUTCOME.get(rule.then, 0) > 0:
                    out.add(f"rule:{rule_id}")  # a rule that restricted is gone
                continue
            if cls._rule_loosens(rule, kept):
                out.add(f"rule:{rule_id}")
        for rule_id, rule in new.items():
            if rule_id not in old and cls.OUTCOME.get(rule.then, 0) <= 1:
                out.add(f"rule:{rule_id}")  # an allowing rule is new
        shared = [rule_id for rule_id in old if rule_id in new]
        if shared != [rule_id for rule_id in new if rule_id in old]:
            out.add("rules:order")
        return out

    @classmethod
    def _rule_loosens(cls, old: Any, new: Any) -> bool:
        lower = cls.OUTCOME.get(new.then, -1) < cls.OUTCOME.get(old.then, -1) or (
            new.then not in cls.OUTCOME and new.then != old.then
        )
        if lower or (old.mandatory and not new.mandatory):
            return True
        edited = (old.tier, old.applies_to, old.when, old.require) != (
            new.tier,
            new.applies_to,
            new.when,
            new.require,
        )
        # A condition that was edited has a direction the client cannot read, whatever happened to the outcome: it is a loosening.
        return edited or bool(set(old.obligations) - set(new.obligations))

    # -- what is granted ----------------------------------------------------------------------------------------
    @classmethod
    def granted(
        cls,
        offered: Mapping[str, Any],
        *,
        policy_keys: Mapping[str, bytes],
        tenant: str,
        from_version: int,
        now: datetime,
    ) -> list[Granted]:
        """The loosenings of `offered` that count: signed by a delegated policy key, for this tenant, scope and version held, current."""
        out: list[Granted] = []
        envelopes = offered.get("loosenings")
        for envelope in envelopes if isinstance(envelopes, list) else []:
            try:
                body = Dsse.verify(envelope, dict(policy_keys), payload_type=LOOSENING_TYPE)
                document = json.loads(body)
            except (BundleError, ValueError, RecursionError):
                continue
            granted = cls._granted(document, offered, tenant, from_version, now)
            if granted is not None:
                out.append(granted)
        return out

    @classmethod
    def _granted(
        cls,
        document: object,
        offered: Mapping[str, Any],
        tenant: str,
        from_version: int,
        now: datetime,
    ) -> Granted | None:
        if not isinstance(document, dict):
            return None
        relaxes, log_id = document.get("relaxes"), document.get("log_id")
        version = document.get("from_version")
        if (
            document.get("_type") != LOOSENING_SCHEMA
            or document.get("tenant") != tenant
            or document.get("scope") != offered.get("scope")
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version != from_version
            or not isinstance(relaxes, list)
            or not 0 < len(relaxes) <= MAX_RELAXES
            or not all(isinstance(item, str) and item for item in relaxes)
            or not isinstance(log_id, str)
            or not 0 < len(log_id) <= 200
        ):
            return None
        issued, expires = (
            cls._instant(document.get("issued_at")),
            cls._instant(document.get("expires_at")),
        )
        if issued is None or expires is None:
            return None
        if (
            expires <= issued
            or expires - issued > MAX_LIFETIME
            or issued > now + SKEW
            or now > expires
        ):
            return None
        return Granted(
            log_id, tuple(relaxes), str(document["issued_at"]), str(document["expires_at"])
        )

    @staticmethod
    def _instant(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            return None
        return moment if moment.tzinfo is not None else None

    # -- the check ----------------------------------------------------------------------------------------------
    @classmethod
    def check(
        cls,
        held: Mapping[str, Any],
        offered: Mapping[str, Any],
        *,
        policy_keys: Mapping[str, bytes],
        tenant: str,
        now: datetime,
    ) -> tuple[Granted, ...]:
        """The loosenings that covered the offer, or `BundleRefused("bundle_loosened")` naming what nothing covered."""
        needed = cls.differences(held, offered)
        if not needed:
            return ()
        version = held.get("version")
        grants = cls.granted(
            offered,
            policy_keys=policy_keys,
            tenant=tenant,
            from_version=version if isinstance(version, int) else -1,
            now=now.astimezone(UTC),
        )
        covered = {name for grant in grants for name in grant.relaxes}
        left = sorted(needed - covered)
        if left:
            raise BundleRefused(
                BundleRefused.LOOSENED,
                "the bundle loosens the policy and no current signed loosening covers: "
                + ", ".join(left),
            )
        return tuple(grant for grant in grants if needed & set(grant.relaxes))


__all__ = ["LOOSENING_SCHEMA", "LOOSENING_TYPE", "MAX_LIFETIME", "SKEW", "Granted", "Loosening"]
