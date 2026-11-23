"""The rule packs the signed feed delivered, loaded as rules (`intel/malware/feed_rules.py` decides
which delivered files are trusted; this loads them): verified packs that fail none of their own
samples, adding to the bundled rules and never replacing one, shadow packs only where asked and
demoted there, and the feed's kill switch applied to delivered rules only.

A pack is checked before it is activated: it must declare an engine range this engine satisfies
(`pack.requires_engine`, refused by the loader), fit the size limits of `PackLimits`, and pass its
own samples. A pack that fails any check is left out and named in the log; the scan runs on what is
bundled.

Rules sit above intel, so the loading lives here and intel never imports the rules layer
(architecture audit F1).
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol

from cordon_scanner.foundation.errors import ConfigError, RulePackError
from cordon_scanner.intel.malware.feed_rules import PACK_FILE, FeedRules

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import Any


from cordon_scanner.rules.feed_floor import FeedFloor
from cordon_scanner.rules.pack import RulePack

logger = logging.getLogger("cordon_scanner.intel.malware.feed_rules")


class PackFiles(Protocol):
    """What the delivered packs are read with: the rule loader's file reader."""

    def load_file(self, path: str | Path) -> RulePack: ...


class PackLimits:
    """What one delivered pack may weigh. A signed feed is trusted for what it says, not for how
    much of the scanner's memory and time it may take: a pack that is too large to compile cheaply
    is refused before any of it is read, so a faulty or hostile set cannot slow every scan."""

    MAX_FILE_BYTES = 1 << 20
    """One pack file."""

    MAX_RULES = 2_000
    """Rules in one pack."""

    MAX_PATTERNS_PER_RULE = 64
    """Alternatives in one rule's match."""

    MAX_PATTERN_CHARS = 2_000
    """One pattern's source."""

    ID_FORM = re.compile(r"^LEARNED\.[A-Za-z0-9_-]+\.[0-9]+$")
    """The only form a delivered rule's id may take: `LEARNED.<area>.<n>`. Anything else could stand for a bundled or an organisation's rule."""

    @classmethod
    def id_problem(cls, pack: RulePack, retired: frozenset[str]) -> str | None:
        """Why a rule id of the pack may not be delivered (outside the learned form, or retired), or `None`."""
        for compiled in pack.rules:
            rule_id = compiled.rule.id
            if cls.ID_FORM.fullmatch(rule_id) is None:
                return f"rule id {rule_id} is outside LEARNED.<area>.<n>"
            if rule_id in retired:
                return f"rule id {rule_id} is retired"
        return None

    @classmethod
    def file_problem(cls, path: Path) -> str | None:
        """Why the file is too large to read, or `None`."""
        size = path.stat().st_size
        if size > cls.MAX_FILE_BYTES:
            return f"the file is {size} bytes; a pack may hold at most {cls.MAX_FILE_BYTES}"
        return None

    @classmethod
    def pack_problem(cls, pack: RulePack) -> str | None:
        """Why the loaded pack is too large to activate, or `None`."""
        if len(pack.rules) > cls.MAX_RULES:
            return f"it has {len(pack.rules)} rules; a pack may hold at most {cls.MAX_RULES}"
        for compiled in pack.rules:
            match = compiled.rule.raw.get("match") or {}
            patterns = match.get("patterns") or ([match["pattern"]] if "pattern" in match else [])
            if len(patterns) > cls.MAX_PATTERNS_PER_RULE:
                return (
                    f"rule {compiled.rule.id} has {len(patterns)} patterns; "
                    f"a rule may hold at most {cls.MAX_PATTERNS_PER_RULE}"
                )
            longest = max((len(str(p)) for p in patterns), default=0)
            if longest > cls.MAX_PATTERN_CHARS:
                return (
                    f"rule {compiled.rule.id} has a pattern of {longest} characters; "
                    f"at most {cls.MAX_PATTERN_CHARS}"
                )
        return None


class FeedPacks:
    """The delivered packs a scan loads, from the files `FeedRules` trusts."""

    @classmethod
    def packs(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None = None
    ) -> tuple[RulePack, ...]:
        """The delivered packs this scan loads: verified, not colliding, shadow only when asked."""
        return tuple(pack for _, pack in cls._select(loader, bundled_ids, shadow=shadow))

    @classmethod
    def skipped(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None = None
    ) -> tuple[tuple[str, str], ...]:
        """The delivered rules this scan could not evaluate (a term written for a meaning this scanner does not know), as (rule id, reason): a gap in what it checked, said and counted, never a rule run with another meaning."""
        return tuple(
            gap
            for _, pack in cls._select(loader, bundled_ids, shadow=shadow)
            for gap in pack.skipped
        )

    @classmethod
    def loaded(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None = None
    ) -> tuple[str, ...]:
        """The candidate ids of the delivered packs a scan here runs, each with a rule still on.

        What the analyser fleet reports beside a verdict, so the Cloud counts a pack as watched on
        a release only where it actually ran (a fleet not yet updated, or a pack refused here,
        must not count towards its record)."""
        return tuple(
            candidate
            for candidate, pack in cls._select(loader, bundled_ids, shadow=shadow)
            if candidate and any(c.rule.enabled for c in pack.rules)
        )

    @classmethod
    def _select(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None
    ) -> list[tuple[str, RulePack]]:
        shadow = FeedRules.shadow_enabled() if shadow is None else shadow
        taken = set(bundled_ids)
        index = FeedRules.index()
        set_problem = FeedFloor.set_problem(index)
        if set_problem is not None:
            logger.warning("feed rule packs not loaded: %s", set_problem)
            return []
        retired = frozenset(str(item) for item in index.get("tombstones") or ())
        out: list[tuple[str, RulePack]] = []
        for entry in index.get("packs") or ():
            if not isinstance(entry, dict):
                continue
            name, enforcement = str(entry.get("file", "")), entry.get("enforcement")
            if not PACK_FILE.fullmatch(name) or enforcement not in ("block", "shadow"):
                continue
            if enforcement == "shadow" and not shadow:
                continue
            path = FeedRules.trusted(name)
            if path is None:
                continue
            try:
                problem = PackLimits.file_problem(path)
                if problem is not None:
                    logger.warning("feed rule pack %s not loaded: %s", name, problem)
                    continue
                pack = loader.load_file(path)
            except (RulePackError, ConfigError, OSError, ValueError) as exc:
                # A bad delivered pack never breaks the scan: it runs on what is bundled.
                logger.warning("feed rule pack %s not loaded: %s", name, exc)
                continue
            problem = (
                PackLimits.pack_problem(pack)
                or PackLimits.id_problem(pack, retired)
                or FeedFloor.pack_problem(pack)
            )
            if problem is not None:
                logger.warning("feed rule pack %s not loaded: %s", name, problem)
                continue
            from cordon_scanner.rules.tester import RuleTester

            for rule_id, why in pack.skipped:
                logger.warning("feed rule %s not evaluated: %s", rule_id, why)
            if RuleTester.run(pack):
                # Its own samples fail: the rule would load and match nothing, or the wrong thing.
                logger.warning("feed rule pack %s not loaded: it fails its own samples", name)
                continue
            ids = {rule.id for rule in pack.rules}
            if ids & taken:
                continue  # a delivered pack adds detection; it never replaces a bundled rule
            taken |= ids
            if enforcement == "shadow":
                pack = cls._shadowed(pack)
            out.append((str(entry.get("candidate_id", ""))[:128], pack))
        out = cls._without_repeats(sorted(out, key=lambda entry: (entry[1].id, entry[1].version)))
        disabled = cls.disabled(index, delivered={r.id for _, p in out for r in p.rules})
        if disabled:
            out = [
                (
                    candidate,
                    replace(
                        pack,
                        rules=tuple(
                            replace(c, rule=replace(c.rule, enabled=False))
                            if c.rule.id in disabled
                            else c
                            for c in pack.rules
                        ),
                    ),
                )
                for candidate, pack in out
            ]
        return out

    @staticmethod
    def _without_repeats(out: list[tuple[str, RulePack]]) -> list[tuple[str, RulePack]]:
        """Packs in (id, version) order, each predicate once: a rule whose predicate an earlier rule already has is left out, and a pack left with no rule is left out."""
        seen: set[str] = set()
        kept: list[tuple[str, RulePack]] = []
        for candidate, pack in out:
            rules = []
            for compiled in pack.rules:
                digest = compiled.predicate_digest()
                if digest not in seen:
                    seen.add(digest)
                    rules.append(compiled)
            if rules or pack.skipped:
                kept.append((candidate, replace(pack, rules=tuple(rules))))
        return kept

    @staticmethod
    def _shadowed(pack: RulePack) -> RulePack:
        """A pack that blocks nothing: every rule reports at low severity and confidence, demoted in category, marked by pack and said in its message."""
        from cordon_scanner.foundation.models import Category, Confidence, Severity

        return replace(
            pack,
            id=f"shadow:{pack.id}",
            rules=tuple(
                replace(
                    compiled,
                    # LOW, where the hardening tier records what decides nothing: INFO is
                    # below the default report threshold, so nobody would see it. Severity
                    # alone is not enough either: a `malicious` rule's category floor lifts
                    # it back to HIGH, so a shadow rule blocked (found end to end). Demoted
                    # in category too, marked by pack, and said in its message.
                    rule=replace(
                        compiled.rule,
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        category=Category.POLICY,
                        rulepack=f"shadow:{compiled.rule.rulepack}",
                        message=f"[shadow: would {compiled.rule.category.value}] "
                        f"{compiled.rule.message}",
                    ),
                )
                for compiled in pack.rules
            ),
        )

    @staticmethod
    def disabled(index: dict[str, Any], *, delivered: set[str]) -> frozenset[str]:
        """The kill switch, limited to delivered rules: a bundled id in the list is ignored."""
        listed = index.get("disabled_rules") or ()
        return frozenset(str(i) for i in listed if isinstance(i, str) and i in delivered)


__all__ = ["FeedPacks", "PackLimits"]
