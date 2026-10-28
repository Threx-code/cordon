"""`rules list`, `rules test`, `rules diff` and `rules show`: the loaded rule packs, and the rules
detectors declare in Python."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.detect.catalogue import DeclaredRule
    from cordon_scanner.foundation.models import Rule
    from cordon_scanner.rules.loader import RulePack, RuleSet, RuleTestFailure


class RulesCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        rules_cmd = sub.add_parser("rules", help="inspect and validate rule packs")
        rules_sub = rules_cmd.add_subparsers(dest="rules_command", metavar="<action>")
        rules_sub.add_parser("list", help="list every loaded rule")
        rules_sub.add_parser("test", help="run every rule's declared samples")
        diff = rules_sub.add_parser(
            "diff", help="compare rule packs and report removal or weakening"
        )
        diff.add_argument("before", help="a pack file, or a directory of packs")
        diff.add_argument(
            "after",
            nargs="?",
            default=None,
            help="the pack to compare; defaults to the packs built into this install",
        )

        show = rules_sub.add_parser("show", help="show one rule in full")
        show.add_argument("rule_id")

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.foundation.config_resolver import ConfigResolver
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        packs = RuleLoader.load_builtin()
        rule_set = RuleSet(packs)
        declared = RuleCatalogue.from_detectors(Registry().detectors())
        disabled_ids = ConfigResolver.resolve(root=".").disabled_rules
        action = args.rules_command or "list"

        if action == "list":
            return cls._list(packs, rule_set, declared, disabled_ids)

        if action == "test":
            return cls._test(packs, rule_set)

        if action == "diff":
            return cls._diff(args, packs)

        if action == "show":
            return cls._show(args.rule_id, rule_set, declared)

        raise ConfigError(f"unknown rules action: {action}")

    @staticmethod
    def _list(
        packs: Sequence[RulePack],
        rule_set: RuleSet,
        declared: Sequence[DeclaredRule],
        disabled_ids: frozenset[str],
    ) -> int:
        total = len(rule_set) + len(declared)
        print(f"{total} rules: {len(rule_set)} from {len(packs)} pack(s), ")
        print(f"{len(declared)} declared by detectors\n")
        for pack in packs:
            print(f"{pack.id} {pack.version}  ({pack.license})")
            for compiled in pack:
                rule = compiled.rule
                marker = " " if rule.enabled else "-"
                print(
                    f" {marker} {rule.id:<34} {rule.severity!s:<9}"
                    f"{rule.confidence!s:<10}{rule.title}"
                )
            print()

        # Listed separately, and labelled, because these do not carry the
        # loader's guarantees: no mandatory samples, no provenance
        # requirement, no independent version. Hiding the difference would
        # be worse than the omission this fixes.
        if declared:
            print("declared by detectors (not pack rules)")
            for declared_rule in declared:
                marker = "-" if declared_rule.id in disabled_ids else " "
                print(
                    f" {marker} {declared_rule.id:<34} {declared_rule.severity!s:<9}"
                    f"{declared_rule.confidence!s:<10}{declared_rule.title}"
                )
            print()
        return int(ExitCode.CLEAN)

    @staticmethod
    def _test(packs: Sequence[RulePack], rule_set: RuleSet) -> int:
        from cordon_scanner.rules.loader import RuleTester

        failures: list[RuleTestFailure] = []
        for pack in packs:
            failures.extend(RuleTester.run(pack))
        if failures:
            print(f"{len(failures)} rule sample(s) failed\n", file=sys.stderr)
            for failure in failures:
                print(f"  {failure.rule_id} [{failure.kind}] {failure.detail}", file=sys.stderr)
                print(f"    sample: {failure.sample}", file=sys.stderr)
            return int(ExitCode.FINDINGS)
        testable = sum(1 for r in rule_set if r.rule.tests.positive or r.rule.tests.negative)
        print(f"all samples passed ({testable} rules with inline samples)")
        return int(ExitCode.CLEAN)

    @classmethod
    def _show(cls, rule_id: str, rule_set: RuleSet, declared: Sequence[DeclaredRule]) -> int:
        found = rule_set.get(rule_id)
        if found is None:
            match = next((r for r in declared if r.id == rule_id), None)
            if match is not None:
                return cls._show_declared(match)
            raise CordonError(f"no such rule: {rule_id}")
        rule = found.rule
        print(f"{rule.id}  {rule.version}  ({rule.rulepack})")
        print(f"{rule.title}\n")
        print(f"category    {rule.category}")
        print(f"severity    {rule.severity}")
        print(f"confidence  {rule.confidence}")
        print(f"match       {rule.match_kind}")
        if rule.languages:
            print(f"languages   {', '.join(rule.languages)}")
        if rule.capability:
            print(f"capability  {rule.capability}")
        if rule.provenance:
            protection = " (protected)" if rule.provenance.protected else ""
            print(f"provenance  {rule.provenance.kind}{protection}")
        print(f"\n{rule.message}\n")
        if rule.remediation:
            print(f"remediation\n  {rule.remediation}\n")
        # Pack rules have carried references since the loader was written
        # and this never printed them, so the one place a reader goes to
        # ask "says who?" answered for neither kind of rule.
        if rule.references:
            print("references")
            for link in rule.references:
                print(f"  {link}")
            print()
        return int(ExitCode.CLEAN)

    @staticmethod
    def _show_declared(match: DeclaredRule) -> int:
        print(f"{match.id}  (declared by the {match.detector!r} detector)")
        print(f"{match.title}\n")
        print(f"category    {match.category}")
        print(f"severity    {match.severity}")
        print(f"confidence  {match.confidence}")
        if match.message:
            print(f"\n{match.message}")
        if match.remediation:
            print(f"\nremediation\n  {match.remediation}")
        if match.references:
            print("\nreferences")
            for link in match.references:
                print(f"  {link}")
        print(
            "\nThis rule is declared in Python rather than in a YAML pack, "
            "so it does not\ncarry the pack guarantees: no mandatory test "
            "samples, no provenance requirement,\nno independent version. "
            "It can be disabled with `rules.disabled` in configuration."
        )
        return int(ExitCode.CLEAN)

    @classmethod
    def _diff(cls, args: argparse.Namespace, packs: Sequence[RulePack]) -> int:
        """Compare two rule sets and report removal or weakening.

        `RuleProvenance.protected` exists solely so that this command "fails
        when one is removed or weakened without an explicit review trailer".
        The command had no implementation, so `provenance: incident` guaranteed
        nothing at all.

        A rule derived from a real incident is the easiest kind to lose: it
        often looks arbitrary out of context -- an opaque string constant with
        no obvious meaning is exactly what a well-intentioned cleanup deletes,
        and a refactor that reorganises a rule set can drop one while the diff
        appears to show nothing but an improvement.

        Weakening means: disabled, severity lowered, or confidence lowered.
        Those are the changes that reduce what a rule does while leaving it
        present, and they do not read as removal in a text diff.
        """
        from cordon_scanner.rules.loader import RuleLoader

        loader = RuleLoader()

        def load(path_text: str) -> tuple[RulePack, ...]:
            path = Path(path_text)
            if path.is_dir():
                return loader.load_dir(path)
            if path.is_file():
                return (loader.load_file(path),)
            raise CordonError(f"no such pack: {path}")

        before = {r.rule.id: r.rule for pack in load(args.before) for r in pack.rules}
        after_packs = load(args.after) if args.after else packs
        after = {r.rule.id: r.rule for pack in after_packs for r in pack.rules}

        removed = sorted(set(before) - set(after))
        added = sorted(set(after) - set(before))
        weakened: list[tuple[str, str]] = []

        for rule_id in sorted(set(before) & set(after)):
            was, now = before[rule_id], after[rule_id]
            if was.enabled and not now.enabled:
                weakened.append((rule_id, "disabled"))
            if now.severity < was.severity:
                weakened.append((rule_id, f"severity {was.severity} -> {now.severity}"))
            if now.confidence < was.confidence:
                weakened.append((rule_id, f"confidence {was.confidence} -> {now.confidence}"))

        for rule_id in added:
            print(f"  added     {rule_id}")
        for rule_id in removed:
            marker = "PROTECTED " if cls._protected(before[rule_id]) else ""
            print(f"  removed   {marker}{rule_id}")
        for rule_id, how in weakened:
            marker = "PROTECTED " if cls._protected(after[rule_id]) else ""
            print(f"  weakened  {marker}{rule_id}: {how}")

        if not (added or removed or weakened):
            print("no rule changes")
            return int(ExitCode.CLEAN)

        protected = [r for r in removed if cls._protected(before[r])]
        protected += [r for r, _ in weakened if cls._protected(after[r])]
        if protected:
            print(
                f"\n{len(protected)} protected rule(s) removed or weakened: "
                f"{', '.join(sorted(set(protected)))}",
                file=sys.stderr,
            )
            print(
                "  A rule marked `provenance: incident` matched something that "
                "actually arrived.\n  Removing or weakening one needs an explicit "
                "review, not a refactor that happens to drop it.",
                file=sys.stderr,
            )
            return int(ExitCode.FINDINGS)

        return int(ExitCode.CLEAN)

    @staticmethod
    def _protected(rule: Rule) -> bool:
        provenance = getattr(rule, "provenance", None)
        return bool(provenance and getattr(provenance, "protected", False))


__all__ = ["RulesCommand"]
