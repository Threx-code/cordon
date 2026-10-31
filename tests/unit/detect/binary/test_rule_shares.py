"""Rule shares (`detect/binary/rule_shares`): a rule set divided so each share can be matched on its
own and the answers put together are the serial answer. A share never lacks a rule its rules read,
and every share holds the global rules."""

from __future__ import annotations

from cordon_scanner.detect.binary.rule_engine.lang import Rules
from cordon_scanner.detect.binary.rule_shares import RuleShares

TEXT = """
import "pe"
global rule g { condition: filesize > 0 }
rule a { strings: $a = "aaaa" condition: $a }
rule b { strings: $b = "bbbb" condition: $b and a }
rule loader_one { strings: $x = "xxxx" condition: $x }
rule loader_two { strings: $y = "yyyy" condition: $y }
rule any_loader { condition: any of (loader_*) }
rule lone { strings: $z = "zzzz" condition: $z }
rule lone2 { strings: $w = "wwww" condition: $w and pe.exports("*") }
"""


class Kit:
    @staticmethod
    def rules() -> list:
        return Rules.compile(TEXT).rules

    @staticmethod
    def names(rules: list, share: frozenset[int]) -> set[str]:
        return {rules[i].name for i in share}


class TestGroups:
    def test_a_reference_and_a_rule_set_keep_their_rules_together(self) -> None:
        rules = Kit.rules()
        groups = [{rules[i].name for i in g} for g in RuleShares.groups(rules)]
        assert {"a", "b"} in groups
        assert {"loader_one", "loader_two", "any_loader"} in groups
        assert {"lone"} in groups and {"lone2"} in groups

    def test_every_share_holds_the_globals_and_whole_groups(self) -> None:
        rules = Kit.rules()
        shares = RuleShares.of(rules, 3)
        assert 1 < len(shares) <= 3
        for share in shares:
            names = Kit.names(rules, share)
            assert "g" in names
            assert ({"a", "b"} <= names) or not ({"a", "b"} & names)
            loaders = {"loader_one", "loader_two", "any_loader"}
            assert (loaders <= names) or not (loaders & names)
        covered = set().union(*shares)
        assert covered == set(range(len(rules)))

    def test_one_share_is_the_whole_set(self) -> None:
        rules = Kit.rules()
        assert RuleShares.of(rules, 1) == [frozenset(range(len(rules)))]

    def test_shares_matched_apart_give_the_serial_answer(self) -> None:
        """Each share matched with the rules outside it left false, the true rules of all shares
        together are exactly the serial match's."""
        rules = Rules.compile(TEXT)
        data = b"aaaa bbbb xxxx zzzz"
        serial = sorted(m.rule for m in rules.match(data))
        assert serial == ["a", "any_loader", "b", "g", "loader_one", "lone"]
        together: set[str] = set()
        for share in RuleShares.of(rules.rules, 3):
            text = "\n".join(
                line
                for line in TEXT.strip().splitlines()
                if line.startswith("import ")
                or line.split("{")[0].split()[-1] in Kit.names(rules.rules, share)
            )
            together |= {m.rule for m in Rules.compile(text).match(data)}
        assert sorted(together) == serial
